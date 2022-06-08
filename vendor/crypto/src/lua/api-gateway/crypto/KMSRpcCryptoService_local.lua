local CryptoService = require "api-gateway.crypto.CryptoService"
local cjson = require "cjson"
local httpclient = require "api-gateway.aws.httpclient.http"
local restyhttp = require "resty.http"
local socket = require "socket"
local SecretManagerService = require "api-gateway.aws.secretmanager.SecretManagerService"
local jwt = require "resty.jwt"


local ngx = ngx
local error = error
local setmetatable = setmetatable
local md5 = ngx.md5
local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64
local get_phase = ngx.get_phase

local _M = {}
local _mt = {
  __index = _M
}



local function starts_with(str, start)
  return str:sub(1, #start) == start
end

local function trim_to_nil(str)
  if str == nil then
    return nil
  end

  str = (str:gsub("^%s*(.-)%s*$", "%1"))

  if string.len(str) == 0 then
    return nil
  else
    return str
  end
end

function _M.new(o)
  local o = o or {}

  local env = os.getenv("ENV")
  local app = os.getenv("APP")

  local client_name = os.getenv("KONG_SERVICE_TO_SERVICE_AUTH_CURRENT_SERVICE_NAME")
  local rsa_private_key = os.getenv("KONG_SERVICE_TO_SERVICE_AUTH_CURRENT_SERVICE_PRIVATE_KEY")
  if env ~= nil and app ~= nil and env ~= "" and app ~= "" then
    local aws_config = cjson.decode(ngx.shared.kong:get("aws_config"))
    local region = trim_to_nil(aws_config.region)
    local access_key_id = trim_to_nil(aws_config.access_key_id)
    local secret_access_key = trim_to_nil(aws_config.secret_access_key)
    print("fetch s2s-auth info from aws service")
    -- fetch value from secret manager
    local aws_credentials = {
      provider = "api-gateway.aws.AWSIAMCredentials",
    }

    if access_key_id and secret_access_key then
      aws_credentials.access_key = access_key_id
      aws_credentials.secret_key = secret_access_key
    end

    local service = SecretManagerService:new({
      aws_region = region,
      aws_credentials = aws_credentials,
      aws_debug = true,
      aws_conn_keepalive = 60000,
      aws_conn_pool = 10
    })

    local client_name_result = service:GetSecretValue(string.format("/%s/%s/SERVICE_TO_SERVICE_AUTH_CURRENT_SERVICE_NAME", env, app))
    if client_name_result then
      client_name = client_name_result["SecretString"]
    end

    local private_key_result = service:GetSecretValue(string.format("/%s/%s/SERVICE_TO_SERVICE_AUTH_CURRENT_SERVICE_PRIVATE_KEY", env, app))
    if private_key_result then
      rsa_private_key = private_key_result["SecretString"]
    end

  end

  local config = {
    url = os.getenv("KONG_KMS_URL"),
    client_name = client_name,
    rsa_private_key = rsa_private_key:gsub("\\n", "\n"),
    token_expiration_timeout_seconds = 60 * 15,
    workspace_id = o.workspace_id or "00000000-0000-0000-0000-000000000000",
    content_type = o.content_type or 'application/json-rpc',
  }

  ngx.log(ngx.INFO, string.format(" KMSRpcCryptoService new(): %s", cjson.encode(config)))

  return setmetatable({
    config = config,
  }, _mt)

end

local function in_init_phase()
  local phase = get_phase()
  return phase == "init" or phase == "init_worker"
end

local function kms_server_error(err)
  if type(err) == 'table' then
    err = cjson.encode(err)
  end
  error("KMS service error123: " .. err, 0)
  -- TODO return detail error messaeg rather than "An unexpected error occurred"
  --return kong.response.exit(500, { message = "KMS service error:" .. err })
end


local function log_request(http_tool_type, url, headers, request_body, response_body)
  ngx.log(ngx.DEBUG, string.format("KMS JSONRPC(%s): url: %s, headers: %s, request_body: %s, response_body: %s", http_tool_type, url, cjson.encode(headers), request_body, response_body))
end

local function do_request(url, headers, request_body)

  if in_init_phase() then
    url = "https://docker.for.mac.host.internal/api/v1/internal/rpc"
    -- ngx.socket.tcp in "resty.http" is not available at the init or init_worker
    local scheme = "http"
    local port = 80
    if starts_with(url, "https") then
      scheme = "https"
      port = 8443
    end
    local httpc = httpclient.new()
    local url_path = url:gsub("^%w+://([^/]+)", "") or ""
    local request = {
      scheme = scheme,
      ssl_verify = false,
      port = port,
      timeout = 10000,
      url = url_path,
      host = url:match("^%w+://([^/]+)"),
      body = request_body,
      method = "POST",
      headers = headers,
      keepalive = 30000, -- 30s keepalive
      poolsize = 50 -- max number of connections allowed in the connection pool
    }
    local ok, code, res_headers, status, body = httpc:request(request)

    if ok and code == 200 then
      log_request('http-client', url, headers, request_body, body)
      local result = cjson.decode(body)
      if result.result then
        return result.result, nil
      else
        return nil, result.error
      end
    end

    return nil, "JSON RPC ERROR: " .. code
  else
    url = "https://docker.for.mac.host.internal:8443/api/v1/internal/rpc"
    local httpc = restyhttp.new()
    httpc:set_timeouts(10 * 1000, 5 * 1000, 20 * 1000)

    local res, err = httpc:request_uri(url, {
      method = "POST",
      body = request_body,
      headers = headers,
      --       keepalive_timeout = 60,
      --       keepalive_pool = 30,
      ssl_verify = false,
    })

    if res and res.status == 200 then
      log_request('resty-http', url, headers, request_body, (res or {}).body)
      local result = cjson.decode(res.body)
      if result.result then
        return result.result, nil
      else
        return nil, result.error
      end
    end

    return nil, "JSON RPC ERROR: ".. err
  end

end


local function fetch_jsonrpc_token(self)
  local alg = 'RS256'
  local rsa_private_key = self.config.rsa_private_key
  -- print("fetch_jsonrpc_token >>> " .. rsa_private_key)
  local header = { typ = "JWT", alg = alg }
  local claim = {
    client_name = self.config.client_name,
    exp = math.floor(ngx.now()) + self.config.token_expiration_timeout_seconds
  }

  local signature = jwt:sign(
    rsa_private_key,
    {
      header=header,
      payload=claim
    }
  )
  ngx.log(ngx.DEBUG, signature)
  return signature
end

local function jsonrpc_call(self, method, ...)
  local endpoint = self.config.url
  local JSONRequestArray = {
    id = tostring(math.random()),
    ["method"] = method,
    ["jsonrpc"] = "2.0",
    params = ...
  }

  return do_request(endpoint, {
    ["Content-Type"] = "application/json-rpc",
    ["Authorization"] = "Bearer " .. fetch_jsonrpc_token(self),
  },  cjson.encode(JSONRequestArray))
end

function _M:hash(input)
  local result = md5(input)
  --print(string.format("call hash: %s %s", input, result))
  return result
end

function _M:encrypt_plaintext(plaintext)
  local ciphertext, err = self:encrypt({
    workspace_id = self.config.workspace_id,
    key_type = "SYNC",
    plaintext = encode_base64(plaintext),
  })
  ngx.log(ngx.DEBUG, string.format("plaintext ==> ciphertext: %s %s", plaintext, ciphertext))
  return ciphertext
end

function _M:encrypt(encryptInput)
  local encryptInputs = {{encryptInput}}
  local result, err = jsonrpc_call(self, "crypto_bulkEncrypt", encryptInputs)
  if err then
    kms_server_error(err)
  end
  if #result ~= 1 then
    kms_server_error("result size not match")
  end

  return result[1].ciphertext_blob
end

function _M:decrypt_ciphertext(ciphertext)
  local plaintext, err = self:decrypt({
    workspace_id = self.config.workspace_id,
    ciphertext_blob = ciphertext,
  })
  plaintext = decode_base64(plaintext)
  ngx.log(ngx.DEBUG, string.format("ciphertext ==> plaintext: %s %s", ciphertext, plaintext))
  return plaintext
end

function _M:decrypt(decryptInput)
  local decryptInputs = {{decryptInput}}
  local result, err = jsonrpc_call(self, "crypto_bulkDecrypt", decryptInputs)
  if err then
    kms_server_error(err)
  end
  if #result ~= 1 then
    kms_server_error("result size not match")
  end

  return result[1].plaintext
end

return _M
