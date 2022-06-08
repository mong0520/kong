local CryptoService = require "api-gateway.crypto.CryptoService"
local cjson = require "cjson"
local error = error
local httpclient = require "api-gateway.aws.httpclient.http"
local restyhttp = require "resty.http"
local socket = require "socket"

local setmetatable = setmetatable
local md5 = ngx.md5
local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64
local get_phase = ngx.get_phase

local _M = {}
local _mt = {
  __index = _M
}

function _M.new(o)
  local o = o or {}

  local config = {
    kms_url = o.kms_url,
    kms_key_group = o.key_group or "API_GATEWAY",
    kms_workspace_id = o.kms_workspace_id or "00000000-0000-0000-0000-000000000000",
    content_type = o.content_type or 'application/json',
  }

  ngx.log(ngx.INFO, string.format(" KMSCryptoService new(): %s", cjson.encode(config)))
  print("KONG_KMS_URL:" .. os.getenv("KONG_KMS_URL"))
  print("KONG_KMS_KEY_GROUP:" .. os.getenv("KONG_KMS_KEY_GROUP"))



  return setmetatable({
    config = config,
  }, _mt)

end


local function starts_with(str, start)
  return str:sub(1, #start) == start
end

local function in_init_phase()
  local phase = get_phase()
  return phase == "init" or phase == "init_worker"
end

local function kms_server_error(err)
  error("KMS service error: " .. err, 0)
  -- TODO return detail error messaeg rather than "An unexpected error occurred"
  --return kong.response.exit(500, { message = "KMS service error:" .. err })
end

local function execute(self, path, request_body)

  local kms_url = self.config.kms_url
  local url = kms_url .. path
  local payload = cjson.encode(request_body)
  local http_tool_type

  local http_result, http_error
  local start = socket.gettime()
  if in_init_phase() then
    -- ngx.socket.tcp in "resty.http" is not available at the init or init_worker
    http_tool_type = 'http-client'
    local scheme = "http"
    local port = 80
    if starts_with(kms_url, "https") then
      scheme = "https"
      port = 443
    end

    local httpc = httpclient.new()
    local url_path = url:gsub("^%w+://([^/]+)", "") or ""
    local request = {
      scheme = scheme,
      ssl_verify = false,
      port = port,
      timeout = 10000,
      url = url_path,
      host = kms_url:match("^%w+://([^/]+)"),
      body = payload,
      method = "POST",
      headers = {
        ["Content-Type"] = self.config.content_type,
      },
      keepalive = 30000, -- 30s keepalive
      poolsize = 50 -- max number of connections allowed in the connection pool
    }
    --print(string.format("request obj: %s", cjson.encode(request)))
    local ok, code, headers, status, body = httpc:request(request)

    if ok then
      if code ~= 200 then
        http_error = body
      end

      http_result = {
        body = body,
        code = code,
      }
    else
      http_error = code
    end

  else
    http_tool_type = 'resty-http'
    local httpc = restyhttp.new()
    httpc:set_timeouts(10 * 1000, 5 * 1000, 20 * 1000)

    local res, err = httpc:request_uri(url, {
      method = "POST",
      body = payload,
      headers = {
        ["Content-Type"] = self.config.content_type,
      },
--       keepalive_timeout = 60,
--       keepalive_pool = 30,
      ssl_verify = false,
    })

    if res then
      if res.status ~= 200 then
        http_error = res.body
      end

      http_result = {
        body = res.body,
        code = res.status,
      }
    else
      http_error = err
    end
  end
  local stop = socket.gettime()

  if http_error then
    kms_server_error(http_error)
  end

  -- check code
  ngx.log(ngx.DEBUG, string.format("KMS Request(%s): url: %s, request_body: %s, http_code: %s response_body: %s", http_tool_type, url, payload, http_result.code, http_result.body))
  local body = cjson.decode(http_result.body)
  if body.code then
    kms_server_error(body.msg)
  end
  return body, nil
end


function _M:hash(input)
  local result = md5(input)
  print(string.format("call hash: %s %s", input, result))
  return result
end

function _M:encrypt_plaintext(plaintext)
  local ciphertext, err =  self:encrypt({
    key_group = self.config.kms_key_group,
    workspace_id = self.config.kms_workspace_id,
    key_type = "SYNC",
    plaintext = encode_base64(plaintext),
  })
  ngx.log(ngx.DEBUG, string.format("plaintext ==> ciphertext: %s %s", plaintext, ciphertext))
  return ciphertext, err
end

function _M:encrypt(encryptInput)
  local path = "/api/v1/workspaces/" .. encryptInput.workspace_id  .. "/crypto/encrypt"
  local result, err = execute(self, path, encryptInput)
  --ngx.log(ngx.DEBUG, string.format("KMS Request(http-client): url: %s, request body: %s, response body: %s", url, payload, ''))
  if err then
    return nil, err
  end

  return result.ciphertext_blob, nil
end

function _M:decrypt_ciphertext(ciphertext)
  local plaintext, err = self:decrypt({
    workspace_id = self.config.kms_workspace_id,
    ciphertext_blob = ciphertext,
  })
  ngx.log(ngx.DEBUG, string.format("ciphertext ==> plaintext: %s %s", ciphertext, decode_base64(plaintext)))
  return decode_base64(plaintext), err
end

function _M:decrypt(decryptInput)
  local path = "/api/v1/workspaces/" ..  decryptInput.workspace_id .. "/crypto/decrypt"
  local result, err = execute(self, path, decryptInput)
  if err then
    return nil, err
  end

  return result.plaintext, nil
end


--function _M:batchEncrypt(encryptInputs)
--  local path = "/api/v1/bulk/crypto/encrypt"
--  local res, err = execute(self, path, {
--    workspace_id = "00000000-0000-0000-0000-000000000000",
--    key_group = "",
--    key_type = "HASH",
--    plaintext = "",
--  })
--  print("calling KMSCryptoService batchEncrypt")
--end
--
--
--function _M:batchDecrypt(decryptInputs)
--  local path = "/api/v1/bulk/crypto/decrypt"
--  local res, err = execute(self, path, {
--    workspace_id = "00000000-0000-0000-0000-000000000000",
--    key_group = "",
--    key_type = "HASH",
--    plaintext = "",
--  })
--  print("calling KMSCryptoService batchDecrypt")
--end

return _M