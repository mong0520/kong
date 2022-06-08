-- SecretManager Client


local AwsService = require "api-gateway.aws.AwsService"
local cjson = require "cjson"
local error = error
local http = require"api-gateway.aws.httpclient.http"
local restyhttp = require"api-gateway.aws.httpclient.restyhttp"

local _M = AwsService:new({ ___super = true })
local super = {
    instance = _M,
    constructor = _M.constructor
}

function _M.new(self, o)
    ngx.log(ngx.DEBUG, "SecretManagerService() o=", tostring(o))
    local o = o or {}
    o.aws_service = "secretsmanager"
    -- aws_service_name is used in the X-Amz-Target Header: i.e Kinesis_20131202.ListStreams
    o.aws_service_name = "secretsmanager"

    -- http_client
    local traceback = debug.traceback()
    --print("traceback:", type(traceback), traceback)
    local http_client
    local idx = string.find(traceback, "kong/cmd")
    if idx then
        print("use resty http (cosocket) to send https requests")
        http_client = restyhttp:new()
    else
        print("use luasocket + luasec to send http(s) requests")
        http_client = http:new()
    end

    o.http_client = http_client


    super.constructor(_M, o)

    setmetatable(o, self)
    self.__index = self
    return o
end

-- API: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
function _M:GetSecretValue(secretId)
    local path = "/"
    local arguments = {
        SecretId = secretId
    }

    -- actionName, arguments, path, http_method, useSSL, timeout, contentType
    local ok, code, headers, status, body = self:performAction("GetSecretValue", arguments, path, "POST", true, 60000)

    if (code == ngx.HTTP_OK and body ~= nil) then
        return cjson.decode(body), code, headers, status, body
    end
    return nil, code, headers, status, body
end

return _M

