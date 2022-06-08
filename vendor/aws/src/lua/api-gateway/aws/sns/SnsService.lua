-- SNS Client
-- Created by IntelliJ IDEA.
-- User: ddascal
-- Date: 21/11/14
-- Time: 16:16
-- To change this template use File | Settings | File Templates.
local http = require"api-gateway.aws.httpclient.http"
local restyhttp = require"api-gateway.aws.httpclient.restyhttp"

local AwsService = require"api-gateway.aws.AwsService"
local cjson = require"cjson"
local error = error

local _M = AwsService:new({ ___super = true })
local super = {
    instance = _M,
    constructor = _M.constructor
}

function _M.new(self, o)
    ngx.log(ngx.DEBUG, "SnsService() o=", tostring(o))
    local o = o or {}
    o.aws_service = "sns"
    -- aws_service_name is used in the X-Amz-Target Header: i.e AmazonSimpleNotificationService.ListTopics
    o.aws_service_name = "AmazonSimpleNotificationService"
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

-- API: http://docs.aws.amazon.com/sns/latest/APIReference/API_ListTopics.html
function _M:listTopics()
    local arguments = {}
    local ok, code, headers, status, body = self:performAction("ListTopics", arguments, "/", "GET", true)

    if (code == ngx.HTTP_OK and body ~= nil) then
        return cjson.decode(body), code, headers, status, body
    end
    return nil, code, headers, status, body
end


local function concatenateTables(...)
    local result = {}

    for i = 1, select("#", ...) do
        local arg = select(i, ...)

        if type(arg) == "table" then
            for k, v in pairs(arg) do
                if (result[k] == nil) then
                    result[k] = v
                end
            end
        end
    end

    return result
end

function _M:formatMessageAttributes(raw_message_attributes)
    local message_attributes = {}

    if raw_message_attributes ~= nil and type(raw_message_attributes) == "table" then
        local counter = 1
        for k, v in pairs(raw_message_attributes) do
            message_attributes["MessageAttributes.entry." .. counter .. ".Name"] = k
            message_attributes["MessageAttributes.entry." .. counter .. ".Value.DataType"] = "String"
            message_attributes["MessageAttributes.entry." .. counter .. ".Value.StringValue"] = v
            counter = counter + 1
        end
    end

    return message_attributes

end

--- API: http://docs.aws.amazon.com/sns/latest/APIReference/API_Publish.html
function _M:publish(subject, message, topicArn, targetArn, raw_message_attributes)
    local arguments = {
        Message = message,
        Subject = subject,
        TopicArn = topicArn,
        TargetArn = targetArn
    }

    local message_attributes = self:formatMessageAttributes(raw_message_attributes)
    if message_attributes ~= nil then
        arguments = concatenateTables(arguments, message_attributes)
    end

    local timeout = 60000
    local ok, code, headers, status, body = self:performAction("Publish", arguments, "/", "POST", true, timeout, "application/x-www-form-urlencoded")

    if (code == ngx.HTTP_OK and body ~= nil) then
        return cjson.decode(body), code, headers, status, body
    end
    return nil, code, headers, status, body
end

return _M
