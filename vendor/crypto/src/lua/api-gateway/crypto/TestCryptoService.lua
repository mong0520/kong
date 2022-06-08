local cjson = require"cjson"


local _M = {}

local _mt = {
  __index = _M
}

local setmetatable = setmetatable
local md5 = ngx.md5
local error = error

function _M:hash(input)
  local result = md5(input)
  print(string.format("call hash: %s %s", input, result))
  return result
end

function _M:encrypt(encryptInput)
  print(string.format("[test-crypto]: call encrypt: %s", encryptInput))
  return encryptInput .. "_encrypted"
end

function _M:decrypt(decryptInput)
  print(string.format("[test-crypto]: call decrypt: %s", decryptInput))
  return decryptInput:gsub("c", "")
end


function _M:batchEncrypt(encryptInputs)
end


function _M:batchDecrypt(decryptInputs)
end


function _M.new()
  return setmetatable({
  }, _mt)
end

return _M
