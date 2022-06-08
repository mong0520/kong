
local CryptoService = {}


local setmetatable = setmetatable
local error = error
local debugCryptoServiceode = ngx.config.debug
local cjson = require"cjson"

function CryptoService:hash(input)

end

function CryptoService:encrypt(encryptInput)
  print("calling CryptoService encrypt")
end

function CryptoService:decrypt(decryptInput)
  print("calling CryptoService decrypt")
end


function CryptoService:batchEncrypt(encryptInputs)
  print("calling CryptoService batchEncrypt")
end


function CryptoService:batchDecrypt(decryptInputs)
  print("calling CryptoService batchDecrypt")
end



return CryptoService