-- JWT validation module
local cjson = require "cjson"
local resty_hmac = require "resty.hmac"
local resty_string = require "resty.string"

local _M = {}

-- Base64 URL decode
local function base64_url_decode(input)
    local remainder = #input % 4
    if remainder > 0 then
        local padlen = 4 - remainder
        input = input .. string.rep('=', padlen)
    end
    input = input:gsub('-', '+'):gsub('_', '/')
    return ngx.decode_base64(input)
end

-- Base64 URL encode
local function base64_url_encode(input)
    local b64 = ngx.encode_base64(input)
    return b64:gsub('+', '-'):gsub('/', '_'):gsub('=', '')
end

-- Parse JWT token
local function parse_jwt(token)
    local parts = {}
    for part in token:gmatch("[^%.]+") do
        table.insert(parts, part)
    end
    
    if #parts ~= 3 then
        return nil, "Invalid JWT format"
    end
    
    local header_json = base64_url_decode(parts[1])
    local payload_json = base64_url_decode(parts[2])
    
    if not header_json or not payload_json then
        return nil, "Failed to decode JWT"
    end
    
    local ok, header = pcall(cjson.decode, header_json)
    if not ok then
        return nil, "Failed to parse JWT header"
    end
    
    ok, payload = pcall(cjson.decode, payload_json)
    if not ok then
        return nil, "Failed to parse JWT payload"
    end
    
    return {
        header = header,
        payload = payload,
        signature = parts[3],
        signing_input = parts[1] .. "." .. parts[2]
    }
end

-- Verify JWT signature using HMAC
local function verify_signature(signing_input, signature, secret, algorithm)
    if not algorithm then
        algorithm = "HS256"
    end
    
    local hmac_type
    if algorithm == "HS256" then
        hmac_type = resty_hmac.ALGOS.SHA256
    elseif algorithm == "HS384" then
        hmac_type = resty_hmac.ALGOS.SHA384
    elseif algorithm == "HS512" then
        hmac_type = resty_hmac.ALGOS.SHA512
    else
        return false, "Unsupported algorithm: " .. algorithm
    end
    
    local hmac = resty_hmac:new(secret, hmac_type)
    if not hmac then
        return false, "Failed to create HMAC"
    end
    
    local ok = hmac:update(signing_input)
    if not ok then
        return false, "Failed to update HMAC"
    end
    
    local computed_sig = hmac:final()
    local encoded_sig = base64_url_encode(computed_sig)
    
    return encoded_sig == signature, nil
end

-- Validate JWT token
function _M.validate(token, secret)
    if not token then
        return nil, "No token provided"
    end
    
    if not secret or secret == "" then
        return nil, "No secret configured"
    end
    
    local jwt, err = parse_jwt(token)
    if not jwt then
        return nil, err
    end
    
    -- Check algorithm
    local alg = jwt.header.alg
    if not alg or (alg ~= "HS256" and alg ~= "HS384" and alg ~= "HS512") then
        return nil, "Unsupported or missing algorithm"
    end
    
    -- Verify signature
    local valid, err = verify_signature(jwt.signing_input, jwt.signature, secret, alg)
    if not valid then
        return nil, err or "Invalid signature"
    end
    
    -- Check expiration
    if jwt.payload.exp then
        local now = ngx.time()
        if now >= jwt.payload.exp then
            return nil, "Token expired"
        end
    end
    
    -- Check not before
    if jwt.payload.nbf then
        local now = ngx.time()
        if now < jwt.payload.nbf then
            return nil, "Token not yet valid"
        end
    end
    
    return jwt.payload, nil
end

-- Check if token has permission for repository and action
function _M.check_permission(payload, repository, action)
    if not payload.access then
        return false, "No access claims in token"
    end
    
    -- Docker registry JWT tokens typically have an 'access' array
    -- Format: [{type: "repository", name: "repo/path", actions: ["pull", "push"]}]
    for _, access in ipairs(payload.access) do
        if access.type == "repository" and access.name == repository then
            if access.actions then
                for _, act in ipairs(access.actions) do
                    if act == action or act == "*" then
                        return true, nil
                    end
                end
            end
        end
    end
    
    return false, "Insufficient permissions"
end

return _M
