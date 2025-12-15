-- S3 URL signing module
local resty_hmac = require "resty.hmac"
local resty_string = require "resty.string"

local _M = {}

-- URL encode
local function url_encode(str)
    if str then
        str = string.gsub(str, "\n", "\r\n")
        str = string.gsub(str, "([^%w%-%.%_%~ ])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
        str = string.gsub(str, " ", "+")
    end
    return str
end

-- SHA256 hash
local function sha256(data)
    local resty_sha256 = require "resty.sha256"
    local sha = resty_sha256:new()
    sha:update(data)
    return sha:final()
end

-- HMAC SHA256
local function hmac_sha256(key, data)
    local hmac = resty_hmac:new(key, resty_hmac.ALGOS.SHA256)
    hmac:update(data)
    return hmac:final()
end

-- Get AWS signature key
local function get_signature_key(key, date_stamp, region, service)
    local k_date = hmac_sha256("AWS4" .. key, date_stamp)
    local k_region = hmac_sha256(k_date, region)
    local k_service = hmac_sha256(k_region, service)
    local k_signing = hmac_sha256(k_service, "aws4_request")
    return k_signing
end

-- Generate AWS v4 signature
local function sign_v4(method, host, uri, query_string, headers, payload_hash, access_key, secret_key, region, service, timestamp)
    -- Create canonical request
    local canonical_uri = uri
    local canonical_querystring = query_string
    
    -- Sort and format headers
    local canonical_headers = ""
    local signed_headers_list = {}
    for k, v in pairs(headers) do
        table.insert(signed_headers_list, k:lower())
    end
    table.sort(signed_headers_list)
    
    local signed_headers = table.concat(signed_headers_list, ";")
    for _, k in ipairs(signed_headers_list) do
        canonical_headers = canonical_headers .. k .. ":" .. headers[k] .. "\n"
    end
    
    local canonical_request = method .. "\n" .. 
                             canonical_uri .. "\n" .. 
                             canonical_querystring .. "\n" .. 
                             canonical_headers .. "\n" .. 
                             signed_headers .. "\n" .. 
                             payload_hash
    
    -- Create string to sign
    local date_stamp = os.date("!%Y%m%d", timestamp)
    local amz_date = os.date("!%Y%m%dT%H%M%SZ", timestamp)
    local credential_scope = date_stamp .. "/" .. region .. "/" .. service .. "/aws4_request"
    
    local canonical_request_hash = resty_string.to_hex(sha256(canonical_request))
    local string_to_sign = "AWS4-HMAC-SHA256\n" .. 
                          amz_date .. "\n" .. 
                          credential_scope .. "\n" .. 
                          canonical_request_hash
    
    -- Calculate signature
    local signing_key = get_signature_key(secret_key, date_stamp, region, service)
    local signature = resty_string.to_hex(hmac_sha256(signing_key, string_to_sign))
    
    return signature, signed_headers, amz_date, credential_scope
end

-- Generate presigned S3 URL
function _M.generate_presigned_url(bucket, key, access_key, secret_key, region, endpoint, expiration)
    if not expiration then
        expiration = 1200 -- 20 minutes default
    end
    
    local timestamp = ngx.time()
    local date_stamp = os.date("!%Y%m%d", timestamp)
    local amz_date = os.date("!%Y%m%dT%H%M%SZ", timestamp)
    
    -- Determine host
    local host
    if endpoint and endpoint ~= "" then
        -- Custom endpoint (e.g., MinIO)
        host = endpoint:gsub("^https?://", "")
    else
        -- Standard S3 endpoint
        if region == "us-east-1" then
            host = bucket .. ".s3.amazonaws.com"
        else
            host = bucket .. ".s3." .. region .. ".amazonaws.com"
        end
    end
    
    -- Build canonical URI
    local canonical_uri = "/" .. key
    
    -- Build query parameters
    local credential = access_key .. "/" .. date_stamp .. "/" .. region .. "/s3/aws4_request"
    
    local query_params = {
        ["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256",
        ["X-Amz-Credential"] = credential,
        ["X-Amz-Date"] = amz_date,
        ["X-Amz-Expires"] = tostring(expiration),
        ["X-Amz-SignedHeaders"] = "host"
    }
    
    -- Sort query parameters
    local sorted_keys = {}
    for k in pairs(query_params) do
        table.insert(sorted_keys, k)
    end
    table.sort(sorted_keys)
    
    local query_parts = {}
    for _, k in ipairs(sorted_keys) do
        table.insert(query_parts, url_encode(k) .. "=" .. url_encode(query_params[k]))
    end
    local canonical_querystring = table.concat(query_parts, "&")
    
    -- Create headers for signing
    local headers = {
        host = host
    }
    
    -- Generate signature
    local signature, signed_headers, _, _ = sign_v4(
        "GET",
        host,
        canonical_uri,
        canonical_querystring,
        headers,
        "UNSIGNED-PAYLOAD",
        access_key,
        secret_key,
        region,
        "s3",
        timestamp
    )
    
    -- Build final URL
    local protocol = "https"
    if endpoint and endpoint:match("^http://") then
        protocol = "http"
    end
    
    local url = protocol .. "://" .. host .. canonical_uri .. "?" .. 
                canonical_querystring .. "&X-Amz-Signature=" .. signature
    
    return url
end

return _M
