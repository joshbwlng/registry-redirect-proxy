-- Main redirect handler
local jwt = require "jwt"
local s3 = require "s3"

-- Extract JWT token from Authorization header
local function get_token_from_header()
    local auth_header = ngx.var.http_authorization
    if not auth_header then
        return nil, "No Authorization header"
    end
    
    -- Check for Bearer token
    local bearer_token = auth_header:match("^Bearer%s+(.+)$")
    if bearer_token then
        return bearer_token, nil
    end
    
    return nil, "Invalid Authorization header format"
end

-- Extract repository path and object from the request
local function parse_request_path()
    local repo_path = ngx.var.repo_path
    local digest = ngx.var.digest
    local reference = ngx.var.reference
    
    if not repo_path then
        return nil, nil, "Failed to parse repository path"
    end
    
    -- Determine the object key (digest or reference)
    local object_key
    if digest then
        object_key = digest
    elseif reference then
        object_key = reference
    else
        return nil, nil, "No digest or reference found"
    end
    
    return repo_path, object_key, nil
end

-- Build S3 key from repository and object
local function build_s3_key(repo_path, object_key)
    -- Docker registry blob storage structure in S3
    -- Typical format: docker/registry/v2/blobs/sha256/ab/abc123.../data
    -- or for manifests: docker/registry/v2/repositories/{repo}/manifests/{tag or sha}
    
    -- Check if it's a digest (blob)
    if object_key:match("^sha256:") then
        local hash = object_key:sub(8) -- Remove 'sha256:' prefix
        local prefix = hash:sub(1, 2)
        -- Standard blob path
        return "docker/registry/v2/blobs/sha256/" .. prefix .. "/" .. hash .. "/data"
    else
        -- Manifest path
        return "docker/registry/v2/repositories/" .. repo_path .. "/_manifests/tags/" .. object_key .. "/current/link"
    end
end

-- Main handler
local jwt_secret = ngx.var.jwt_secret
local s3_bucket = ngx.var.s3_bucket
local s3_region = ngx.var.s3_region
local s3_access_key = ngx.var.s3_access_key
local s3_secret_key = ngx.var.s3_secret_key
local s3_endpoint = ngx.var.s3_endpoint

-- Validate environment configuration
if not jwt_secret or jwt_secret == "" then
    ngx.log(ngx.ERR, "JWT_SECRET not configured")
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("Configuration error")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

if not s3_bucket or s3_bucket == "" then
    ngx.log(ngx.ERR, "S3_BUCKET not configured")
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("Configuration error")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

if not s3_access_key or s3_access_key == "" or not s3_secret_key or s3_secret_key == "" then
    ngx.log(ngx.ERR, "S3 credentials not configured")
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("Configuration error")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

-- Extract and validate JWT token
local token, err = get_token_from_header()
if not token then
    ngx.log(ngx.WARN, "Failed to extract token: ", err)
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["WWW-Authenticate"] = 'Bearer realm="Registry"'
    ngx.say("Unauthorized: ", err)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local payload, err = jwt.validate(token, jwt_secret)
if not payload then
    ngx.log(ngx.WARN, "JWT validation failed: ", err)
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["WWW-Authenticate"] = 'Bearer realm="Registry"'
    ngx.say("Unauthorized: ", err)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Parse request path
local repo_path, object_key, err = parse_request_path()
if not repo_path then
    ngx.log(ngx.ERR, "Failed to parse request: ", err)
    ngx.status = ngx.HTTP_BAD_REQUEST
    ngx.say("Bad request: ", err)
    return ngx.exit(ngx.HTTP_BAD_REQUEST)
end

-- Check permissions (pull action for GET requests)
local has_permission, err = jwt.check_permission(payload, repo_path, "pull")
if not has_permission then
    ngx.log(ngx.WARN, "Permission denied for ", repo_path, ": ", err)
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say("Forbidden: ", err)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- Build S3 key
local s3_key = build_s3_key(repo_path, object_key)
ngx.log(ngx.INFO, "Generating S3 URL for key: ", s3_key)

-- Generate presigned S3 URL (20 minutes expiration)
local presigned_url = s3.generate_presigned_url(
    s3_bucket,
    s3_key,
    s3_access_key,
    s3_secret_key,
    s3_region,
    s3_endpoint,
    1200  -- 20 minutes in seconds
)

-- Log the redirect
ngx.log(ngx.INFO, "Redirecting ", repo_path, "/", object_key, " to S3")

-- Perform redirect
return ngx.redirect(presigned_url, ngx.HTTP_TEMPORARY_REDIRECT)
