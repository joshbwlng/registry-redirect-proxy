FROM openresty/openresty:alpine

# Install dependencies
RUN apk add --no-cache \
    openssl \
    openssl-dev \
    git \
    gcc \
    make \
    musl-dev

# Install lua-resty-hmac via LuaRocks
RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-hmac

# Install lua-resty-string via LuaRocks
RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-string

# Create directories
RUN mkdir -p /etc/nginx/lua /var/log/nginx

# Copy nginx configuration
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Copy Lua scripts
COPY lua/ /etc/nginx/lua/

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1

# Start nginx
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
