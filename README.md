# registry-redirect-proxy

Very simple example of standing up a proxy in front of zot to redirect authorized layer download requests to s3 signed urls while proxying other requests on to zot itself

Generate keypair:
```bash
mkdir keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

Start cluster:
```bash
docker compose up --build
```

Push an image directly to zot:
```bash
docker tag hello-world localhost:5001/v2/foobar:latest
docker push localhost:5001/v2/foobar:latest
```

Pull via the proxy and watch proxy+api service logs to see that (a) JWT tokens are being generated and returned to the client and (b) a signed URL is being returned to the client with a redirect 307 response:
```
docker logs -f zot-test-api-1
docker logs -f registry-redirect
docker rmi hello-world:latest localhost:5001/v2/foobar:latest
docker pull localhost:5000/v2/foobar:latest
```
