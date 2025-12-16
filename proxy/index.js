import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import jwt from 'jsonwebtoken';
import fs from 'node:fs';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const app = express();
const PORT = 5000;

const publicKey = fs.readFileSync('/keys/public.pem');

const s3Client = new S3Client({
  region: 'us-east-1',
  endpoint: 'http://minio:9000',
  credentials: {
    accessKeyId: 'minioadmin',
    secretAccessKey: 'minioadmin',
  },
  forcePathStyle: true,
});

const sendAuthChallenge = (res, repo, message = 'authentication required', code = 'UNAUTHORIZED') => {
  const challenge = `Bearer realm="http://localhost:8001/auth/v1/token",service="zot",scope="repository:${repo}:pull"`;
  res.set('www-authenticate', challenge);
  res.set('docker-distribution-api-version', 'registry/2.0');
  return res.status(401).json({
    errors: [{
      code,
      message,
      detail: [{"Type":"repository","Name":repo,"Action":"pull"}]
    }],
  });
};

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  console.warn('Authorization Header:', authHeader);

  // Parse repo and digest from URL
  const match = req.url.match(/^\/v2\/([\/a-z0-9]+)\/blobs\/sha256:([a-f0-9]{64})$/);
  if (match) {
    req.params = {
      repo: match[1],
      digest: match[2],
    };
  } else {
    console.error('URL does not match expected pattern for blob download');
    return res.status(400).json({ error: 'Bad Request: Invalid URL format' });
  }
  if (!authHeader) {
    console.warn('No Authorization header present');
    return sendAuthChallenge(res, match[1], 'authentication required', 'UNAUTHORIZED');
  }

  const token = authHeader.match(/^Bearer\s+(.+)$/)?.[1];
  if (!token) {
    return sendAuthChallenge(res, match[1], 'authentication required', 'UNAUTHORIZED');
  }
  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    const hasAccess = decoded.access.find(a => a.type === 'repository' && a.name === match[1] && a.actions.includes('pull'));
    if (!hasAccess) {
      console.warn('Token does not have access entry for the requested repository');
      return sendAuthChallenge(res, match[1], 'insufficient scope', 'UNAUTHORIZED');
    }
    req.jwt = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
};

app.get(/^\/v2\/[\/a-z0-9]+\/blobs\/sha256:[a-f0-9]{64}$/, verifyJWT, async (req, res) => {
  const { repo, digest } = req.params;

  try {
    const command = new GetObjectCommand({
      Bucket: 'zot',
      Key: `data/data/${repo}/blobs/sha256/${digest}`,
    });
    const signedUrl = await getSignedUrl(s3Client, command, { expiresIn: 3600 });
    console.log(`Redirecting to S3: ${signedUrl}`);
    res.redirect(307, signedUrl);
  } catch (error) {
    console.error('Error generating signed URL:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.use('/', createProxyMiddleware({
  target: 'http://zot:5001',
  changeOrigin: true,
  logger: console,
  logLevel: 'debug',
}));

app.listen(PORT, () => {
  console.log(`Proxy server running on port: ${PORT}`);
});
