import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';

const app = express();
const PORT = process.env.PORT || 3000;

// Load Private Key
const privateKey = fs.readFileSync(path.join(__dirname, 'keys', 'private.pem'));

app.get('/auth/v1/token', (req: Request, res: Response) => {
    console.log(`[Token Server] Received auth request:`, req.query);

    const service = req.query.service as string;
    const scope = req.query.scope as string;
    const account = req.query.account as string || 'anonymous';

    // 1. Parse the requested scope (e.g., "repository:test-repo:pull,push")
    let access: any[] = [];
    
    if (scope) {
        const parts = scope.split(':');
        if (parts.length === 3) {
            access.push({
                type: parts[0],    // "repository"
                name: parts[1],    // "test-repo"
                actions: parts[2].split(',') // ["pull", "push"]
            });
        }
    }

    // 2. Construct JWT Payload (Standard Docker Registry Spec)
    const payload = {
        iss: 'my-auth-api',       // Issuer (must match implied trust, though Zot only checks sig)
        sub: account,             // Subject (who is this token for?)
        aud: service,             // Audience (must match "service" in zot-config.json)
        access: access            // The permissions list
    };

    // 3. Sign the Token
    const token = jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        expiresIn: '1h',
        keyid: 'my-key-id'      // Optional: Key ID useful for rotation
    });

    console.log(`[Token Server] Issued token for scope: ${scope}`);

    // 4. Return standard Docker/Distribution format
    res.json({
        token: token,
        access_token: token // Some older clients look for this field
    });
});

app.listen(PORT, () => {
    console.log(`[Token Server] Listening on port ${PORT}`);
});
