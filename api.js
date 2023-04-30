const axios = require('axios');
const dotenv = require('dotenv');
const express = require('express');
const { Issuer, generators } = require('openid-client');
const jwtLib = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');


dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

const nonce = 'ro8gajhfmhi'
const state = '4fnwmtru7me'

app.get('/auth/facebook', async (req, res) => {
    const facebookIssuer = await Issuer.discover('https://www.facebook.com');
    const client = new facebookIssuer.Client({
        client_id: process.env.FACEBOOK_APP_ID,
        redirect_uris: ['https://oidcdebugger.com/debug'],
        response_types: ['id_token'],
    });

    const authorizationUrl = client.authorizationUrl({
        scope: 'openid',
        state: state,
        response_mode: 'form_post',
        nonce,
    });
    res.redirect(authorizationUrl);
});

app.get('/auth/facebook/validate', async (req, res) => {
    const idToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjhhYjM3MTc1MjdhZTQwMWRlNWRjMGRmNGY5ZjJmZTZkNjUwY2NhYWUifQ.eyJpc3MiOiJodHRwczpcL1wvd3d3LmZhY2Vib29rLmNvbSIsImF1ZCI6IjEzMDIwNjE3NTA1MjA5MjEiLCJzdWIiOiI2MzEwODcwMzMyMzE0MjA5IiwiaWF0IjoxNjgyNjM1ODI1LCJleHAiOjE2ODI2Mzk0MjUsImp0aSI6ImlrTXQuNmI2N2IyNjgzZGQ5YjY0NjNkMTc0MTZkNGNkYmFlZjg3NTFiZDFiNDcwOTk0NDhhMWU0N2VmYjcyOWNmMmNhMiIsIm5vbmNlIjoicm84Z2FqaGZtaGkiLCJlbWFpbCI6Imd1c3Rhdm8uMTEyMDAxXHUwMDQwaG90bWFpbC5jb20iLCJnaXZlbl9uYW1lIjoiR3VzdGF2byIsImZhbWlseV9uYW1lIjoiTXVuaG96IENvcnJlYSIsIm5hbWUiOiJHdXN0YXZvIE11bmhveiBDb3JyZWEiLCJwaWN0dXJlIjoiaHR0cHM6XC9cL3BsYXRmb3JtLWxvb2thc2lkZS5mYnNieC5jb21cL3BsYXRmb3JtXC9wcm9maWxlcGljXC8_YXNpZD02MzEwODcwMzMyMzE0MjA5JmhlaWdodD0xMDAmd2lkdGg9MTAwJmV4dD0xNjg1MjI3ODI1Jmhhc2g9QWVUSElFMk9jOXZWUEpRWGJMYyJ9.GRKyoQ4oKacwnb0g5pJpnYBPAJI640j00cehllcsZQsDcisWZfMR_LB-0xpaEk8AzUppy1LZpt2zzoiJWFynSJlXddgzrliDvXfng75u9GoxyVghCaN3OjwLloAuUpRlPTw7aYqcf44AzZy-uhV8jxyyNHJhMdCpPbTH8CvYy8KIiP3PuiFJscOhvG-X4ifGpXe6GoXqYHLYQ-ZZBOjX6qvLz6cZiOpwOKzuGhjyW1PIj7gRJvNrn0250ZA422JWYCF2nBU3q9PmdWdtKiPjTdfR_sU6VmePJLY75sxWN-kFwfox0mq3Go9Zi5APzpWeC5gKIPy_UOCGY76aLmFaSQ'
    const clientId = process.env.FACEBOOK_APP_ID;

    try {
        await validateJwt(idToken, state, nonce, clientId)
        res.send('ID token is valid');
    } catch (err) {
        console.error('ID token validation error:', err);
        res.status(400).send('Invalid ID token');
    }
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});

function getKey(header, callback) {
    const client = jwksClient({
        jwksUri: 'https://www.facebook.com/.well-known/oauth/openid/jwks/'
    });
    client.getSigningKey(header.kid, function (err, key) {
        if (err) {
            console.error('Error getting signing key:', err);
            callback(err);
            return;
        }

        if (!key) {
            console.error('No matching key found for kid:', header.kid);
            callback(new Error('No matching key found'));
            return;
        }

        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
}


async function validateJwt(jwt, nonce, clientId) {
    const decodedToken = jwtLib.decode(jwt, { complete: true });

    if (!decodedToken || !decodedToken.payload) {
        throw new Error('Invalid JWT format');
    }

    const payload = decodedToken.payload;

    const currentTimestamp = Math.floor(Date.now() / 1000);

    if (payload.exp <= currentTimestamp) {
        throw new Error('Expired JWT');
    }

    if (payload.nonce !== nonce) {
        throw new Error('Invalid nonce');
    }

    if (payload.aud !== clientId) {
        throw new Error('Invalid audience');
    }

    try {
        getKey(decodedToken.header, async (err, signingKey) => {
            if (err) {
                console.error('Error getting signing key:', err);
                return;
            }
            await jwtLib.verify(jwt, signingKey, { algorithms: ['RS256'] });

        });
    } catch (error) {
        throw new Error('Invalid JWT signature');
    }

    return payload;
}
