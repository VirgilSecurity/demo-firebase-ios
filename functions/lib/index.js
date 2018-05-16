"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const functions = require("firebase-functions");
const express = require("express");
const admin = require("firebase-admin");
const virgil_sdk_1 = require("virgil-sdk");
const virgil_crypto_1 = require("virgil-crypto");
const app = express();
admin.initializeApp();
const validateFirebaseIdToken = (req, res, next) => {
    console.log('Check if request is authorized with Firebase ID token');
    if ((!req.headers.authorization || !req.headers.authorization.startsWith('Bearer '))) {
        console.error('No Firebase ID token was passed as a Bearer token in the Authorization header.', 'Make sure you authorize your request by providing the following HTTP header:', 'Authorization: Bearer <Firebase ID Token>');
        res.status(403).send('Unauthorized');
        return;
    }
    const idToken = req.headers.authorization.split('Bearer ')[1];
    console.log('id token', idToken);
    admin.auth().verifyIdToken(idToken).then((decodedIdToken) => {
        console.log('ID Token correctly decoded', decodedIdToken);
        req.user = decodedIdToken;
        next();
    }).catch((error) => {
        console.error('Error while verifying Firebase ID token:', error);
        res.status(401).send('Unauthorized');
    });
};
const crypto = new virgil_crypto_1.VirgilCrypto();
const { appid, apikeyid, apiprivatekey } = functions.config().virgil;
const generator = new virgil_sdk_1.JwtGenerator({
    appId: appid,
    apiKeyId: apikeyid,
    apiKey: crypto.importPrivateKey(apiprivatekey),
    accessTokenSigner: new virgil_crypto_1.VirgilAccessTokenSigner(crypto)
});
app.use(validateFirebaseIdToken);
app.post('/generate_jwt', (req, res) => {
    if (!req.body || !req.body.identity)
        res.status(400).send('identity param is required');
    const virgilJwtToken = generator.generateToken(req.body.identity);
    res.json({ token: virgilJwtToken.toString() });
});
// This HTTPS endpoint can only be accessed by your Firebase Users.
// Requests need to be authorized by providing an `Authorization` HTTP header
// with value `Bearer <Firebase ID Token>`.
exports.api = functions.https.onRequest(app);
//# sourceMappingURL=index.js.map