"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const functions = require("firebase-functions");
const express = require("express");
const admin = require("firebase-admin");
// import { JwtGenerator } from 'virgil-sdk';
// import { createVirgilCrypto, VirgilAccessTokenSigner } from 'virgil-crypto';
const app = express();
admin.initializeApp();
// // Start writing Firebase Functions
// // https://firebase.google.com/docs/functions/typescript
//
// export const helloWorld = functions.https.onRequest((request, response) => {
//  response.send("Hello from Firebase!");
// });
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
        res.status(403).send('Unauthorized');
    });
};
app.use(validateFirebaseIdToken);
app.post('/generate_jwt', (req, res) => {
    const { appid, apikeyid, apiprivatekey } = functions.config().virgil;
    // const crypto = createVirgilCrypto();
    // const generator = new JwtGenerator({
    //  appId: appid,
    // 	apiKeyId: apikeyid,
    // 	apiKey: crypto.importPrivateKey(apiprivatekey),
    // 	accessTokenSigner: new VirgilAccessTokenSigner(crypto)
    // })
    // const virgilJwtToken = generator.generateToken(req.body.identity);
    console.log('credentials:', appid, apikeyid, apiprivatekey);
    res.json({ token: req.body.identity });
});
// This HTTPS endpoint can only be accessed by your Firebase Users.
// Requests need to be authorized by providing an `Authorization` HTTP header
// with value `Bearer <Firebase ID Token>`.
exports.api = functions.https.onRequest(app);
//# sourceMappingURL=index.js.map