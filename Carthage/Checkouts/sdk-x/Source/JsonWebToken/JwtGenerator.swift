//
// Copyright (C) 2015-2018 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation
import VirgilCryptoAPI

/// Class responsible for JWT generation
@objc(VSSJwtGenerator) open class JwtGenerator: NSObject {
    /// Api Private Key for signing generated tokens
    /// - Note: Can be taken [here](https://dashboard.virgilsecurity.com/api-keys)
    @objc public let apiKey: PrivateKey
    /// Public Key identifier of Api Key
    /// - Note: Can be taken [here](https://dashboard.virgilsecurity.com/api-keys)
    @objc public let apiPublicKeyIdentifier: String
    /// Implementation of AccessTokenSigner for signing generated tokens
    @objc public let accessTokenSigner: AccessTokenSigner
    /// Application Id
    /// - Note: Can be taken [here](https://dashboard.virgilsecurity.com)
    @objc public let appId: String
    /// Lifetime of generated tokens
    @objc public let ttl: TimeInterval

    /// Initializer
    ///
    /// - Parameters:
    ///   - apiKey: Api Private Key for signing generated tokens
    ///   - apiPublicKeyIdentifier: Public Key identifier of Api Key
    ///   - accessTokenSigner: implementation of AccessTokenSigner for signing generated tokens
    ///   - appId: Application Id
    ///   - ttl: Lifetime of generated tokens
    @objc public init(apiKey: PrivateKey, apiPublicKeyIdentifier: String,
                      accessTokenSigner: AccessTokenSigner, appId: String, ttl: TimeInterval) {
        self.apiKey = apiKey
        self.apiPublicKeyIdentifier = apiPublicKeyIdentifier
        self.accessTokenSigner = accessTokenSigner
        self.appId = appId
        self.ttl = ttl

        super.init()
    }

    /// Generates new JWT
    ///
    /// - Parameters:
    ///   - identity: Identity to generate with
    ///   - additionalData: Dictionary with additional data
    /// - Returns: Generated and signed `Jwt`
    /// - Throws: Rethrows from JwtHeaderContent, JwtBodyContent, Jwt, AccessTokenSigner
    @objc public func generateToken(identity: String, additionalData: [String: String]? = nil) throws -> Jwt {
        let jwtHeaderContent = try JwtHeaderContent(keyIdentifier: self.apiPublicKeyIdentifier)
        let jwtBodyContent = try JwtBodyContent(appId: self.appId, identity: identity,
                                                expiresAt: Date() + self.ttl, issuedAt: Date(),
                                                additionalData: additionalData)

        let data = try Jwt.dataToSign(headerContent: jwtHeaderContent, bodyContent: jwtBodyContent)

        let signature = try self.accessTokenSigner.generateTokenSignature(of: data, using: self.apiKey)

        return try Jwt(headerContent: jwtHeaderContent, bodyContent: jwtBodyContent,
                       signatureContent: JwtSignatureContent(signature: signature))
    }
}
