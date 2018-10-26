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

/// Class responsible for verification of JWTs
@objc(VSSJwtVerifier) open class JwtVerifier: NSObject {
    /// Public Key which should be used to verify signatures
    @objc public let apiPublicKey: PublicKey
    /// Identifier of public key which should be used to verify signatures
    @objc public let apiPublicKeyIdentifier: String
    /// AccessTokenSigner implementation for verifying signatures
    @objc public let accessTokenSigner: AccessTokenSigner

    /// Initializer
    ///
    /// - Parameters:
    ///   - apiPublicKey: Public Key which should be used to verify signatures
    ///   - apiPublicKeyIdentifier: identifier of public key which should be used to verify signatures
    ///   - accessTokenSigner: AccessTokenSigner implementation for verifying signatures
    @objc public init(apiPublicKey: PublicKey, apiPublicKeyIdentifier: String, accessTokenSigner: AccessTokenSigner) {
        self.apiPublicKey = apiPublicKey
        self.apiPublicKeyIdentifier = apiPublicKeyIdentifier
        self.accessTokenSigner = accessTokenSigner
    }

    /// Verifies Jwt signature
    ///
    /// - Parameter token: Jwt to be verified
    /// - Returns: true if token is verified, false otherwise
    @objc public func verify(token: Jwt) -> Bool {
        do {
            let data = try token.dataToSign()
            let signature = token.signatureContent.signature

            return self.accessTokenSigner.verifyTokenSignature(signature, of: data, with: self.apiPublicKey)
        }
        catch {
            return false
        }
    }
}
