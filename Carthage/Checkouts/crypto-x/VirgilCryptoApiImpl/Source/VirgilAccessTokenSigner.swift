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

/// Adapter for AccessTokenSigner protocol using VirgilCrypto
@objc(VSMVirgilAccessTokenSigner) public class VirgilAccessTokenSigner: NSObject {
    /// VirgilCrypto instance
    @objc public let virgilCrypto: VirgilCrypto

    /// Initializer
    ///
    /// - Parameter virgilCrypto: VirgilCrypto instance
    @objc public init(virgilCrypto: VirgilCrypto = VirgilCrypto()) {
        self.virgilCrypto = virgilCrypto

        super.init()
    }
}

// MARK: - Implementation of AccessTokenSigner protocol
extension VirgilAccessTokenSigner: AccessTokenSigner {
    /// Generates digital signature for token
    ///
    /// - Parameters:
    ///   - token: Token to be signed
    ///   - privateKey: Private key
    /// - Returns: Digital signature data
    /// - Throws: Rethrows from VirgilCrypto.
    ///           VirgilCryptoError.passedKeyIsNotVirgil if passed key is of wrong type
    public func generateTokenSignature(of token: Data, using privateKey: PrivateKey) throws -> Data {
        guard let privateKey = privateKey as? VirgilPrivateKey else {
            throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        return try self.virgilCrypto.generateSignature(of: token, using: privateKey)
    }

    /// Verifies token's signature.
    ///
    /// - Parameters:
    ///   - signature: Digital signature
    ///   - token: Token data
    ///   - publicKey: Signer's public key
    /// - Returns: true if verified, false otherwise
    public func verifyTokenSignature(_ signature: Data, of token: Data, with publicKey: PublicKey) -> Bool {
        guard let publicKey = publicKey as? VirgilPublicKey else {
            return false
        }

        return self.virgilCrypto.verifySignature(signature, of: token, with: publicKey)
    }

    /// Returns algorithm used for signing
    ///
    /// - Returns: algorithm string. Currently VEDS512
    public func getAlgorithm() -> String {
        return "VEDS512"
    }
}
