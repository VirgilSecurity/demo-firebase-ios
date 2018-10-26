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
import VirgilCrypto

// MARK: - Extension for key generation
extension VirgilCrypto {
    /// Generates mutiple key pairs of default key type.
    /// Performance-optimized for generating more than 1 key
    ///
    /// - Parameter numberOfKeyPairs: Number of keys needed
    /// - Returns: Array of generated keys
    /// - Throws: Rethrows from KeyPair
    @objc open func generateMultipleKeyPairs(numberOfKeyPairs: UInt) throws -> [VirgilKeyPair] {
        return try KeyPair
            .generateMultipleKeys(numberOfKeyPairs, keyPairType: self.defaultKeyType)
            .map({ try self.wrapKeyPair(keyPair: $0) })
    }

    /// Generates KeyPair of default key type
    ///
    /// NOTE: If you need more than 1 keypair, consider using generateMultipleKeyPairs
    ///
    /// - Returns: Generated KeyPair
    /// - Throws: Rethrows from KeyPair
    @objc open func generateKeyPair() throws -> VirgilKeyPair {
        return try self.generateKeyPair(ofType: self.defaultKeyType)
    }

    /// Generates KeyPair of given type
    ///
    /// NOTE: If you need more than 1 keypair, consider using generateMultipleKeyPairs
    ///
    /// - Parameter type: KeyPair type
    /// - Returns: Generated KeyPair
    /// - Throws: Rethrows from KeyPair
    @objc open func generateKeyPair(ofType type: VSCKeyType) throws -> VirgilKeyPair {
        let keyPair = KeyPair(keyPairType: type, password: nil)

        return try self.wrapKeyPair(keyPair: keyPair)
    }

    /// Wraps binary key pair to VirgilKeyPair instance
    ///
    /// - Parameters:
    ///   - privateKey: Binary private key
    ///   - publicKey: Binary public key
    /// - Returns: VirgilKeyPair instance
    /// - Throws: VirgilCryptoError.publicKeyToDERFailed, VirgilCryptoError.privateKeyToDERFailed
    @objc open func wrapKeyPair(privateKey: Data, publicKey: Data) throws -> VirgilKeyPair {
        guard let publicKeyDER = KeyPair.publicKey(toDER: publicKey) else {
            throw VirgilCryptoError.publicKeyToDERFailed
        }

        guard let privateKeyDER = KeyPair.privateKey(toDER: privateKey) else {
            throw VirgilCryptoError.privateKeyToDERFailed
        }

        let identifier = self.computeKeyIdentifier(publicKeyData: publicKeyDER)

        let privateKey = VirgilPrivateKey(identifier: identifier, rawKey: privateKeyDER)
        let publicKey = VirgilPublicKey(identifier: identifier, rawKey: publicKeyDER)

        return VirgilKeyPair(privateKey: privateKey, publicKey: publicKey)
    }

    private func wrapKeyPair(keyPair: KeyPair) throws -> VirgilKeyPair {
        return try self.wrapKeyPair(privateKey: keyPair.privateKey(), publicKey: keyPair.publicKey())
    }
}
