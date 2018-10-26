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

/// Adapter for CardCrypto protocol using VirgilCrypto
@objc(VSMVirgilCardCrypto) public class VirgilCardCrypto: NSObject {
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

// MARK: - Implementation of CardCrypto protocol
extension VirgilCardCrypto: CardCrypto {
    /// Generates digital signature of data using specified private key.
    ///
    /// - Parameters:
    ///   - data: Data to be signed
    ///   - privateKey: Signer's private key
    /// - Returns: Digitar signature data
    /// - Throws: Rethrows from VirgilCrypto.
    ///           VirgilCryptoError.passedKeyIsNotVirgil if passed key is of wrong type
    public func generateSignature(of data: Data, using privateKey: PrivateKey) throws -> Data {
        guard let privateKey = privateKey as? VirgilPrivateKey else {
            throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        return try self.virgilCrypto.generateSignature(of: data, using: privateKey)
    }

    /// Verifies digital signature.
    ///
    /// - Parameters:
    ///   - signature: Digital signature data
    ///   - data: Data that was signed
    ///   - publicKey: Signer's public key
    /// - Returns: true if verified, false otherwise
    public func verifySignature(_ signature: Data, of data: Data, with publicKey: PublicKey) -> Bool {
        guard let publicKey = publicKey as? VirgilPublicKey else {
            return false
        }

        return self.virgilCrypto.verifySignature(signature, of: data, with: publicKey)
    }

    /// Computes SHA-512.
    ///
    /// - Parameter data: Data to be hashed
    /// - Returns: Resulting hash value
    /// - Throws: Doesn't throw. throws added to conform to protocol
    public func generateSHA512(for data: Data) throws -> Data {
         return self.virgilCrypto.computeHash(for: data, using: .SHA512)
    }

    /// Imports public key from DER or PEM format
    ///
    /// - Parameter data: Public key data in DER or PEM format
    /// - Returns: Imported public key
    /// - Throws: Rethrows from VirgilCrypto
    public func importPublicKey(from data: Data) throws -> PublicKey {
        return try self.virgilCrypto.importPublicKey(from: data)
    }

    /// Exports public key to DER format
    ///
    /// - Parameter publicKey: Public key to be exported
    /// - Returns: Public key in DER format
    /// - Throws: VirgilCryptoError.passedKeyIsNotVirgil if passed key is of wrong type
    public func exportPublicKey(_ publicKey: PublicKey) throws -> Data {
        guard let publicKey = publicKey as? VirgilPublicKey else {
            throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        return self.virgilCrypto.exportPublicKey(publicKey)
    }
}
