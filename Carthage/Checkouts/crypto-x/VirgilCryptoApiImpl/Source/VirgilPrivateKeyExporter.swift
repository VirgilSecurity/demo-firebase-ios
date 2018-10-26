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

/// Adapter for PrivateKeyExporter protocol using VirgilCrypto
@objc(VSMVirgilPrivateKeyExporter) open class VirgilPrivateKeyExporter: NSObject {
    /// VirgilCrypto instance
    @objc public let virgilCrypto: VirgilCrypto
    /// Password used to encrypt private key. Do NOT use nil, unless your storage/transport channel is secured
    @objc public let password: String?

    /// Initializer
    ///
    /// - Parameters:
    ///   - virgilCrypto: VirgilCrypto instance
    ///   - password: Password used to encrypt private key.
    ///               NOTE: Do NOT use nil, unless your storage/transport channel is secured
    @objc public init(virgilCrypto: VirgilCrypto = VirgilCrypto(), password: String? = nil) {
        self.virgilCrypto = virgilCrypto
        self.password = password

        super.init()
    }
}

// MARK: - Implementation of PrivateKeyExporter protocol
extension VirgilPrivateKeyExporter: PrivateKeyExporter {
    /// Exports private key to DER format
    ///
    /// - Parameters:
    ///   - privateKey: Private key to be exported
    /// - Returns: Exported private key in DER format
    /// - Throws: Rethrows from VirgilCrypto.
    ///           VirgilCryptoError.passedKeyIsNotVirgil if passed key is of wrong type
    @objc open func exportPrivateKey(privateKey: PrivateKey) throws -> Data {
        guard let privateKey = privateKey as? VirgilPrivateKey else {
            throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        if let password = self.password {
            return try self.virgilCrypto.exportPrivateKey(privateKey, password: password)
        }
        else {
            return self.virgilCrypto.exportPrivateKey(privateKey)
        }
    }

    /// Imports Private Key from DER or PEM format
    ///
    /// - Parameter data: Private key in DER or PEM format
    /// - Returns: Imported private key
    /// - Throws: Rethrows from VirgilCrypto
    @objc open func importPrivateKey(from data: Data) throws -> PrivateKey {
        return try self.virgilCrypto.importPrivateKey(from: data)
    }
}
