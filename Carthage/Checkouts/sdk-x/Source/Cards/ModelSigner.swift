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

/// Class responsible for signing RawSignerModel
@objc(VSSModelSigner) public final class ModelSigner: NSObject {
    /// Signer identifier for self signatures
    @objc public static let selfSignerIdentifier = "self"
    /// CardCrypto implementation instance for generating signatures
    @objc public let cardCrypto: CardCrypto

    /// Initializer
    ///
    /// - Parameter cardCrypto: CardCrypto implementation instance for generating signatures
    @objc public init(cardCrypto: CardCrypto) {
        self.cardCrypto = cardCrypto

        super.init()
    }

    /// Adds signature to given RawSignedModel with provided signer, privateKey and additionalData
    ///
    /// - Parameters:
    ///   - model: RawSignedModel to sign
    ///   - signer: identifier of signer
    ///   - privateKey: PrivateKey to sign with
    ///   - additionalData: additionalData to sign with model
    /// - Throws: corresponding error id signature generation fails
    @objc public func sign(model: RawSignedModel, signer: String, privateKey: PrivateKey,
                           additionalData: Data?) throws {
        let combinedSnapshot = model.contentSnapshot + (additionalData ?? Data())
        let signature = try cardCrypto.generateSignature(of: combinedSnapshot, using: privateKey)

        let rawSignature = RawSignature(signer: signer, signature: signature,
                                        snapshot: additionalData)

        try model.addSignature(rawSignature)
    }

    /// Adds owner's signature to given RawSignedModel using provided PrivateKey
    ///
    /// - Parameters:
    ///   - model: RawSignedModel to sign
    ///   - privateKey: PrivateKey to sign with
    ///   - additionalData: additionalData to sign with model
    /// - Throws: corresponding error id signature generation fails
    @objc public func selfSign(model: RawSignedModel, privateKey: PrivateKey, additionalData: Data?) throws {
        try self.sign(model: model, signer: ModelSigner.selfSignerIdentifier,
                      privateKey: privateKey, additionalData: additionalData)
    }

    /// Adds signature to given RawSignedModel with provided signer, privateKey and additionalData
    ///
    /// - Parameters:
    ///   - model: RawSignedModel to sign
    ///   - signer: identifier of signer
    ///   - privateKey: PrivateKey to sign with
    ///   - extraFields: Dictionary with extra data to sign with model
    /// - Throws: corresponding error id signature generation fails
    @objc public func sign(model: RawSignedModel, signer: String, privateKey: PrivateKey,
                           extraFields: [String: String]? = nil) throws {
        let additionalData: Data?
        if let extraFields = extraFields {
            additionalData = try JSONSerialization.data(withJSONObject: extraFields, options: [])
        }
        else {
            additionalData = nil
        }

        try self.sign(model: model, signer: signer, privateKey: privateKey, additionalData: additionalData)
    }

    /// Adds owner's signature to given RawSignedModel using provided PrivateKey
    ///
    /// - Parameters:
    ///   - model: RawSignedModel to sign
    ///   - privateKey: PrivateKey to sign with
    ///   - extraFields: Dictionary with extra data to sign with model
    /// - Throws: corresponding error id signature generation fails
    @objc public func selfSign(model: RawSignedModel, privateKey: PrivateKey,
                               extraFields: [String: String]? = nil) throws {
        try self.sign(model: model, signer: ModelSigner.selfSignerIdentifier,
                      privateKey: privateKey, extraFields: extraFields)
    }
}
