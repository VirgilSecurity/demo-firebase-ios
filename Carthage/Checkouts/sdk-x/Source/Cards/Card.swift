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

/// Class representing Virgil Card
@objc(VSSCard) public class Card: NSObject {
    /// Identifier of Virgil Card
    /// - Note: Is unique
    @objc public let identifier: String
    /// Virgil Card identity
    @objc public let identity: String
    /// PublicKey of Virgil Card
    @objc public let publicKey: PublicKey
    /// Identifier of outdated previous Virgil Card with same identity
    @objc public let previousCardId: String?
    /// Previous Virgil Card instance
    @objc public var previousCard: Card?
    /// True if Virgil Card is outdated, false otherwise
    @objc public var isOutdated: Bool
    /// Version of Virgil Card
    @objc public let version: String
    /// Creation date of Virgil Card
    @objc public let createdAt: Date
    /// Array with CardSignatures of Virgil Card
    @objc public let signatures: [CardSignature]
    /// Snapshot of corresponding `RawCardContent`
    @objc public let contentSnapshot: Data

    internal init(identifier: String, identity: String, publicKey: PublicKey,
                  isOutdated: Bool = false, version: String, createdAt: Date,
                  signatures: [CardSignature], previousCardId: String? = nil,
                  previousCard: Card? = nil, contentSnapshot: Data) {
        self.identifier = identifier
        self.identity = identity
        self.publicKey = publicKey
        self.previousCardId = previousCardId
        self.previousCard = previousCard
        self.isOutdated = isOutdated
        self.version = version
        self.createdAt = createdAt
        self.signatures = signatures
        self.contentSnapshot = contentSnapshot

        super.init()
    }

    /// Builds RawSignedModel representing Card
    ///
    /// - Returns: RawSignedModel representing Card
    /// - Throws: corresponding error
    @objc public func getRawCard() throws -> RawSignedModel {
        let rawCard = RawSignedModel(contentSnapshot: self.contentSnapshot)

        for cardSignature in self.signatures {
            let signature = RawSignature(signer: cardSignature.signer,
                                         signature: cardSignature.signature,
                                         snapshot: cardSignature.snapshot)

            try rawCard.addSignature(signature)
        }

        return rawCard
    }
}
