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

/// Represents content of Virgil Card
@objc(VSSRawCardContent) public final class RawCardContent: NSObject, Codable {
    /// Card identity
    @objc public let identity: String
    /// PublicKey data
    @objc public let publicKey: Data
    /// Identifier of outdated previous Virgil Card with same identity.
    @objc public let previousCardId: String?
    /// Version of Virgil Card
    @objc public let version: String
    /// UTC timestamp of creation date
    @objc public let createdAt: Int64

    /// Defines coding keys for encoding and decoding
    private enum CodingKeys: String, CodingKey {
        case publicKey = "public_key"
        case previousCardId = "previous_card_id"
        case createdAt = "created_at"
        case identity = "identity"
        case version = "version"
    }

    /// Initializes a new `RawCardContent` with the provided content
    ///
    /// - Parameters:
    ///   - identity: Card identity
    ///   - publicKey: PublicKey data
    ///   - previousCardId: Identifier of previous Virgil Card with same identity
    ///   - version: Virgil Card version
    ///   - createdAt: Date of creation
    @objc public convenience init(identity: String, publicKey: Data, previousCardId: String? = nil,
                                  version: String = "5.0", createdAt: Date) {
        self.init(identity: identity, publicKey: publicKey, previousCardId: previousCardId,
                  version: version, createdAtTimestamp: DateUtils.dateToTimestamp(date: createdAt))
    }

    /// Initializes a new `RawCardContent` with the provided content
    ///
    /// - Parameters:
    ///   - identity: Card identity
    ///   - publicKey: PublicKey data
    ///   - previousCardId: Identifier of previous Virgil Card with same identity
    ///   - version: Virgil Card version
    ///   - createdAtTimestamp: Timestamp of creation
    @objc public init(identity: String, publicKey: Data, previousCardId: String? = nil,
                      version: String = "5.0", createdAtTimestamp: Int64) {
        self.identity = identity
        self.publicKey = publicKey
        self.previousCardId = previousCardId
        self.version = version
        self.createdAt = createdAtTimestamp

        super.init()
    }

    /// Initializes `RawCardContent` from binary content snapshot
    ///
    /// - Parameter snapshot: Binary snapshot of `RawCardContent`
    /// - Throws: Rethrows from JSONDecoder
    @objc public convenience init(snapshot: Data) throws {
        let content = try JSONDecoder().decode(RawCardContent.self, from: snapshot)

        self.init(identity: content.identity, publicKey: content.publicKey,
                  previousCardId: content.previousCardId, version: content.version,
                  createdAtTimestamp: content.createdAt)
    }

    /// Takes binary snapshot of `RawCardContent`
    ///
    /// - Returns: Binary snapshot of `RawCardContent`
    /// - Throws: Rethrows from JSONEncoder
    @objc public func snapshot() throws -> Data {
        return try JSONEncoder().encode(self)
    }
}
