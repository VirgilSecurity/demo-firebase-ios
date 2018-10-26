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

/// Class representing Keychain entry
@objc(VSSKeychainEntry) public final class KeychainEntry: NSObject {
    /// Sensitive data
    @objc public let data: Data

    /// Alias
    @objc public let name: String

    /// Additional meta info
    @objc public let meta: [String: String]?

    /// Entry creation date (obtained from Keychain)
    @objc public let creationDate: Date

    /// Entry modification date (obtained from Keychain)
    @objc public let modificationDate: Date

    /// Init
    ///
    /// - Parameters:
    ///   - data: Sensitive data
    ///   - name: Alias
    ///   - meta: Additional meta
    ///   - creationDate: Creation date
    ///   - modificationDate: Modification date
    @objc public init(data: Data, name: String, meta: [String: String]?, creationDate: Date, modificationDate: Date) {
        self.data = data
        self.name = name
        self.meta = meta
        self.creationDate = creationDate
        self.modificationDate = modificationDate

        super.init()
    }
}

// MARK: - Equality override
public extension KeychainEntry {
    /// Equality operator
    ///
    /// - Parameters:
    ///   - lhs: left argument
    ///   - rhs: right argument
    /// - Returns: true if left and right arguments are equal, false otherwiseKeychainStorageErrorCodes
    static func == (lhs: KeychainEntry, rhs: KeychainEntry) -> Bool {
        return lhs.data == rhs.data
            && lhs.name == rhs.name
            && lhs.meta == rhs.meta
            && lhs.creationDate == rhs.creationDate
            && lhs.modificationDate == rhs.modificationDate
    }
}
