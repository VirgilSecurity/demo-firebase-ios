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
import VirgilSDK

internal final class KeychainUtils {
    internal static let keyknoxMetaCreationDateKey = "k_cda"
    internal static let keyknoxMetaModificationDateKey = "k_mda"

    internal func extractModificationDate(fromKeychainEntry keychainEntry: KeychainEntry) throws
        -> (creationDate: Date, modificationDate: Date) {
            guard let meta = keychainEntry.meta else {
                throw SyncKeyStorageError.noMetaInKeychainEntry
            }

            guard let modificationTimestampStr = meta[KeychainUtils.keyknoxMetaModificationDateKey],
                let modificationTimestamp = Int64(modificationTimestampStr) else {
                    throw SyncKeyStorageError.invalidModificationDateInKeychainEntry
            }
            guard let creationTimestampStr = meta[KeychainUtils.keyknoxMetaCreationDateKey],
                let creationTimestamp = Int64(creationTimestampStr) else {
                    throw SyncKeyStorageError.invalidCreationDateInKeychainEntry
            }

            return (DateUtils.dateFromMilliTimestamp(creationTimestamp),
                    DateUtils.dateFromMilliTimestamp(modificationTimestamp))
    }

    internal func filterKeyknoxKeychainEntry(_ keychainEntry: KeychainEntry) -> KeychainEntry? {
        do {
            _ = try self.extractModificationDate(fromKeychainEntry: keychainEntry)

            return keychainEntry
        }
        catch {
            return nil
        }
    }

    internal func createMetaForKeychain(from cloudEntry: CloudEntry) throws -> [String: String] {
        var additionalDict = [
            KeychainUtils.keyknoxMetaCreationDateKey:
                "\(DateUtils.dateToMilliTimestamp(date: cloudEntry.creationDate))",
            KeychainUtils.keyknoxMetaModificationDateKey:
                "\(DateUtils.dateToMilliTimestamp(date: cloudEntry.modificationDate))"
        ]

        if let meta = cloudEntry.meta {
            try additionalDict.merge(meta, uniquingKeysWith: { _, _ in
                throw SyncKeyStorageError.invalidKeysInEntryMeta
            })
        }

        return additionalDict
    }
}
