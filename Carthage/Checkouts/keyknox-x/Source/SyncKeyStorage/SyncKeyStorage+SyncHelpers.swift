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

// MARK: Sync helpers
extension SyncKeyStorage {
    internal func syncDeleteEntries(_ entriesToDelete: [String]) throws {
        try entriesToDelete.forEach {
            try self.keychainStorage.deleteEntry(withName: $0)
        }
    }

    internal func syncStoreEntries(_ entriesToStore: [String]) throws {
        try entriesToStore.forEach {
            let cloudEntry = try self.cloudKeyStorage.retrieveEntry(withName: $0)

            let meta = try self.keychainUtils.createMetaForKeychain(from: cloudEntry)

            _ = try self.keychainStorage.store(data: cloudEntry.data, withName: cloudEntry.name, meta: meta)
        }
    }

    internal func syncCompareEntries(_ entriesToCompare: [String], keychainEntries: [KeychainEntry]) throws {
        // Determine newest version and either update keychain entry or upload newer version to cloud
        try entriesToCompare.forEach { name in
            guard let keychainEntry = keychainEntries.first(where: { $0.name == name }) else {
                throw SyncKeyStorageError.keychainEntryNotFoundWhileComparing
            }

            let cloudEntry = try self.cloudKeyStorage.retrieveEntry(withName: name)

            let keychainDate = try self.keychainUtils.extractModificationDate(fromKeychainEntry: keychainEntry)

            if keychainDate.modificationDate < cloudEntry.modificationDate {
                let meta = try self.keychainUtils.createMetaForKeychain(from: cloudEntry)

                try self.keychainStorage.updateEntry(withName: cloudEntry.name, data: cloudEntry.data, meta: meta)
            }
        }
    }
}
