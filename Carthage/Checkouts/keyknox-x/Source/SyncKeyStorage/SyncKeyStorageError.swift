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

/// Declares error types and codes for SyncKeyStorage
///
/// - keychainEntryNotFoundWhileUpdating: KeychainEntry not found while updating
/// - cloudEntryNotFoundWhileUpdating: CloudEntry not found while updating
/// - cloudEntryNotFoundWhileDeleting: CloudEntry notfound while deleting
/// - keychainEntryNotFoundWhileComparing: KeychainEntry not found while comparing
/// - keychainEntryAlreadyExistsWhileStoring: KeychainEntry already exists while storing
/// - cloudEntryAlreadyExistsWhileStoring: CloudEntry already exists while storing
/// - invalidModificationDateInKeychainEntry: Invalid modificationDate in KeychainEntry
/// - invalidCreationDateInKeychainEntry: Invalid creationDate in KeychainEntry
/// - noMetaInKeychainEntry: No meta in keychainEntry
/// - invalidKeysInEntryMeta: Invalid keys in entry meta
/// - inconsistentStateError: Inconsistent state error
/// - entrySavingError: Error while saving entry
@objc(VSKSyncKeyStorageError) public enum SyncKeyStorageError: Int, Error {
    case keychainEntryNotFoundWhileUpdating
    case cloudEntryNotFoundWhileUpdating
    case cloudEntryNotFoundWhileDeleting
    case keychainEntryNotFoundWhileComparing
    case keychainEntryAlreadyExistsWhileStoring
    case cloudEntryAlreadyExistsWhileStoring
    case invalidModificationDateInKeychainEntry
    case invalidCreationDateInKeychainEntry
    case noMetaInKeychainEntry
    case invalidKeysInEntryMeta
    case inconsistentStateError
    case entrySavingError
}
