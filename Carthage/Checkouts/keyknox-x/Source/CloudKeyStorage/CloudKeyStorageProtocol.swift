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
import VirgilCryptoAPI

/// Cloud KeyStorage protocol
public protocol CloudKeyStorageProtocol {
    /// Store entries to cloud
    ///
    /// - Parameter keyEntries: Entries to store
    /// - Returns: GenericOperation<[CloudEntry]>
    func storeEntries(_ keyEntries: [KeyEntry]) -> GenericOperation<[CloudEntry]>

    /// Store entry to cloud
    ///
    /// - Parameters:
    ///   - name: name
    ///   - data: data
    ///   - meta: meta
    /// - Returns: GenericOperation<CloudEntry>
    func storeEntry(withName name: String, data: Data, meta: [String: String]?) -> GenericOperation<CloudEntry>

    /// Update entry in Cloud
    ///
    /// - Parameters:
    ///   - name: name
    ///   - data: data
    ///   - meta: meta
    /// - Returns: GenericOperation<CloudEntry>
    func updateEntry(withName name: String, data: Data, meta: [String: String]?) -> GenericOperation<CloudEntry>

    /// Returns all entries loaded from Cloud
    ///
    /// - Returns: All entries
    /// - Throws: Depends on implementation
    func retrieveAllEntries() throws -> [CloudEntry]

    /// Retrieve entry loaded from Cloud
    ///
    /// - Parameter name: name
    /// - Returns: Entry
    /// - Throws: Depends on implementation
    func retrieveEntry(withName name: String) throws -> CloudEntry

    /// Check if entry exists in list of loaded from Cloud entries
    ///
    /// - Parameter name: entry name
    /// - Returns: true if entry exists, false - otherwise
    /// - Throws: Depends on implementation
    func existsEntry(withName name: String) throws -> Bool

    /// Deletes entry from Cloud
    ///
    /// - Parameter name: entry name
    /// - Returns: GenericOperation<Void>
    func deleteEntry(withName name: String) -> GenericOperation<Void>

    /// Deletes entries from Cloud
    ///
    /// - Parameter names: names of entries to delete
    /// - Returns: GenericOperation<Void>
    func deleteEntries(withNames names: [String]) -> GenericOperation<Void>

    /// Deletes all entries from Cloud
    ///
    /// - Returns: GenericOperation<Void>
    func deleteAllEntries() -> GenericOperation<Void>

    /// Retrieves entries from Cloud
    ///
    /// - Returns: GenericOperation<Void>
    func retrieveCloudEntries() -> GenericOperation<Void>

    /// Updated recipients. See KeyknoxManager.updateRecipients
    ///
    /// - Parameters:
    ///   - newPublicKeys: New public keys
    ///   - newPrivateKey: New private key
    /// - Returns: GenericOperation<Void>
    func updateRecipients(newPublicKeys: [PublicKey]?, newPrivateKey: PrivateKey?) -> GenericOperation<Void>
}
