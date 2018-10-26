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

/// Class responsible for synchronization between Keychain and Keyknox Cloud
@objc(VSKSyncKeyStorage) open class SyncKeyStorage: NSObject {
    /// User's identity to separate keys in Keychain
    @objc public let identity: String

    /// CloudKeyStorageProtocol implementation
    public let cloudKeyStorage: CloudKeyStorageProtocol

    internal let keychainStorage: KeychainStorageProtocol
    internal let keychainUtils: KeychainUtils

    private let queue = DispatchQueue(label: "SyncKeyStorageQueue")

    /// Init
    ///
    /// - Parameters:
    ///   - identity: User's identity to separate keys in Keychain
    ///   - keychainStorage: KeychainStorageProtocol implementation
    ///   - cloudKeyStorage: CloudKeyStorageProtocol implementation
    public init(identity: String, keychainStorage: KeychainStorageProtocol,
                cloudKeyStorage: CloudKeyStorageProtocol) {
        self.identity = identity
        self.keychainStorage = KeychainStorageWrapper(identity: identity, keychainStorage: keychainStorage)
        self.cloudKeyStorage = cloudKeyStorage
        self.keychainUtils = KeychainUtils()

        super.init()
    }

    /// Init
    ///
    /// - Parameters:
    ///   - identity: User's identity to separate keys in Keychain
    ///   - cloudKeyStorage: CloudKeyStorageProtocol implementation
    /// - Throws: Rethrows from KeychainStorageParams
    @objc public convenience init(identity: String, cloudKeyStorage: CloudKeyStorage) throws {
        let configuration = try KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: configuration)

        self.init(identity: identity, keychainStorage: keychainStorage, cloudKeyStorage: cloudKeyStorage)
    }

    /// Init
    ///
    /// - Parameters:
    ///   - identity: User's identity to separate keys in Keychain
    ///   - accessTokenProvider: AccessTokenProvider implementation
    ///   - publicKeys: Public keys used for encryption and signature verification
    ///   - privateKey: Private key used for decryption and signature generation
    /// - Throws: Rethrows from CloudKeyStorage and KeychainStorageParams
    @objc convenience public init(identity: String, accessTokenProvider: AccessTokenProvider,
                                  publicKeys: [PublicKey], privateKey: PrivateKey) throws {
        let cloudKeyStorage = try CloudKeyStorage(accessTokenProvider: accessTokenProvider,
                                                  publicKeys: publicKeys, privateKey: privateKey)

        try self.init(identity: identity, cloudKeyStorage: cloudKeyStorage)
    }
}

// MARK: - Extension with Queries
extension SyncKeyStorage {
    /// Updates entry in Keyknox Cloud and Keychain
    ///
    /// - Parameters:
    ///   - name: Name
    ///   - data: New data
    ///   - meta: New meta
    /// - Returns: GenericOperation<Void>
    open func updateEntry(withName name: String, data: Data, meta: [String: String]?) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    guard try self.keychainStorage.existsEntry(withName: name) else {
                        throw SyncKeyStorageError.keychainEntryNotFoundWhileUpdating
                    }

                    do {
                        _ = try self.cloudKeyStorage.existsEntry(withName: name)
                    }
                    catch {
                        throw SyncKeyStorageError.cloudEntryNotFoundWhileUpdating
                    }

                    let cloudEntry = try self.cloudKeyStorage.updateEntry(withName: name, data: data,
                                                                          meta: meta).startSync().getResult()
                    let meta = try self.keychainUtils.createMetaForKeychain(from: cloudEntry)
                    try self.keychainStorage.updateEntry(withName: name, data: data, meta: meta)

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Retrieves entry from Keychain
    ///
    /// - Parameter name: Name
    /// - Returns: KeychainEntry
    /// - Throws: Rethrows from KeychainStorage
    @objc open func retrieveEntry(withName name: String) throws -> KeychainEntry {
        return try self.keychainStorage.retrieveEntry(withName: name)
    }

    /// Deletes entries from both Keychain and Keyknox Cloud
    ///
    /// - Parameter names: Names to delete
    /// - Returns: GenericOperation<Void>
    open func deleteEntries(withNames names: [String]) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    for name in names {
                        guard try self.cloudKeyStorage.existsEntry(withName: name) else {
                            throw SyncKeyStorageError.cloudEntryNotFoundWhileDeleting
                        }
                    }

                    _ = try self.cloudKeyStorage.deleteEntries(withNames: names).startSync().getResult()

                    for name in names {
                        _ = try self.keychainStorage.deleteEntry(withName: name)
                    }

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Deletes entry from both Keychain and Keyknox Cloud
    ///
    /// - Parameter name: Name
    /// - Returns: GenericOperation<Void>
    open func deleteEntry(withName name: String) -> GenericOperation<Void> {
        return self.deleteEntries(withNames: [name])
    }

    /// Stores entry in both Keychain and Keyknox Cloud
    ///
    /// - Parameters:
    ///   - name: Name
    ///   - data: Data
    ///   - meta: Meta
    /// - Returns: GenericOperation<KeychainEntry>
    open func storeEntry(withName name: String, data: Data,
                         meta: [String: String]? = nil) -> GenericOperation<KeychainEntry> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let keychainEntries = try self.storeEntriesSync([KeyEntry(name: name, data: data, meta: meta)])
                    guard keychainEntries.count == 1, let keychainEntry = keychainEntries.first else {
                        throw SyncKeyStorageError.entrySavingError
                    }

                    completion(keychainEntry, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Stores entries in both Keychain and Keyknox Cloud
    ///
    /// - Parameter keyEntries: Key entries to store
    /// - Returns: GenericOperation<[KeychainEntry]>
    open func storeEntries(_ keyEntries: [KeyEntry]) -> GenericOperation<[KeychainEntry]> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    completion(try self.storeEntriesSync(keyEntries), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    private func storeEntriesSync(_ keyEntries: [KeyEntry]) throws -> [KeychainEntry] {
        for keyEntry in keyEntries {
            guard !(try self.keychainStorage.existsEntry(withName: keyEntry.name)) else {
                throw SyncKeyStorageError.keychainEntryAlreadyExistsWhileStoring
            }

            guard !(try self.cloudKeyStorage.existsEntry(withName: keyEntry.name)) else {
                throw SyncKeyStorageError.cloudEntryAlreadyExistsWhileStoring
            }
        }

        let cloudEntries = try self.cloudKeyStorage.storeEntries(keyEntries).startSync().getResult()

        var keychainEntries = [KeychainEntry]()

        for entry in zip(keyEntries, cloudEntries) {
            guard entry.0.name == entry.1.name else {
                throw SyncKeyStorageError.inconsistentStateError
            }

            let meta = try self.keychainUtils.createMetaForKeychain(from: entry.1)
            let keychainEntry = try self.keychainStorage.store(data: entry.0.data,
                                                               withName: entry.0.name,
                                                               meta: meta)

            keychainEntries.append(keychainEntry)
        }

        return keychainEntries
    }

    /// Performs synchronization between Keychain and Keyknox Cloud
    ///
    /// - Returns: GenericOperation<Void>
    open func sync() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                let retrieveCloudEntriesOperation = self.cloudKeyStorage.retrieveCloudEntries()
                let retrieveKeychainEntriesOperation = CallbackOperation<[KeychainEntry]> { _, completion in
                    do {
                        let keychainEntries = try self.keychainStorage.retrieveAllEntries()
                            .compactMap(self.keychainUtils.filterKeyknoxKeychainEntry)

                        completion(keychainEntries, nil)
                    }
                    catch {
                        completion(nil, error)
                    }
                }

                let syncOperation = CallbackOperation<Void> { operation, completion in
                    do {
                        let keychainEntries: [KeychainEntry] = try operation.findDependencyResult()

                        let keychainSet = Set<String>(keychainEntries.map { $0.name })
                        let cloudSet = Set<String>(try self.cloudKeyStorage.retrieveAllEntries().map { $0.name })

                        let entriesToDelete = [String](keychainSet.subtracting(cloudSet))
                        let entriesToStore = [String](cloudSet.subtracting(keychainSet))
                        let entriesToCompare = [String](keychainSet.intersection(cloudSet))

                        try self.syncDeleteEntries(entriesToDelete)
                        try self.syncStoreEntries(entriesToStore)
                        try self.syncCompareEntries(entriesToCompare, keychainEntries: keychainEntries)

                        completion((), nil)
                    }
                    catch {
                        completion(nil, error)
                    }
                }

                syncOperation.addDependency(retrieveCloudEntriesOperation)
                syncOperation.addDependency(retrieveKeychainEntriesOperation)

                let operations = [retrieveCloudEntriesOperation, retrieveKeychainEntriesOperation,
                                  syncOperation]
                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                operations.forEach {
                    completionOperation.addDependency($0)
                }

                let queue = OperationQueue()
                queue.addOperations(operations + [completionOperation], waitUntilFinished: true)
            }
        }
    }

    /// Updates recipients. See KeyknoxManager.updateRecipients
    ///
    /// - Parameters:
    ///   - newPublicKeys: New public keys
    ///   - newPrivateKey: New private key
    /// - Returns: GenericOperation<Void>
    open func updateRecipients(newPublicKeys: [PublicKey]? = nil,
                               newPrivateKey: PrivateKey? = nil) -> GenericOperation<Void> {
        return self.cloudKeyStorage.updateRecipients(newPublicKeys: newPublicKeys,
                                                     newPrivateKey: newPrivateKey)
    }

    /// Retrieves all entries from Keychain
    ///
    /// - Returns: Keychain entries
    /// - Throws: Rethrows from KeychainStorage
    open func retrieveAllEntries() throws -> [KeychainEntry] {
        return try self.keychainStorage.retrieveAllEntries().compactMap(self.keychainUtils.filterKeyknoxKeychainEntry)
    }

    /// Checks if entry exists in Keychain
    ///
    /// - Parameter name: Entry name
    /// - Returns: true if entry exists, false - otherwise
    /// - Throws: Rethrows from KeychainStorage
    open func existsEntry(withName name: String) throws -> Bool {
        return try self.keychainStorage.existsEntry(withName: name)
    }

    /// Deletes all entries in both Keychain and Keyknox Cloud
    ///
    /// - Returns: GenericOperation<Void>
    open func deleteAllEntries() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    _ = try self.cloudKeyStorage.deleteAllEntries().startSync().getResult()

                    let entriesToDelete = try self.keychainStorage.retrieveAllEntries()
                        .compactMap(self.keychainUtils.filterKeyknoxKeychainEntry)
                        .map { $0.name }

                    try self.syncDeleteEntries(entriesToDelete)

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }
}
