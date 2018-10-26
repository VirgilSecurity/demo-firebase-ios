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
import VirgilSDK

/// Class responsible for storing Keys in Cloud using E2EE
@objc(VSKCloudKeyStorage) open class CloudKeyStorage: NSObject {
    /// KeyknoxManager
    @objc public let keyknoxManager: KeyknoxManager

    private var cache: [String: CloudEntry] = [:]
    private var decryptedKeyknoxData: DecryptedKeyknoxValue?
    private let cloudEntrySerializer = CloudEntrySerializer()

    /// Shows whether this storage was synced
    @objc public var storageWasSynced: Bool { return self.decryptedKeyknoxData != nil }

    private let queue = DispatchQueue(label: "CloudKeyStorageQueue")

    /// Init
    ///
    /// - Parameter keyknoxManager: KeyknoxManager
    @objc public init(keyknoxManager: KeyknoxManager) {
        self.keyknoxManager = keyknoxManager

        super.init()
    }

    /// Init
    ///
    /// - Parameters:
    ///   - accessTokenProvider: AccessTokenProvider implementation
    ///   - publicKeys: Public keys used for encryption and signature verification
    ///   - privateKey: Private key used for decryption and signature verification
    /// - Throws: Rethrows from KeyknoxManager
    @objc convenience public init(accessTokenProvider: AccessTokenProvider,
                                  publicKeys: [PublicKey], privateKey: PrivateKey) throws {
        let keyknoxManager = try KeyknoxManager(accessTokenProvider: accessTokenProvider,
                                                publicKeys: publicKeys, privateKey: privateKey)

        self.init(keyknoxManager: keyknoxManager)
    }
}

extension CloudKeyStorage: CloudKeyStorageProtocol {
    private func storeEntriesSync(_ keyEntries: [KeyEntry]) throws -> [CloudEntry] {
        guard self.storageWasSynced else {
            throw CloudKeyStorageError.cloudStorageOutOfSync
        }

        for entry in keyEntries {
            guard self.cache[entry.name] == nil else {
                throw CloudKeyStorageError.entryAlreadyExists
            }
        }

        var cloudEntries = [CloudEntry]()
        for entry in keyEntries {
            let now = Date()
            let cloudEntry = CloudEntry(name: entry.name, data: entry.data,
                                        creationDate: now, modificationDate: now, meta: entry.meta)

            cloudEntries.append(cloudEntry)
            self.cache[entry.name] = cloudEntry
        }

        let data = try self.cloudEntrySerializer.serialize(dict: self.cache)

        let response = try self.keyknoxManager.pushValue(data, previousHash: self.decryptedKeyknoxData?.keyknoxHash)
            .startSync().getResult()

        self.cache = try self.cloudEntrySerializer.deserialize(data: response.value)
        self.decryptedKeyknoxData = response

        return cloudEntries
    }

    /// Stores entries to cloud
    ///
    /// - Parameter keyEntries: Entries to store
    /// - Returns: GenericOperation<[CloudEntry]>
    open func storeEntries(_ keyEntries: [KeyEntry]) -> GenericOperation<[CloudEntry]> {
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

    /// Stores entry to cloud
    ///
    /// - Parameters:
    ///   - name: Name
    ///   - data: Data
    ///   - meta: Meta
    /// - Returns: GenericOperation<CloudEntry>
    open func storeEntry(withName name: String, data: Data,
                         meta: [String: String]? = nil) -> GenericOperation<CloudEntry> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let cloudEntries = try self.storeEntriesSync([KeyEntry(name: name, data: data, meta: meta)])
                    guard cloudEntries.count == 1, let cloudEntry = cloudEntries.first else {
                        throw CloudKeyStorageError.entrySavingError
                    }

                    completion(cloudEntry, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Updates entry in Cloud
    ///
    /// - Parameters:
    ///   - name: Name
    ///   - data: New data
    ///   - meta: New meta
    /// - Returns: GenericOperation<CloudEntry>
    open func updateEntry(withName name: String, data: Data,
                          meta: [String: String]? = nil) -> GenericOperation<CloudEntry> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    guard self.storageWasSynced else {
                        throw CloudKeyStorageError.cloudStorageOutOfSync
                    }

                    let now = Date()
                    let creationDate = self.cache[name]?.creationDate ?? now

                    let cloudEntry = CloudEntry(name: name, data: data,
                                                creationDate: creationDate, modificationDate: now, meta: meta)

                    self.cache[name] = cloudEntry

                    let data = try self.cloudEntrySerializer.serialize(dict: self.cache)

                    let response = try self.keyknoxManager
                        .pushValue(data, previousHash: self.decryptedKeyknoxData?.keyknoxHash)
                        .startSync().getResult()

                    self.cache = try self.cloudEntrySerializer.deserialize(data: response.value)
                    self.decryptedKeyknoxData = response

                    completion(cloudEntry, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Retrieves entry loaded from Cloud
    ///
    /// - Parameter name: Name
    /// - Returns: Entry
    /// - Throws: CloudKeyStorageError.cloudStorageOutOfSync
    @objc open func retrieveEntry(withName name: String) throws -> CloudEntry {
        guard self.storageWasSynced else {
            throw CloudKeyStorageError.cloudStorageOutOfSync
        }

        guard let entry = self.cache[name] else {
            throw CloudKeyStorageError.entryNotFound
        }

        return entry
    }

    /// Returns all entries loaded from Cloud
    ///
    /// - Returns: All entries
    /// - Throws: CloudKeyStorageError.cloudStorageOutOfSync if storage was not synced
    @objc open func retrieveAllEntries() throws -> [CloudEntry] {
        guard self.storageWasSynced else {
            throw CloudKeyStorageError.cloudStorageOutOfSync
        }

        return [CloudEntry](self.cache.values)
    }

    /// Checks if entry exists in list of loaded from Cloud entries
    ///
    /// - Parameter name: Entry name
    /// - Returns: true if entry exists, false - otherwise
    /// - Throws: CloudKeyStorageError.cloudStorageOutOfSync if storage was not synced
    open func existsEntry(withName name: String) throws -> Bool {
        guard self.storageWasSynced else {
            throw CloudKeyStorageError.cloudStorageOutOfSync
        }

        return self.cache[name] != nil
    }

    /// Deletes entry from Cloud
    ///
    /// - Parameter name: Entry name
    /// - Returns: GenericOperation<Void>
    open func deleteEntry(withName name: String) -> GenericOperation<Void> {
        return self.deleteEntries(withNames: [name])
    }

    /// Deletes entries from Cloud
    ///
    /// - Parameter names: Names of entries to delete
    /// - Returns: GenericOperation<Void>
    open func deleteEntries(withNames names: [String]) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    guard self.storageWasSynced else {
                        throw CloudKeyStorageError.cloudStorageOutOfSync
                    }

                    for name in names {
                        guard self.cache[name] != nil else {
                            throw CloudKeyStorageError.entryNotFound
                        }
                    }

                    for name in names {
                        self.cache.removeValue(forKey: name)
                    }

                    let data = try self.cloudEntrySerializer.serialize(dict: self.cache)

                    let response = try self.keyknoxManager
                        .pushValue(data, previousHash: self.decryptedKeyknoxData?.keyknoxHash)
                        .startSync().getResult()

                    self.cache = try self.cloudEntrySerializer.deserialize(data: response.value)
                    self.decryptedKeyknoxData = response

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Deletes all entries from Cloud
    ///
    /// - Returns: GenericOperation<Void>
    open func deleteAllEntries() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let response = try self.keyknoxManager
                        .resetValue().startSync().getResult()

                    self.cache = try self.cloudEntrySerializer.deserialize(data: response.value)
                    self.decryptedKeyknoxData = response

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
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
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    guard let decryptedKeyknoxData = self.decryptedKeyknoxData else {
                        throw CloudKeyStorageError.cloudStorageOutOfSync
                    }

                    // Cloud is empty, no need to update anything
                    guard !decryptedKeyknoxData.value.isEmpty || !decryptedKeyknoxData.meta.isEmpty else {
                        completion((), nil)
                        return
                    }

                    let response = try self.keyknoxManager
                        .updateRecipients(value: decryptedKeyknoxData.value,
                                          previousHash: decryptedKeyknoxData.keyknoxHash,
                                          newPublicKeys: newPublicKeys, newPrivateKey: newPrivateKey)
                        .startSync().getResult()

                    self.cache = try self.cloudEntrySerializer.deserialize(data: response.value)
                    self.decryptedKeyknoxData = response

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Retrieves entries from Cloud
    ///
    /// - Returns: GenericOperation<Void>
    open func retrieveCloudEntries() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let response = try self.keyknoxManager.pullValue().startSync().getResult()

                    self.cache = try self.cloudEntrySerializer.deserialize(data: response.value)
                    self.decryptedKeyknoxData = response

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }
}
