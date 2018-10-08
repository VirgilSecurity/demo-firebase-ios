//
//  VirgilHelper+Keyknox.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 10/4/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import VirgilSDK
import VirgilKeyknox
import VirgilPythia
import VirgilCryptoApiImpl

extension VirgilHelper {
    func publishToKeyknox(key: VirgilPrivateKey, usingPassword password: String, completion: @escaping (Error?) -> ()) {
        self.setUpSyncKeyStorage(password: password) { syncKeyStorage, error in
            guard let syncKeyStorage = syncKeyStorage, error == nil else {
                completion(error)
                return
            }

            do {
                let exportedHistoryKey = try self.privateKeyExporter.exportPrivateKey(privateKey: key)

                syncKeyStorage.storeEntry(withName: self.identity, data: exportedHistoryKey) { _, error in
                    completion(error)
                }
            } catch {
                completion(error)
            }
        }
    }

    func fetchFromKeyknox(usingPassword password: String, identity: String, completion: @escaping (VirgilPrivateKey?, Error?) -> ()) {
        self.setUpSyncKeyStorage(password: password) { syncKeyStorage, error in
            guard let syncKeyStorage = syncKeyStorage, error == nil else {
                completion(nil, error)
                return
            }

            do {
                let entry = try syncKeyStorage.retrieveEntry(withName: identity)
                let key = try self.privateKeyExporter.importPrivateKey(from: entry.data)

                guard let historyKey = key as? VirgilPrivateKey else {
                    throw VirgilHelperError.keyIsNotVirgil
                }

                completion(historyKey, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    func deleteKeyknoxEntry(password: String, completion: @escaping (Error?) -> ()) {
        self.setUpSyncKeyStorage(password: password) { syncKeyStorage, error in
            guard let syncKeyStorage = syncKeyStorage, error == nil else {
                completion(error)
                return
            }

            syncKeyStorage.deleteEntry(withName: self.identity) { error in
                guard error == nil else {
                    completion(error)
                    return
                }
            }
        }
    }

    func changeKeyknoxPassword(from oldPassword: String, to newPassword: String, completion: @escaping (Error?) -> ()) {
        self.setUpSyncKeyStorage(password: oldPassword) { syncKeyStorage, error in
            guard let syncKeyStorage = syncKeyStorage, error == nil else {
                completion(error)
                return
            }

            self.generateBrainKey(password: newPassword) { brainKeyPair, error in
                guard let brainKeyPair = brainKeyPair, error == nil else {
                    completion(error)
                    return
                }
                syncKeyStorage.updateRecipients(newPublicKeys: [brainKeyPair.publicKey], newPrivateKey: brainKeyPair.privateKey) { error in

                }
            }
        }
    }

    func rotateHistoryKey(password: String, completion: @escaping (Error?) -> ()) {
        do {
            let newHistoryKeyPair = try self.crypto.generateKeyPair()
            let newHistoryKey = newHistoryKeyPair.privateKey

            self.setUpSyncKeyStorage(password: password) { syncKeyStorage, error in
                guard let syncKeyStorage = syncKeyStorage, error == nil else {
                    completion(error)
                    return
                }
                do {
                    let exportedNewHistoryKey = try self.privateKeyExporter.exportPrivateKey(privateKey: newHistoryKey)

                    syncKeyStorage.updateEntry(withName: self.identity, data: exportedNewHistoryKey, meta: nil) { error in
                        self.historyKeyPair = newHistoryKeyPair
                        completion(error)
                    }
                } catch {
                    completion(error)
                }
            }
        } catch {
            completion(error)
        }
    }

    // MARK: - Private API

    private func setUpSyncKeyStorage(password: String, completion: @escaping (SyncKeyStorage?, Error?) -> ()) {
        self.generateBrainKey(password: password) { brainKeyPair, error in
            guard let brainKeyPair = brainKeyPair, error == nil else {
                completion(nil, error)
                return
            }

            do {
                let syncKeyStorage = try self.generateSyncKeyStorage(keyPair: brainKeyPair)

                syncKeyStorage.sync { error in
                    completion(syncKeyStorage, error)
                }
            } catch {
                completion(nil, error)
            }
        }
    }

    private func generateSyncKeyStorage(keyPair: VirgilKeyPair) throws -> SyncKeyStorage {
        let cloudKeyStorage = try CloudKeyStorage(accessTokenProvider: self.cardManager.accessTokenProvider,
                                                  publicKeys: [keyPair.publicKey], privateKey: keyPair.privateKey)
        let syncKeyStorage = SyncKeyStorage(identity: self.identity, keychainStorage: self.keychainStorage,
                                            cloudKeyStorage: cloudKeyStorage)

        return syncKeyStorage
    }

    private func generateBrainKey(password: String, brainKeyId: String? = nil, completion: @escaping (VirgilKeyPair?, Error?) -> ()) {
        let brainKeyContext = BrainKeyContext.makeContext(accessTokenProvider: cardManager.accessTokenProvider)
        let brainKey = BrainKey(context: brainKeyContext)

        brainKey.generateKeyPair(password: password, brainKeyId: nil) { brainKeyPair, error in
            completion(brainKeyPair, error)
        }
    }
}
