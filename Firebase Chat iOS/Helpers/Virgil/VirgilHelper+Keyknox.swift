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
    func publishToKeyknox(key: VirgilPrivateKey, usingPassword password: String, identity: String,
                          cardManager: CardManager, completion: @escaping (Error?) -> ()) {
        let brainKeyContext = BrainKeyContext.makeContext(accessTokenProvider: cardManager.accessTokenProvider)
        let brainKey = BrainKey(context: brainKeyContext)

        brainKey.generateKeyPair(password: password, brainKeyId: nil) { brainKeyPair, error in
            guard let brainKeyPair = brainKeyPair, error == nil else {
                completion(error)
                return
            }

            do {
                let exportedHistoryKey = try self.privateKeyExporter.exportPrivateKey(privateKey: key)

                let cloudKeyStorage = try CloudKeyStorage(accessTokenProvider: cardManager.accessTokenProvider,
                                                          publicKeys: [brainKeyPair.publicKey], privateKey: brainKeyPair.privateKey)
                let syncKeyStorage = SyncKeyStorage(identity: identity, keychainStorage: self.keychainStorage,
                                                    cloudKeyStorage: cloudKeyStorage)

                syncKeyStorage.sync { error in
                    guard error == nil else {
                        completion(error)
                        return
                    }
                    syncKeyStorage.storeEntry(withName: identity, data: exportedHistoryKey) { _, error in
                        completion(error)
                    }
                }
            } catch {
                completion(error)
            }
        }
    }

    func fetchFromKeyknox(usingPassword password: String, identity: String, cardManager: CardManager,
                          completion: @escaping (VirgilPrivateKey?, Error?) -> ()) {
        let brainKeyContext = BrainKeyContext.makeContext(accessTokenProvider: cardManager.accessTokenProvider)
        let brainKey = BrainKey(context: brainKeyContext)

        brainKey.generateKeyPair(password: password, brainKeyId: nil) { brainKeyPair, error in
            guard let brainKeyPair = brainKeyPair, error == nil else {
                completion(nil, error)
                return
            }

            do {
                let cloudKeyStorage = try CloudKeyStorage(accessTokenProvider: cardManager.accessTokenProvider,
                                                          publicKeys: [brainKeyPair.publicKey], privateKey: brainKeyPair.privateKey)
                let syncKeyStorage = SyncKeyStorage(identity: identity, keychainStorage: self.keychainStorage,
                                                    cloudKeyStorage: cloudKeyStorage)

                syncKeyStorage.sync { error in
                    guard error == nil else {
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
            } catch {
                completion(nil, error)
            }
        }
    }
}
