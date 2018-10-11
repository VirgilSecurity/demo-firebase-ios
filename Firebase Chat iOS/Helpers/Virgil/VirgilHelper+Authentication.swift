//
//  VirgilHelper+Authentication.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/27/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import VirgilSDK
import VirgilCryptoApiImpl

extension VirgilHelper {
    func bootstrapUser(completion: @escaping (Error?) -> ()) {
        if (try? self.fetchHistoryKeyPair()) != nil {
            completion(nil)
        } else {
            self.cardManager.searchCards(identity: self.identity) { cards, error in
                guard let cards = cards, error == nil, cards.isEmpty else {
                    completion(error ?? VirgilHelperError.missingKeys)
                    return
                }

                do {
                    let historyKeyPair = try self.crypto.generateKeyPair()

                    self.cardManager.publishCard(privateKey: historyKeyPair.privateKey,
                                                 publicKey: historyKeyPair.publicKey, identity: self.identity)
                    { card, error in
                        guard error == nil else {
                            completion(error)
                            return
                        }
                        self.historyKeyPair = historyKeyPair

                        do {
                            let data = try self.privateKeyExporter.exportPrivateKey(privateKey: historyKeyPair.privateKey)
                            _ = try self.keychainStorage.store(data: data, withName: self.identity, meta: nil)
                        } catch {
                            completion(error)
                        }

                        completion(nil)
                    }
                } catch {
                    completion(error)
                }
            }
        }
    }

    func bootstrapUser(password: String, completion: @escaping (Error?) -> ()) {
        if (try? self.fetchHistoryKeyPair()) != nil {
            completion(nil)
        } else {
            self.cardManager.searchCards(identity: self.identity) { cards, error in
                guard let cards = cards, error == nil else {
                    completion(error)
                    return
                }

                if cards.isEmpty {
                    self.signUp(password: password, completion: completion)
                } else {
                    self.recoverUserKey(usingPassword: password) { _, error in
                        completion(error)
                    }
                }
            }
        }
    }

    // MARK: - Private API

    private func signUp(password: String, completion: @escaping (Error?) -> ()) {
        do {
            let historyKeyPair = try self.crypto.generateKeyPair()

            self.publishToKeyknox(key: historyKeyPair.privateKey, usingPassword: password) { error in
                guard error == nil else {
                    completion(error)
                    return
                }

                self.cardManager.publishCard(privateKey: historyKeyPair.privateKey,
                                             publicKey: historyKeyPair.publicKey, identity: self.identity)
                { card, error in
                    guard card != nil, error == nil else {
                        self.deleteKeyknoxEntry(password: password) { err in
                            if let err = err {
                                Log.error("Deleting Keyknox entry failed with error: \(err.localizedDescription)")
                            }
                            completion(error)
                        }
                        return
                    }
                    self.historyKeyPair = historyKeyPair

                    completion(nil)
                }
            }
        } catch {
            completion(error)
        }
    }
}
