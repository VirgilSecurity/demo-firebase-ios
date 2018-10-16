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
        guard let identityKeyPair = self.identityKeyPair, identityKeyPair.isPublished else {
            completion(nil)
            return
        }

        do {
            let keyPair = try self.crypto.generateKeyPair()

            self.publishCardThenUpdateLocal(keyPair: keyPair, completion: completion)
        } catch {
            completion(error)
        }
    }

    func bootstrapUser(password: String, completion: @escaping (Error?) -> ()) {
        guard self.identityKeyPair == nil else {
            completion(nil)
            return
        }

        self.cardManager.searchCards(identity: self.identity) { cards, error in
            guard let cards = cards, error == nil else {
                completion(error)
                return
            }

            if cards.isEmpty {
                self.signUp(password: password, completion: completion)
            } else {
                self.signIn(password: password, completion: completion)
            }
        }
    }

    // MARK: - Private API

    private func signUp(password: String, completion: @escaping (Error?) -> ()) {
        do {
            var keyPair = try self.crypto.generateKeyPair()

            self.publishToKeyknox(key: keyPair.privateKey, usingPassword: password) { entry, error in
                do {
                    try self.updateIfExists(keyPair: &keyPair, entry: entry, error: error)

                    guard let entry = entry, error == nil else {
                        completion(error)
                        return
                    }

                    try self.storeLocal(data: entry.data, isPublished: false)

                    self.publishCardThenUpdateLocal(keyPair: keyPair, completion: completion)
                } catch {
                    completion(error)
                    return
                }
            }
        } catch {
            completion(error)
        }
    }

    private func updateIfExists(keyPair: inout VirgilKeyPair, entry: KeychainEntry?, error: Error?) throws {
        if let entry = entry, let error = error as? VirgilHelperError, error == VirgilHelperError.entryExists {
            let privateKey = try self.privateKeyExporter.importPrivateKey(from: entry.data)
            guard let virgilPrivateKey = privateKey as? VirgilPrivateKey else {
                throw VirgilHelperError.keyIsNotVirgil
            }
            let virgilPublicKey = try self.crypto.extractPublicKey(from: virgilPrivateKey)

            keyPair = VirgilKeyPair(privateKey: virgilPrivateKey, publicKey: virgilPublicKey)
        }
    }

    private func signIn(password: String, completion: @escaping (Error?) -> ()) {
        self.fetchFromKeyknox(usingPassword: password) { entry, error in
            guard let entry = entry, error == nil else {
                completion(error)
                return
            }
            do {
                try self.storeLocal(data: entry.data, isPublished: true)
                completion(nil)
            } catch {
                completion(error)
            }
        }
    }
}
