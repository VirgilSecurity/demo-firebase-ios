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
    func signIn(with identity: String, token: String, completion: @escaping (Error?) -> ()) {
        do {
            let keyEntry = try self.keychainStorage.retrieveEntry(withName: identity)

            let key = try self.privateKeyExporter.importPrivateKey(from: keyEntry.data)

            guard let historyKey = key as? VirgilPrivateKey else {
                throw VirgilHelperError.keyIsNotVirgil
            }
            let publicKey = try self.crypto.extractPublicKey(from: historyKey)

            self.historyKeyPair = VirgilKeyPair(privateKey: historyKey, publicKey: publicKey)

            completion(nil)
        } catch {
            completion(error)
        }
    }

    func signIn(with identity: String, token: String, password: String, completion: @escaping (Error?) -> ()) {
        Log.debug("Signing in")

        try? self.keychainStorage.deleteEntry(withName: identity)

        self.fetchFromKeyknox(usingPassword: password, identity: identity, cardManager: cardManager) { historyKey, error in
            guard let historyKey = historyKey, error == nil else {
                completion(error)
                return
            }
            do {
                let publicKey = try self.crypto.extractPublicKey(from: historyKey)
                self.historyKeyPair = VirgilKeyPair(privateKey: historyKey, publicKey: publicKey)
                completion(nil)
            } catch {
                completion(error)
            }
        }
    }

    func signUp(with identity: String, token: String, password: String, completion: @escaping (Error?) -> ()) {
        Log.debug("Signing up")
        
        do {
            let historyKeyPair = try self.crypto.generateKeyPair()

            let group = DispatchGroup()
            var err: Error?

            try? keychainStorage.deleteEntry(withName: identity)

            group.enter()
            cardManager.publishCard(privateKey: historyKeyPair.privateKey, publicKey: historyKeyPair.publicKey,
                                    identity: identity) { card, error in
                err = error
                group.leave()
            }

            group.enter()
            self.publishToKeyknox(key: historyKeyPair.privateKey, usingPassword: password,
                                  identity: identity, cardManager: cardManager) { error in
                err = error
                group.leave()
            }

            group.notify(queue: .main) {
                self.historyKeyPair = err == nil ? historyKeyPair : nil
                completion(err)
            }
        } catch {
            completion(error)
        }
    }
}
