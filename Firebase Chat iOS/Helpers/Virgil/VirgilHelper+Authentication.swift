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
    func signIn(token: String, completion: @escaping (Error?) -> ()) {
        do {
            try self.fetchHistoryKeyPair()
            completion(nil)
        } catch {
            completion(error)
        }
    }

    func signIn(token: String, password: String, completion: @escaping (Error?) -> ()) {
        Log.debug("Signing in")

        try? self.keychainStorage.deleteEntry(withName: identity)

        self.fetchFromKeyknox(usingPassword: password, identity: self.identity) { historyKey, error in
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

    func signUp(token: String, password: String, completion: @escaping (Error?) -> ()) {
        Log.debug("Signing up")
        
        do {
            let historyKeyPair = try self.crypto.generateKeyPair()

            let group = DispatchGroup()
            var err: Error?

            try? keychainStorage.deleteEntry(withName: self.identity)

            group.enter()
            self.cardManager.publishCard(privateKey: historyKeyPair.privateKey, publicKey: historyKeyPair.publicKey,
                                    identity: identity) { card, error in
                err = error
                group.leave()
            }

            group.enter()
            self.publishToKeyknox(key: historyKeyPair.privateKey, usingPassword: password) { error in
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
