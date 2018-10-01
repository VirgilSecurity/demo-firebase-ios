//
//  VirgilHelper+Authentication.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/27/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import VirgilSDK
import VirgilKeyknox
import VirgilPythia
import VirgilCryptoApiImpl

extension VirgilHelper {
    /// Loads users' Private Key and Public Keys, CoreData account
    ///
    /// - Parameters:
    ///   - identity: users' identity
    ///   - token: Firebase Auth token
    ///   - completion: completion handler, called with error if failed
    func signIn(with identity: String, token: String, completion: @escaping (Error?) -> ()) {
        Log.debug("Signing in")
        self.setCardManager(identity: identity, authToken: token)

        do {
            guard try self.keychainStorage.existsEntry(withName: identity) else {
                //            self.signUp(with: identity, token: token) { error in
                //                completion(error)
                //            }
                return
            }

            guard let cardManager = self.cardManager else {
                throw VirgilHelperError.missingCardManager
            }
            try CoreDataHelper.sharedInstance.loadAccount(withIdentity: identity)

            let keyEntry = try self.keychainStorage.retrieveEntry(withName: identity)

            guard let privateKey = keyEntry.privateKey as? VirgilPrivateKey else {
                throw VirgilHelperError.keyIsNotVirgil
            }
            let publicKey = try self.crypto.extractPublicKey(from: privateKey)
            self.keyPair = VirgilKeyPair(privateKey: privateKey, publicKey: publicKey)

            completion(nil)
        } catch {
            completion(error)
        }
    }

    /// Publishes new Card, creates CoreData and Firestore account
    ///
    /// - Parameters:
    ///   - identity: users' identity
    ///   - token: Firebase Auth token
    ///   - completion: completion handler, called with error if failed
    func signUp(with identity: String, token: String, password: String, completion: @escaping (String?, Error?) -> ()) {
        Log.debug("Signing up")
        self.setCardManager(identity: identity, authToken: token)
        do {
            let historyKeyPair = try self.crypto.generateKeyPair()
            guard let cardManager = self.cardManager else {
                throw VirgilHelperError.missingCardManager
            }

            let group = DispatchGroup()
            var err: Error?
            var exportedCard: String?

            try? keychainStorage.deleteEntry(withName: identity)

            group.enter()
            self.publishCard(keyPair: historyKeyPair, identity: identity, cardManager: cardManager) { card, error in
                err = error
                exportedCard = card
                group.leave()
            }

            group.enter()
            self.publishToKeyknox(key: historyKeyPair.privateKey, usingPassword: password, identity: identity, cardManager: cardManager) { error in
                err = error
                group.leave()
            }

            group.notify(queue: .main) {
                if err == nil {
                    self.historyKeyPair = historyKeyPair

                    completion(exportedCard, nil)
                } else {
                    completion(nil, err)
                }
            }
        } catch {
            completion(nil, error)
        }
    }

    private func publishCard(keyPair: VirgilKeyPair, identity: String, cardManager: CardManager, completion: @escaping (String?, Error?) -> ()) {
        cardManager.publishCard(privateKey: keyPair.privateKey, publicKey: keyPair.publicKey, identity: identity) { card, error in
            do {
                guard let card = card, error == nil else {
                    throw error!
                }
                let exportedCard = try cardManager.exportCardAsBase64EncodedString(card)

                completion(exportedCard, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    private func publishToKeyknox(key: VirgilPrivateKey, usingPassword password: String, identity: String,
                                  cardManager: CardManager, completion: @escaping (Error?) -> ()) {
        let brainKeyContext = BrainKeyContext.makeContext(accessTokenProvider: cardManager.accessTokenProvider)
        let brainKey = BrainKey(context: brainKeyContext)

        do {
            let brainKeyPair = try brainKey.generateKeyPair(password: password).startSync().getResult()

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

        }
    }

    /// Updates CardManager instance
    ///
    /// - Parameters:
    ///   - identity: new user's identity
    ///   - authToken: Firebase Auth token
    func setCardManager(identity: String, authToken: String) {
        let accessTokenProvider = CachingJwtProvider(renewTokenCallback: { tokenContext, completion in
            let jwtRequest = try? ServiceRequest(url: URL(string: self.jwtEndpoint)!,
                                                 method: ServiceRequest.Method.post,
                                                 headers: ["Content-Type": "application/json",
                                                           "Authorization": "Bearer " + authToken],
                                                 params: ["identity": identity])
            guard let request = jwtRequest,
                let jwtResponse = try? self.connection.send(request),
                let responseBody = jwtResponse.body,
                let json = try? JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any],
                let jwtStr = json?["token"] as? String else {
                    Log.error("Getting JWT failed")
                    completion(nil, VirgilHelperError.gettingJwtFailed)
                    return
            }

            completion(jwtStr, nil)
        })
        let cardCrypto = VirgilCardCrypto()
        guard let verifier = VirgilCardVerifier(cardCrypto: cardCrypto) else {
            Log.error("VirgilCardVerifier init failed")
            return
        }
        let params = CardManagerParams(cardCrypto: cardCrypto,
                                       accessTokenProvider: accessTokenProvider,
                                       cardVerifier: verifier)
        self.cardManager = CardManager(params: params)
    }
}
