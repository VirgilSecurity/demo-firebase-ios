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
    /// Loads users' Private Key and Public Keys, CoreData account
    ///
    /// - Parameters:
    ///   - identity: users' identity
    ///   - token: Firebase Auth token
    ///   - completion: completion handler, called with error if failed
    func signIn(with identity: String, token: String, completion: @escaping (Error?) -> ()) {
        guard self.keyStorage.exists(withName: identity) else {
            self.signUp(with: identity, token: token) { error in
                completion(error)
            }
            return
        }

        Log.debug("Signing in")
        self.update(email: identity, authToken: token)
        do {
            guard let cardManager = self.cardManager else {
                throw VirgilHelperError.missingCardManager
            }
            try CoreDataHelper.sharedInstance.loadAccount(withIdentity: identity)

            let keyEntry = try self.keyStorage.load(withName: identity)

            guard let privateKey = keyEntry.privateKey as? VirgilPrivateKey else {
                throw VirgilHelperError.keyIsNotVirgil
            }
            self.privateKey = privateKey

            cardManager.searchCards(identity: identity) { cards, error in
                guard error == nil, let cards = cards else {
                    Log.error("Search self cards failed with error: \(error?.localizedDescription ?? "unknown error")")
                    completion(error)
                    return
                }
                let keys = cards.map { $0.publicKey }
                guard let virgilKeys = keys as? [VirgilPublicKey] else {
                    completion(VirgilHelperError.keyIsNotVirgil)
                    return
                }
                self.selfKeys = virgilKeys

                completion(nil)
            }
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
    func signUp(with identity: String, token: String, completion: @escaping (Error?) -> ()) {
        Log.debug("Signing up")
        self.update(email: identity, authToken: token)
        do {
            let keyPair = try self.crypto.generateKeyPair()
            guard let cardManager = self.cardManager else {
                completion(VirgilHelperError.missingCardManager)
                return
            }

            cardManager.publishCard(privateKey: keyPair.privateKey,
                                    publicKey: keyPair.publicKey,
                                    identity: identity) { card, error in
                guard let card = card, error == nil else {
                    Log.error("Failed to create card with error: \(error?.localizedDescription ?? "unknown error")")
                    completion(error)
                    return
                }
                do {
                    try? self.keyStorage.delete(withName: identity)
                    try self.keyStorage.store(privateKey: keyPair.privateKey, name: identity, meta: nil)

                    let exportedCard = try cardManager.exportCardAsBase64EncodedString(card)
                    self.privateKey = keyPair.privateKey

                    let group = DispatchGroup()
                    var err: Error?

                    group.enter()
                    cardManager.searchCards(identity: identity) { cards, error in
                        guard error == nil, let cards = cards else {
                            Log.error("Search self cards failed with error: \(error?.localizedDescription ?? "unknown error")")
                            err = error
                            return
                        }
                        let keys = cards.map { $0.publicKey }
                        guard let virgilKeys = keys as? [VirgilPublicKey] else {
                            Log.error("Converting keys to Virgil failed")
                            err = NSError()
                            return
                        }
                        self.selfKeys = virgilKeys

                        defer { group.leave() }
                    }

                    group.enter()
                    FirebaseHelper.sharedInstance.doesUserExist(withUsername: identity) { exist in
                        if !exist {
                            FirebaseHelper.sharedInstance.createUser(email: identity) { error in
                                if let error = error {
                                    Log.error("Firebase: creating user failed with error: \(error.localizedDescription)")
                                    err = error
                                }
                                group.leave()
                            }
                        } else { group.leave() }
                    }

                    group.notify(queue: .main) {
                        if err == nil {
                            CoreDataHelper.sharedInstance.createAccount(withIdentity: identity, exportedCard: exportedCard) {
                                completion(err)
                            }
                        } else {
                            completion(err)
                        }
                    }
                } catch {
                    completion(error)
                }
            }
        } catch {
            completion(error)
        }
    }

    /// Updates CardManager instance
    ///
    /// - Parameters:
    ///   - identity: new user's identity
    ///   - authToken: Firebase Auth token
    func update(email identity: String, authToken: String) {
        let accessTokenProvider = CallbackJwtProvider(getTokenCallback: { tokenContext, completion in
            if let cashedJwt = self.cashedJwt, !tokenContext.forceReload {
                completion(cashedJwt, nil)
            } else {
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
                self.cashedJwt = jwtStr

                completion(jwtStr, nil)
            }
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
