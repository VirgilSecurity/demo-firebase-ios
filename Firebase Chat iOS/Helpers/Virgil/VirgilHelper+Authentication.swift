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
    func authenticate(email identity: String, authToken: String, completion: @escaping (Error?) -> ()) {
        let accessTokenProvider = CallbackJwtProvider(getTokenCallback: {
            tokenContext, completion in
            if let cashedJwt = self.cashedJwt, !tokenContext.forceReload {
                completion(cashedJwt, nil)
            } else {
                let jwtRequest = try? ServiceRequest(url: URL(string: self.jwtEndpoint)!,
                                                     method: ServiceRequest.Method.post,
                                                     headers: ["Content-Type": "application/json",
                                                               "Authorization": "Bearer " + authToken],
                                                     params: ["identity" : identity])
                guard let request = jwtRequest,
                    let jwtResponse = try? self.connection.send(request),
                    let responseBody = jwtResponse.body,
                    let json = try? JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any],
                    let jwtStr = json?["token"] as? String else {
                        Log.error("Getting JWT failed")
                        completion(nil, NSError())
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

        if self.keyStorage.exists(withName: identity) {
            self.signIn(identity) { error in
                DispatchQueue.main.async {
                    completion(error)
                }
            }
        } else {
            self.signUp(identity) { error in
                DispatchQueue.main.async {
                    completion(error)
                }
            }
        }
    }

    private func signIn(_ identity: String, completion: @escaping (Error?) -> ()) {
        Log.debug("Signing in")
        do {
            guard let cardManager = self.cardManager else {
                Log.error("Missing CardManager")
                throw NSError()
            }
            guard CoreDataHelper.sharedInstance.loadAccount(withIdentity: identity) else {
                Log.error("Missing account")
                throw NSError()
            }

            let keyEntry = try self.keyStorage.load(withName: identity)

            guard let privateKey = keyEntry.privateKey as? VirgilPrivateKey else {
                Log.error("Converting private key to Virgil failed")
                throw NSError()
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
                    Log.error("Converting keys to Virgil failed")
                    completion(NSError())
                    return
                }
                self.selfKeys = virgilKeys

                FirebaseHelper.sharedInstance.setUpChannelListListener(email: identity)

                completion(nil)
            }
        } catch {
            completion(error)
        }
    }

    private func signUp(_ identity: String, completion: @escaping (Error?) -> ()) {
        Log.debug("Signing up")
        do {
            let keyPair = try self.crypto.generateKeyPair()
            guard let cardManager = self.cardManager else {
                Log.error("Missing CardManager")
                completion(NSError())
                return
            }

            cardManager.publishCard(privateKey: keyPair.privateKey, publicKey: keyPair.publicKey, identity: identity) { card, error in
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
                            if FirebaseHelper.sharedInstance.channelListListener == nil {
                                FirebaseHelper.sharedInstance.setUpChannelListListener(email: identity)
                            }

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
}
