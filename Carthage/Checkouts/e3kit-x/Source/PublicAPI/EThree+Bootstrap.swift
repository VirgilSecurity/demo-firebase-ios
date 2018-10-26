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

import VirgilSDK
import VirgilCryptoApiImpl

// MARK: - Extension with bootstrap operations
extension EThree {
    /// Initializes E3Kit with a callback to get Virgil access token
    ///
    /// - Parameters:
    ///   - tokenCallback: callback to get Virgil access token
    ///   - completion: completion handler, called with initialized EThree or corresponding Error
    @objc public static func initialize(tokenCallback: @escaping RenewJwtCallback,
                                        completion: @escaping (EThree?, Error?) -> ()) {
        let renewTokenCallback: CachingJwtProvider.RenewJwtCallback = { _, completion in
            tokenCallback(completion)
        }

        let accessTokenProvider = CachingJwtProvider(renewTokenCallback: renewTokenCallback)
        let tokenContext = TokenContext(service: "cards", operation: "")
        accessTokenProvider.getToken(with: tokenContext) { token, error in
            guard let identity = token?.identity(), error == nil else {
                completion(nil, error)
                return
            }
            do {
                let cardCrypto = VirgilCardCrypto()
                guard let verifier = VirgilCardVerifier(cardCrypto: cardCrypto) else {
                    completion(nil, EThreeError.verifierInitFailed)
                    return
                }
                let params = CardManagerParams(cardCrypto: cardCrypto,
                                               accessTokenProvider: accessTokenProvider,
                                               cardVerifier: verifier)
                let cardManager = CardManager(params: params)

                let ethree = try EThree(identity: identity, cardManager: cardManager)
                completion(ethree, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Attempts to load the authenticated user's private key from the cloud. If the user doesn't have
    /// a private key yet, it creates one and backs it up to the cloud, using the password specified.
    /// Without password it wouldn't use cloud to backup or retrieve key
    ///
    /// - Parameters:
    ///   - password: Private Key password
    ///   - completion: completion handler, called with corresponding error
    @objc public func bootstrap(password: String? = nil, completion: @escaping (Error?) -> ()) {
        if let identityKeyPair = self.localKeyManager.retrieveKeyPair() {
            self.authManager.signInFromKnownDevice(identityKeyPair: identityKeyPair, completion: completion)
        } else {
            self.cardManager.searchCards(identity: self.identity) { cards, error in
                guard let cards = cards, error == nil else {
                    completion(error)
                    return
                }

                if cards.isEmpty {
                    self.authManager.signUp(password: password, completion: completion)
                } else {
                    guard let password = password else {
                        completion(EThreeError.passwordRequired)
                        return
                    }

                    self.authManager.signInFromNewDevice(password: password, completion: completion)
                }
            }
        }
    }

    /// Deletes Private Key from local storage
    ///
    /// - Throws: KeychainStorageError
    @objc public func cleanUp() throws {
        try self.localKeyManager.delete()
    }
}
