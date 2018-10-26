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

import Foundation
import VirgilCryptoApiImpl

extension AuthManager {
    internal func signUp(password: String?, completion: @escaping (Error?) -> ()) {
        if let password = password {
            self.signUpWithPassword(password: password, completion: completion)
        } else {
            self.signUpWithoutPassword(completion: completion)
        }
    }

    internal func signUpWithPassword(password: String, completion: @escaping (Error?) -> ()) {
        self.cloudKeyManager.setUpSyncKeyStorage(password: password) { syncKeyStorage, error in
            guard let syncKeyStorage = syncKeyStorage, error == nil else {
                completion(error)
                return
            }

            let finishSignUp: (Data, VirgilKeyPair) -> () = { data, keyPair in
                do {
                    try self.localKeyManager.store(data: data, isPublished: false)
                    self.publishCardThenUpdateLocal(keyPair: keyPair, completion: completion)
                } catch {
                    completion(error)
                }
            }
            do {
                if try syncKeyStorage.existsEntry(withName: self.identity) {
                    let entry = try syncKeyStorage.retrieveEntry(withName: self.identity)
                    let keyPair = try self.buildKeyPair(from: entry.data)
                    finishSignUp(entry.data, keyPair)
                } else {
                    let keyPair = try self.crypto.generateKeyPair()
                    let exportedIdentityKey = self.crypto.exportPrivateKey(keyPair.privateKey)

                    syncKeyStorage.storeEntry(withName: self.identity, data: exportedIdentityKey) { entry, error in
                        guard let entry = entry, error == nil else {
                            completion(error)
                            return
                        }
                        finishSignUp(entry.data, keyPair)
                    }
                }
            } catch {
                completion(error)
            }
        }
    }

    internal func signUpWithoutPassword(completion: @escaping (Error?) -> ()) {
        do {
            let keyPair = try self.crypto.generateKeyPair()

            self.cardManager.publishCard(privateKey: keyPair.privateKey, publicKey: keyPair.publicKey,
                                         identity: self.identity) { cards, error in
                guard error == nil else {
                    completion(error)
                    return
                }

                let data = self.crypto.exportPrivateKey(keyPair.privateKey)

                do {
                    try self.localKeyManager.store(data: data, isPublished: true)

                    completion(nil)
                } catch {
                    completion(error)
                }
            }
        } catch {
            completion(error)
        }
    }
}
