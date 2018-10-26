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
import VirgilSDK

internal class AuthManager {
    internal let identity: String
    internal let crypto: VirgilCrypto
    internal let cardManager: CardManager
    internal let localKeyManager: LocalKeyManager
    internal let cloudKeyManager: CloudKeyManager

    internal init(identity: String, crypto: VirgilCrypto, cardManager: CardManager,
                  localKeyManager: LocalKeyManager, cloudKeyManager: CloudKeyManager) {
        self.identity = identity
        self.crypto = crypto
        self.cardManager = cardManager
        self.localKeyManager = localKeyManager
        self.cloudKeyManager = cloudKeyManager
    }

    internal func publishCardThenUpdateLocal(keyPair: VirgilKeyPair, completion: @escaping (Error?) -> ()) {
        self.cardManager.publishCard(privateKey: keyPair.privateKey, publicKey: keyPair.publicKey,
                                     identity: self.identity) { cards, error in
            guard error == nil else {
                completion(error)
                return
            }

            do {
                try self.localKeyManager.update(isPublished: true)

                completion(nil)
            } catch {
                completion(error)
            }
        }
    }

    internal func buildKeyPair(from data: Data) throws -> VirgilKeyPair {
        let key = try self.crypto.importPrivateKey(from: data)
        let publicKey = try self.crypto.extractPublicKey(from: key)

        return VirgilKeyPair(privateKey: key, publicKey: publicKey)
    }
}
