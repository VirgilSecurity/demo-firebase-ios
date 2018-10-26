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
import VirgilCryptoAPI

//Objective-C compatible Queries
extension CardManager {
    /// Asynchronously returns `Card` with given identifier
    /// from the Virgil Cards Service with given ID, if exists
    ///
    /// NOTE: See swift version for additional info
    ///
    /// - Parameters:
    ///   - cardId: string with unique Virgil Card identifier
    ///   - completion: completion handler, called with found and verified Card or corresponding error
    @objc open func getCard(withId cardId: String, completion: @escaping (Card?, Error?) -> Void) {
        self.getCard(withId: cardId).start(completion: completion)
    }

    /// Asynchronously creates Virgil Card instance on the Virgil Cards Service and associates it with unique identifier
    /// Also makes the Card accessible for search/get queries from other users
    /// `RawSignedModel` should be at least selfSigned
    ///
    /// NOTE: See swift version for additional info
    ///
    /// - Parameters:
    ///   - rawCard: self signed `RawSignedModel`
    ///   - completion: completion handler, called with published and verified Card or corresponding error
    @objc open func publishCard(rawCard: RawSignedModel, completion: @escaping (Card?, Error?) -> Void) {
        self.publishCard(rawCard: rawCard).start(completion: completion)
    }

    /// Asynchronously generates self signed RawSignedModel and creates Virgil Card
    /// instance on the Virgil Cards Service and associates it with unique identifier
    ///
    /// NOTE: See swift version for additional info
    ///
    /// - Parameters:
    ///   - privateKey: Private Key to self sign RawSignedModel with
    ///   - publicKey: PublicKey for generating RawSignedModel
    ///   - identity: identity for generating RawSignedModel. Will be taken from token if omitted
    ///   - previousCardId: identifier of Virgil Card to replace
    ///   - extraFields: Dictionary with extra data to sign with model
    ///   - completion: completion handler, called with published and verified Card or corresponding error
    @objc open func publishCard(privateKey: PrivateKey, publicKey: PublicKey, identity: String,
                                previousCardId: String? = nil, extraFields: [String: String]? = nil,
                                completion: @escaping (Card?, Error?) -> Void) {
        self.publishCard(privateKey: privateKey, publicKey: publicKey, identity: identity,
                         previousCardId: previousCardId, extraFields: extraFields)
            .start(completion: completion)
    }

    /// Asynchronously performs search of Virgil Cards using identity on the Virgil Cards Service
    ///
    /// NOTE: See swift version for additional info
    ///
    /// - Parameters:
    ///   - identity: identity of cards to search
    ///   - completion: completion handler, called with found and verified Cards or corresponding error
    @objc open func searchCards(identity: String, completion: @escaping ([Card]?, Error?) -> Void) {
        self.searchCards(identity: identity).start(completion: completion)
    }
}
