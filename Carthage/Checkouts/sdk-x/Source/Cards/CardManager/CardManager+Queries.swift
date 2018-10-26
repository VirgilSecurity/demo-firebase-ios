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

// MARK: - Extension for primary operations
extension CardManager {
    /// Makes CallbackOperation<Card> for getting verified Virgil Card
    /// from the Virgil Cards Service with given ID, if exists
    ///
    /// - Parameter cardId: identifier of Virgil Card to find
    /// - Returns: CallbackOperation<GetCardResponse> for getting `GetCardResponse` with verified Virgil Card
    open func getCard(withId cardId: String) -> GenericOperation<Card> {
        let makeAggregateOperation: (Bool) -> GenericOperation<Card> = { force in
            return CallbackOperation { _, completion in
                let tokenContext = TokenContext(service: "cards", operation: "get", forceReload: force)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                let getCardOperation = self.makeGetCardOperation(cardId: cardId)
                let verifyCardOperation = self.makeVerifyCardOperation()
                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)

                getCardOperation.addDependency(getTokenOperation)
                verifyCardOperation.addDependency(getCardOperation)

                completionOperation.addDependency(getTokenOperation)
                completionOperation.addDependency(getCardOperation)
                completionOperation.addDependency(verifyCardOperation)

                let queue = OperationQueue()
                let operations = [getTokenOperation, getCardOperation, verifyCardOperation, completionOperation]
                queue.addOperations(operations, waitUntilFinished: false)
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    /// Generates self signed RawSignedModel
    ///
    /// - Parameters:
    ///   - privateKey: PrivateKey to self sign with
    ///   - publicKey: Public Key instance
    ///   - identity: Card's identity
    ///   - previousCardId: Identifier of Virgil Card with same identity this Card will replace
    ///   - extraFields: Dictionary with extra data to sign with model. Should be JSON-compatible
    /// - Returns: Self signed RawSignedModel
    /// - Throws: Rethrows from CardCrypto, JSONEncoder, JSONSerialization, ModelSigner
    @objc open func generateRawCard(privateKey: PrivateKey, publicKey: PublicKey,
                                    identity: String, previousCardId: String? = nil,
                                    extraFields: [String: String]? = nil) throws -> RawSignedModel {
        return try CardManager.generateRawCard(cardCrypto: self.cardCrypto, modelSigner: self.modelSigner,
                                               privateKey: privateKey, publicKey: publicKey,
                                               identity: identity, previousCardId: previousCardId,
                                               extraFields: extraFields)
    }

    /// Generates self signed RawSignedModel
    ///
    /// - Parameters:
    ///   - cardCrypto: CardCrypto implementation
    ///   - modelSigner: ModelSigner implementation
    ///   - privateKey: PrivateKey to self sign with
    ///   - publicKey: Public Key instance
    ///   - identity: Card's identity
    ///   - previousCardId: Identifier of Virgil Card with same identity this Card will replace
    ///   - extraFields: Dictionary with extra data to sign with model. Should be JSON-compatible
    /// - Returns: Self signed RawSignedModel
    /// - Throws: Rethrows from CardCrypto, JSONEncoder, JSONSerialization, ModelSigner
    @objc open class func generateRawCard(cardCrypto: CardCrypto, modelSigner: ModelSigner,
                                          privateKey: PrivateKey, publicKey: PublicKey,
                                          identity: String, previousCardId: String? = nil,
                                          extraFields: [String: String]? = nil) throws -> RawSignedModel {
        let exportedPubKey = try cardCrypto.exportPublicKey(publicKey)

        let cardContent = RawCardContent(identity: identity, publicKey: exportedPubKey,
                                         previousCardId: previousCardId, createdAt: Date())

        let snapshot = try JSONEncoder().encode(cardContent)

        let rawCard = RawSignedModel(contentSnapshot: snapshot)

        var data: Data?
        if extraFields != nil {
            data = try JSONSerialization.data(withJSONObject: extraFields as Any, options: [])
        }
        else {
            data = nil
        }

        try modelSigner.selfSign(model: rawCard, privateKey: privateKey, additionalData: data)

        return rawCard
    }

    /// Makes CallbackOperation<Card> for creating Virgil Card instance
    /// on the Virgil Cards Service and associates it with unique identifier
    ///
    /// - Parameter rawCard: RawSignedModel of Card to create
    /// - Returns: CallbackOperation<Card> for creating Virgil Card instance
    open func publishCard(rawCard: RawSignedModel) -> GenericOperation<Card> {
        let makeAggregateOperation: (Bool) -> GenericOperation<Card> = { forceReload in
            return CallbackOperation { _, completion in
                let tokenContext = TokenContext(service: "cards", operation: "publish", forceReload: forceReload)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                let generateRawCardOperation = self.makeGenerateRawCardOperation(rawCard: rawCard)
                let signOperation = self.makeAdditionalSignOperation()
                let publishCardOperation = self.makePublishCardOperation()
                let verifyCardOperation = self.makeVerifyCardOperation()
                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)

                generateRawCardOperation.addDependency(getTokenOperation)
                signOperation.addDependency(generateRawCardOperation)
                publishCardOperation.addDependency(getTokenOperation)
                publishCardOperation.addDependency(signOperation)
                verifyCardOperation.addDependency(publishCardOperation)

                completionOperation.addDependency(getTokenOperation)
                completionOperation.addDependency(generateRawCardOperation)
                completionOperation.addDependency(signOperation)
                completionOperation.addDependency(publishCardOperation)
                completionOperation.addDependency(verifyCardOperation)

                let queue = OperationQueue()
                let operations = [getTokenOperation, generateRawCardOperation, signOperation,
                                  publishCardOperation, verifyCardOperation, completionOperation]
                queue.addOperations(operations, waitUntilFinished: false)
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    /// Makes CallbackOperation<Card> for generating self signed RawSignedModel and
    /// creating Virgil Card instance on the Virgil Cards Service
    ///
    /// - Parameters:
    ///   - privateKey: PrivateKey to self sign with
    ///   - publicKey: Public Key instance
    ///   - identity: Card's identity
    ///   - previousCardId: Identifier of Virgil Card with same identity this Card will replace
    ///   - extraFields: Dictionary with extra data to sign with model. Should be JSON-compatible
    /// - Returns: CallbackOperation<Card> for generating self signed RawSignedModel and
    ///            creating Virgil Card instance on the Virgil Cards Service
    open func publishCard(privateKey: PrivateKey, publicKey: PublicKey,
                          identity: String? = nil, previousCardId: String? = nil,
                          extraFields: [String: String]? = nil) -> GenericOperation<Card> {
        let makeAggregateOperation: (Bool) -> GenericOperation<Card> = { forceReload in
            return CallbackOperation { operation, completion in
                let tokenContext = TokenContext(service: "cards", operation: "publish", forceReload: forceReload)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                let generateRawCardOperation =
                    self.makeGenerateRawCardOperation(privateKey: privateKey, publicKey: publicKey,
                                                      previousCardId: previousCardId, extraFields: extraFields)
                let signOperation = self.makeAdditionalSignOperation()
                let publishCardOperation = self.makePublishCardOperation()
                let verifyCardOperation = self.makeVerifyCardOperation()
                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)

                generateRawCardOperation.addDependency(getTokenOperation)
                signOperation.addDependency(generateRawCardOperation)
                publishCardOperation.addDependency(getTokenOperation)
                publishCardOperation.addDependency(signOperation)
                verifyCardOperation.addDependency(publishCardOperation)

                completionOperation.addDependency(getTokenOperation)
                completionOperation.addDependency(generateRawCardOperation)
                completionOperation.addDependency(signOperation)
                completionOperation.addDependency(publishCardOperation)
                completionOperation.addDependency(verifyCardOperation)

                let queue = OperationQueue()
                let operations = [getTokenOperation, generateRawCardOperation, signOperation,
                                  publishCardOperation, verifyCardOperation, completionOperation]
                queue.addOperations(operations, waitUntilFinished: false)
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    /// Makes CallbackOperation<[Card]> for performing search of Virgil Cards
    /// using identity on the Virgil Cards Service
    ///
    /// NOTE: Resulting array will contain only actual cards.
    ///       Older cards (that were replaced) can be accessed using previousCard property of new cards.
    ///
    /// - Parameter identity: identity of cards to search
    /// - Returns: CallbackOperation<[Card]> for performing search of Virgil Cards
    open func searchCards(identity: String) -> GenericOperation<[Card]> {
        let makeAggregateOperation: (Bool) -> GenericOperation<[Card]> = { forceReload in
            return CallbackOperation { _, completion in
                let tokenContext = TokenContext(service: "cards", operation: "search", forceReload: forceReload)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                let searchCardsOperation = self.makeSearchCardsOperation(identity: identity)
                let verifyCardsOperation = self.makeVerifyCardsOperation()
                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)

                searchCardsOperation.addDependency(getTokenOperation)
                verifyCardsOperation.addDependency(searchCardsOperation)

                completionOperation.addDependency(getTokenOperation)
                completionOperation.addDependency(searchCardsOperation)
                completionOperation.addDependency(verifyCardsOperation)

                let queue = OperationQueue()
                let operations = [getTokenOperation, searchCardsOperation, verifyCardsOperation, completionOperation]
                queue.addOperations(operations, waitUntilFinished: false)
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }
}
