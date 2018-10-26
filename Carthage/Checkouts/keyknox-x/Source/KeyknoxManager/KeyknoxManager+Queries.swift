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
import VirgilSDK
import VirgilCryptoAPI

// MARK: - Queries
extension KeyknoxManager {
    /// Signs then encrypts and pushed value to Keyknox service
    ///
    /// - Parameters:
    ///   - value: value to push
    ///   - previousHash: previous value hash
    /// - Returns: CallbackOperation<DecryptedKeyknoxValue>
    open func pushValue(_ value: Data, previousHash: Data?) -> GenericOperation<DecryptedKeyknoxValue> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxValue> = { force in
            return CallbackOperation { _, completion in
                self.queue.async {
                    let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                    let getTokenOperation = OperationUtils.makeGetTokenOperation(
                        tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                    let extractDataOperations = CallbackOperation { _, completion in
                        completion(value, nil)
                    }
                    let encryptOperation = self.makeEncryptOperation()
                    let pushValueOperation = self.makePushValueOperation(previousHash: previousHash)
                    let decryptOperation = self.makeDecryptOperation()

                    encryptOperation.addDependency(extractDataOperations)
                    pushValueOperation.addDependency(encryptOperation)
                    pushValueOperation.addDependency(getTokenOperation)
                    decryptOperation.addDependency(pushValueOperation)

                    let operations = [getTokenOperation, extractDataOperations,
                                      encryptOperation, pushValueOperation, decryptOperation]
                    let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                    operations.forEach {
                        completionOperation.addDependency($0)
                    }

                    let queue = OperationQueue()
                    queue.addOperations(operations + [completionOperation], waitUntilFinished: true)
                }
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    /// Pull value, decrypt then verify signature
    ///
    /// - Returns: CallbackOperation<DecryptedKeyknoxValue>
    open func pullValue() -> GenericOperation<DecryptedKeyknoxValue> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxValue> = { force in
            return CallbackOperation { _, completion in
                self.queue.async {
                    let tokenContext = TokenContext(service: "keyknox", operation: "get", forceReload: force)
                    let getTokenOperation = OperationUtils.makeGetTokenOperation(
                        tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                    let pullValueOperation = self.makePullValueOperation()
                    let decryptOperation = self.makeDecryptOperation()

                    pullValueOperation.addDependency(getTokenOperation)
                    decryptOperation.addDependency(pullValueOperation)

                    let operations = [getTokenOperation, pullValueOperation, decryptOperation]
                    let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                    operations.forEach {
                        completionOperation.addDependency($0)
                    }

                    let queue = OperationQueue()
                    queue.addOperations(operations + [completionOperation], waitUntilFinished: true)
                }
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    /// Resets Keyknox value (makes it empty). Also increments version
    ///
    /// - Returns: GenericOperation<Void>
    open func resetValue() -> GenericOperation<DecryptedKeyknoxValue> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxValue> = { force in
            return CallbackOperation { _, completion in
                self.queue.async {
                    let tokenContext = TokenContext(service: "keyknox", operation: "delete", forceReload: force)
                    let getTokenOperation = OperationUtils.makeGetTokenOperation(
                        tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                    let pullValueOperation = self.makeResetValueOperation()

                    pullValueOperation.addDependency(getTokenOperation)

                    let operations = [getTokenOperation, pullValueOperation]
                    let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                    operations.forEach {
                        completionOperation.addDependency($0)
                    }

                    let queue = OperationQueue()
                    queue.addOperations(operations + [completionOperation], waitUntilFinished: true)
                }
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    /// Updates public keys for ecnryption and signature verification
    /// and private key for decryption and signature generation
    ///
    /// - Parameters:
    ///   - newPublicKeys: New public keys that will be used for encryption and signature verification
    ///   - newPrivateKey: New private key that will be used for decryption and signature generation
    /// - Returns: CallbackOperation<DecryptedKeyknoxValue>
    open func updateRecipients(newPublicKeys: [PublicKey]? = nil,
                               newPrivateKey: PrivateKey? = nil) -> GenericOperation<DecryptedKeyknoxValue> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxValue> = { force in
            return CallbackOperation { _, completion in
                self.queue.async {
                    guard (newPublicKeys != nil && !(newPublicKeys?.isEmpty ?? true))
                        || newPrivateKey != nil else {
                            completion(nil, KeyknoxManagerError.keysShouldBeUpdated)
                            return
                    }

                    let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                    let getTokenOperation = OperationUtils.makeGetTokenOperation(
                        tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                    let pullValueOperation = self.makePullValueOperation()
                    let decryptOperation = self.makeDecryptOperation()
                    let encryptOperation = self.makeEncryptOperation(newPublicKeys: newPublicKeys,
                                                                     newPrivateKey: newPrivateKey)
                    let pushValueOperation = self.makePushValueOperation()
                    let decryptOperation2 = self.makeDecryptOperation()

                    let queue = OperationQueue()
                    let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)

                    let extractDataOperation = CallbackOperation<Data> { operation, completion in
                        do {
                            let data: DecryptedKeyknoxValue = try operation.findDependencyResult()

                            // Empty data, no need to reencrypt anything
                            guard !data.value.isEmpty || !data.meta.isEmpty else {
                                completionOperation.removeDependency(encryptOperation)
                                encryptOperation.cancel()

                                completionOperation.removeDependency(pushValueOperation)
                                pushValueOperation.cancel()

                                completionOperation.removeDependency(decryptOperation2)
                                decryptOperation2.cancel()

                                let newOperation = CallbackOperation { _, completion in
                                    completion(data, nil)
                                }
                                completionOperation.addDependency(newOperation)
                                queue.addOperation(newOperation)

                                completion(data.value, nil)
                                return
                            }

                            completion(data.value, nil)
                        }
                        catch {
                            completion(nil, error)
                        }
                    }

                    pullValueOperation.addDependency(getTokenOperation)
                    decryptOperation.addDependency(pullValueOperation)
                    extractDataOperation.addDependency(decryptOperation)
                    encryptOperation.addDependency(extractDataOperation)
                    pushValueOperation.addDependency(getTokenOperation)
                    pushValueOperation.addDependency(pullValueOperation)
                    pushValueOperation.addDependency(encryptOperation)
                    decryptOperation2.addDependency(pushValueOperation)

                    let operations = [getTokenOperation, pullValueOperation, decryptOperation,
                                      extractDataOperation, encryptOperation, pushValueOperation, decryptOperation2]
                    operations.forEach {
                        completionOperation.addDependency($0)
                    }

                    queue.addOperations(operations + [completionOperation], waitUntilFinished: true)
                }
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    /// Updates public keys for ecnryption and signature verification
    /// and private key for decryption and signature generation
    ///
    /// - Parameters:
    ///   - value: Current Keyknox value
    ///   - previousHash: Previous Keyknox value hash
    ///   - newPublicKeys: New public keys that will be used for encryption and signature verification
    ///   - newPrivateKey: New private key that will be used for decryption and signature generation
    /// - Returns: CallbackOperation<DecryptedKeyknoxValue>
    open func updateRecipients(value: Data, previousHash: Data,
                               newPublicKeys: [PublicKey]? = nil,
                               newPrivateKey: PrivateKey? = nil) -> GenericOperation<DecryptedKeyknoxValue> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxValue> = { force in
            return CallbackOperation { _, completion in
                self.queue.async {
                    guard !value.isEmpty else {
                        completion(nil, KeyknoxManagerError.dataIsEmpty)
                        return
                    }

                    let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                    let getTokenOperation = OperationUtils.makeGetTokenOperation(
                        tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                    let extractDataOperation = CallbackOperation { _, completion in
                        completion(value, nil)
                    }
                    let encryptOperation = self.makeEncryptOperation(newPublicKeys: newPublicKeys,
                                                                     newPrivateKey: newPrivateKey)
                    let pushValueOperation = self.makePushValueOperation(previousHash: previousHash)
                    let decryptOperation = self.makeDecryptOperation()

                    encryptOperation.addDependency(extractDataOperation)
                    pushValueOperation.addDependency(getTokenOperation)
                    pushValueOperation.addDependency(encryptOperation)
                    decryptOperation.addDependency(pushValueOperation)

                    let operations = [extractDataOperation, encryptOperation, getTokenOperation,
                                      pushValueOperation, decryptOperation]
                    let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                    operations.forEach {
                        completionOperation.addDependency($0)
                    }

                    let queue = OperationQueue()
                    queue.addOperations(operations + [completionOperation], waitUntilFinished: true)
                }
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
