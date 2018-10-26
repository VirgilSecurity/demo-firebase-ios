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

/// Class that helps to create Operation instances for common cases
public final class OperationUtils {
    /// Creates empty async operation
    ///
    /// - Returns: GenericOperation<Void>
    public class func makeEmptyOperation() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            completion(Void(), nil)
        }
    }

    /// Creates completion operation that finds result and passes it to completion callback
    ///
    /// - Parameter completion: completion callback to be called after finding result
    /// - Returns: GenericOperation<Void>
    public class func makeCompletionOperation<T>(completion: @escaping (T?, Error?) -> Void) -> GenericOperation<Void> {
        let completionOperation = CallbackOperation { _, completion in
            completion(Void(), nil)
        }

        completionOperation.completionBlock = {
            do {
                if let error = completionOperation.findDependencyError() {
                    completion(nil, error)
                    return
                }

                let res: T = try completionOperation.findDependencyResult()
                completion(res, nil)
            }
            catch {
                completion(nil, error)
            }
        }

        return completionOperation
    }

    private class func makeRetryOperation(aggregateOperation: Operation,
                                          makeAggregateOperation: @escaping (Bool) -> Operation,
                                          completionOperation: Operation,
                                          queue: OperationQueue) -> GenericOperation<Void> {
        let retryCheckOp = CallbackOperation<Void> { [unowned completionOperation, queue] operation, completion in
            if let error = operation.findDependencyError(),
                let serviceError = error as? ServiceError,
                serviceError.errorCode == 20304 {
                let aggregateOperationRetry = makeAggregateOperation(true)
                completionOperation.addDependency(aggregateOperationRetry)
                completionOperation.removeDependency(aggregateOperation)
                queue.addOperation(aggregateOperationRetry)
                completion(Void(), nil)
            }

            completion(Void(), nil)
        }

        return retryCheckOp
    }

    /// Creates retry operation using operation fabric in form of closure
    ///
    /// - Parameter makeAggregateOperation: Operation fabric closure
    /// - Returns: GenericOperation<T>
    public class func makeRetryAggregate<T>(
        makeAggregateOperation: @escaping (Bool) -> GenericOperation<T>) -> GenericOperation<T> {
        return CallbackOperation<T> { _, completion in
            let queue = OperationQueue()

            let aggregateOperation = makeAggregateOperation(false)
            let completionOperation = self.makeCompletionOperation(completion: completion)
            let retryCheckOperation =
                self.makeRetryOperation(aggregateOperation: aggregateOperation,
                                        makeAggregateOperation: makeAggregateOperation,
                                        completionOperation: completionOperation, queue: queue)

            retryCheckOperation.addDependency(aggregateOperation)

            completionOperation.addDependency(aggregateOperation)
            completionOperation.addDependency(retryCheckOperation)

            let operations = [aggregateOperation, retryCheckOperation, completionOperation]
            queue.addOperations(operations, waitUntilFinished: false)
        }
    }

    /// Creates operation that obtains token
    ///
    /// - Parameters:
    ///   - tokenContext: TokenContext
    ///   - accessTokenProvider: AccessTokenProvider
    /// - Returns: GenericOperation<AccessToken>
    public class func makeGetTokenOperation(tokenContext: TokenContext,
                                            accessTokenProvider: AccessTokenProvider) -> GenericOperation<AccessToken> {
        return CallbackOperation<AccessToken> { _, completion in
            accessTokenProvider.getToken(with: tokenContext, completion: completion)
        }
    }
}
