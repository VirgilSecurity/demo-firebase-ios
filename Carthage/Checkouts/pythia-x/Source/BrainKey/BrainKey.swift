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
import VirgilCrypto
import VirgilCryptoApiImpl

/// Class for Pythia BrainKey
@objc(VSYBrainKey) open class BrainKey: NSObject {
    /// PythiaClientProtocol implementation
    @objc public let client: PythiaClientProtocol
    /// PythiaCryptoProtocol implementation
    @objc public let pythiaCrypto: PythiaCryptoProtocol
    /// AccessTokenProvider implementation
    @objc public let accessTokenProvider: AccessTokenProvider
    /// Default key type to be generated
    @objc public let keyPairType: VSCKeyType

    /// Initializer
    ///
    /// - Parameter context: BrainKey context
    @objc public init(context: BrainKeyContext) {
        self.client = context.client
        self.accessTokenProvider = context.accessTokenProvider
        self.pythiaCrypto = context.pythiaCrypto
        self.keyPairType = context.keyPairType
    }

    /// Generates key pair based on given password and brainkeyId
    ///
    /// - Parameters:
    ///   - password: password from which key pair will be generated
    ///   - brainKeyId: optional brainKey identifier (in case one wants to generate several key pairs from 1 password)
    /// - Returns: GenericOperation with VirgilKeyPair
    open func generateKeyPair(password: String, brainKeyId: String? = nil) -> GenericOperation<VirgilKeyPair> {
        return CallbackOperation { _, completion in
            let tokenContext = TokenContext(service: "pythia", operation: "seed", forceReload: false)
            let getTokenOperation = OperationUtils.makeGetTokenOperation(
                tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)

            let blindedResult: BlindResult
            do {
                blindedResult = try self.pythiaCrypto.blind(password: password)
            }
            catch {
                completion(nil, error)
                return
            }

            let seedOperation = self.makeSeedOperation(blindedPassword: blindedResult.blindedPassword,
                                                       brainKeyId: brainKeyId)

            let generateOperation = self.makeGenerateOperation(blindingSecret: blindedResult.blindingSecret)

            let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)

            seedOperation.addDependency(getTokenOperation)

            generateOperation.addDependency(seedOperation)

            completionOperation.addDependency(getTokenOperation)
            completionOperation.addDependency(seedOperation)
            completionOperation.addDependency(generateOperation)

            let queue = OperationQueue()
            let operations = [getTokenOperation, seedOperation, generateOperation, completionOperation]
            queue.addOperations(operations, waitUntilFinished: false)
        }
    }
}
