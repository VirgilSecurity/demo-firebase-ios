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
import VirgilCryptoApiImpl

extension BrainKey {
    internal func makeSeedOperation(blindedPassword: Data, brainKeyId: String?) -> GenericOperation<Data> {
        return CallbackOperation { operation, completion in
            do {
                let token: AccessToken = try operation.findDependencyResult()

                let seed = try self.client.generateSeed(blindedPassword: blindedPassword,
                                                        brainKeyId: brainKeyId,
                                                        token: token.stringRepresentation())

                completion(seed, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    internal func makeGenerateOperation(blindingSecret: Data) -> GenericOperation<VirgilKeyPair> {
        return CallbackOperation { operation, completion in
            do {
                let seed: Data = try operation.findDependencyResult()

                let deblindedPassword = try self.pythiaCrypto.deblind(transformedPassword: seed,
                                                                      blindingSecret: blindingSecret)

                completion(try self.pythiaCrypto.generateKeyPair(ofType: self.keyPairType,
                                                                 fromSeed: deblindedPassword), nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }
}
