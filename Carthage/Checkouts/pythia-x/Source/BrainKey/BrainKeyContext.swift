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

/// Context with dependencies needed for BrainKey
@objc(VSYBrainKeyContext) public final class BrainKeyContext: NSObject {
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
    /// - Parameters:
    ///   - client: PythiaClientProtocol implementation
    ///   - pythiaCrypto: PythiaCryptoProtocol implementation
    ///   - accessTokenProvider: AccessTokenProvider implementation
    ///   - keyPairType: Default key type to be generated
    @objc public init(client: PythiaClientProtocol = PythiaClient(),
                      pythiaCrypto: PythiaCryptoProtocol = PythiaCrypto(),
                      accessTokenProvider: AccessTokenProvider,
                      keyPairType: VSCKeyType = .FAST_EC_ED25519) {
        self.client = client
        self.pythiaCrypto = pythiaCrypto
        self.accessTokenProvider = accessTokenProvider
        self.keyPairType = keyPairType

        super.init()
    }

    /// Fabric method to create context
    ///
    /// - Parameter accessTokenProvider: AccessTokenProvider implementation
    /// - Returns: Initialized BrainKeyContext instance
    @objc public static func makeContext(accessTokenProvider: AccessTokenProvider) -> BrainKeyContext {
        return BrainKeyContext(client: PythiaClient(), pythiaCrypto: PythiaCrypto(),
                               accessTokenProvider: accessTokenProvider, keyPairType: .FAST_EC_ED25519)
    }
}
