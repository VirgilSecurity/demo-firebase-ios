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

/// Contains parameters for initializing CardManager
@objc(VSSCardManagerParams) public final class CardManagerParams: NSObject {
    /// CardCrypto instance
    @objc public let cardCrypto: CardCrypto
    /// AccessTokenProvider instance used for getting Access Token
    /// when performing queries
    @objc public let accessTokenProvider: AccessTokenProvider
    /// Card Verifier instance used for verifying Cards
    @objc public let cardVerifier: CardVerifier
    /// ModelSigner instance used for self signing Cards
    @objc public var modelSigner: ModelSigner
    /// CardClient instance used for performing queries
    @objc public var cardClient: CardClientProtocol
    /// Callback used for custom signing RawSignedModel, which takes RawSignedModel
    /// to sign and competion handler, called with signed RawSignedModel or provided error
    @objc public var signCallback: ((RawSignedModel, @escaping (RawSignedModel?, Error?) -> Void) -> Void)?
    /// Will automatically perform second query with forceReload = true AccessToken if true
    @objc public var retryOnUnauthorized: Bool

    /// Initializer
    ///
    /// - Parameters:
    ///   - cardCrypto: CardCrypto instance
    ///   - accessTokenProvider: AccessTokenProvider instance for getting Access Token
    ///     when performing queries
    ///   - cardVerifier: Card Verifier instance for verifyng Cards
    @objc public init(cardCrypto: CardCrypto, accessTokenProvider: AccessTokenProvider, cardVerifier: CardVerifier) {
        self.cardCrypto = cardCrypto
        self.modelSigner = ModelSigner(cardCrypto: cardCrypto)
        self.cardClient = CardClient()
        self.accessTokenProvider = accessTokenProvider
        self.cardVerifier = cardVerifier
        self.retryOnUnauthorized = true

        super.init()
    }
}
