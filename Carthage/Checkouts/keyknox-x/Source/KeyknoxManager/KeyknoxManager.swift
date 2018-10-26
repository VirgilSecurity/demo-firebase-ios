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

/// Class responsible for managing Keyknox value with E2EE
@objc(VSKKeyknoxManager) open class KeyknoxManager: NSObject {
    /// AccessTokenProvider instance used for getting Access Token
    /// when performing queries
    @objc public let accessTokenProvider: AccessTokenProvider

    /// KeyknoxClient instance used for performing queries
    @objc public let keyknoxClient: KeyknoxClientProtocol

    /// Public keys used for encryption and signature verification
    @objc internal(set) public var publicKeys: [PublicKey]

    /// Private key used for decryption and signing
    @objc internal(set) public var privateKey: PrivateKey

    /// KeyknoxCryptoProtocol implementation
    public let crypto: KeyknoxCryptoProtocol

    /// Retry on 401 error
    @objc public let retryOnUnauthorized: Bool

    internal let queue = DispatchQueue(label: "KeyknoxManagerQueue")

    /// Init
    ///
    /// - Parameters:
    ///   - accessTokenProvider: AccessTokenProvider implementation
    ///   - keyknoxClient: KeyknoxClientProtocol implementation
    ///   - publicKeys: Public keys used for encryption and signature verification
    ///   - privateKey: Private key used for decryption and signing
    ///   - crypto: KeyknoxCryptoProtocol implementation
    ///   - retryOnUnauthorized: Retry on 401 error
    /// - Throws: KeyknoxManagerError.noPublicKeys if public keys array is empty
    public init(accessTokenProvider: AccessTokenProvider,
                keyknoxClient: KeyknoxClientProtocol = KeyknoxClient(),
                publicKeys: [PublicKey], privateKey: PrivateKey,
                crypto: KeyknoxCryptoProtocol = KeyknoxCrypto(),
                retryOnUnauthorized: Bool = false) throws {
        guard !publicKeys.isEmpty else {
            throw KeyknoxManagerError.noPublicKeys
        }

        self.accessTokenProvider = accessTokenProvider
        self.keyknoxClient = keyknoxClient
        self.publicKeys = publicKeys
        self.privateKey = privateKey
        self.crypto = crypto
        self.retryOnUnauthorized = retryOnUnauthorized

        super.init()
    }

    /// Init
    ///
    /// - Parameters:
    ///   - accessTokenProvider: AccessTokenProvider implementation
    ///   - keyknoxClient: KeyknoxClientProtocol implementation
    ///   - publicKeys: Public keys used for encryption and signature verification
    ///   - privateKey: Private key used for decryption and signing
    ///   - retryOnUnauthorized: Retry on 401 error
    /// - Throws: KeyknoxManagerError.noPublicKeys
    @objc public convenience init(accessTokenProvider: AccessTokenProvider,
                                  keyknoxClient: KeyknoxClientProtocol = KeyknoxClient(),
                                  publicKeys: [PublicKey], privateKey: PrivateKey,
                                  retryOnUnauthorized: Bool = false) throws {
        try self.init(accessTokenProvider: accessTokenProvider,
                      keyknoxClient: keyknoxClient,
                      publicKeys: publicKeys, privateKey: privateKey,
                      crypto: KeyknoxCrypto(),
                      retryOnUnauthorized: retryOnUnauthorized)
    }
}
