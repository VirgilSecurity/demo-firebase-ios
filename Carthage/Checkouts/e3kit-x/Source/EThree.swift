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

/// Declares error types and codes for EThree
///
/// - verifierInitFailed: Initialization of VirgilCardVerifier failed
/// - keyIsNotVirgil: Casting Key to Virgil Key failed
/// - strToDataFailed: String to Data failed
/// - strFromDataFailed: Data to String failed
/// - missingKeys: missing Private or Public Keys
/// - passwordRequired: password required
/// - notBootstrapped: User was not bootstrapped
/// - missingIdentities: got empty array of identities to lookup for
@objc(VTEEThreeError) public enum EThreeError: Int, Error {
    case verifierInitFailed = 1
    case keyIsNotVirgil = 2
    case strToDataFailed = 3
    case strFromDataFailed = 4
    case missingKeys = 5
    case passwordRequired = 6
    case notBootstrapped = 7
    case missingIdentities = 8
}

@objc(VTEEThree) open class EThree: NSObject {
    /// Typealias for callback used below
    public typealias JwtStringCallback = (String?, Error?) -> Void
    /// Typealias for callback used below
    public typealias RenewJwtCallback = (@escaping JwtStringCallback) -> Void

    /// Identity of user. Obtained from tokenCollback
    @objc public let identity: String
    /// VirgilCrypto instance
    @objc public let crypto: VirgilCrypto
    /// CardManager instance
    @objc public let cardManager: CardManager

    internal let localKeyManager: LocalKeyManager
    internal let cloudKeyManager: CloudKeyManager
    internal let authManager: AuthManager

    internal init(identity: String, cardManager: CardManager) throws {
        self.identity = identity
        self.crypto = VirgilCrypto()
        self.cardManager = cardManager

        let storageParams = try KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: storageParams)

        self.localKeyManager = LocalKeyManager(identity: identity,
                                               crypto: self.crypto,
                                               keychainStorage: keychainStorage)

        self.cloudKeyManager = CloudKeyManager(identity: identity,
                                               accessTokenProvider: cardManager.accessTokenProvider,
                                               crypto: self.crypto,
                                               keychainStorage: keychainStorage)

        self.authManager = AuthManager(identity: identity,
                                       crypto: self.crypto,
                                       cardManager: cardManager,
                                       localKeyManager: self.localKeyManager,
                                       cloudKeyManager: self.cloudKeyManager)

        super.init()
    }
}
