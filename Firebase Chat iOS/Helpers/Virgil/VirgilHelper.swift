//
//  VirgilHelper.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/13/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import VirgilSDK
import VirgilCryptoApiImpl
import VirgilCryptoAPI

/// Provides usage of VirgilSDK and VirgilCrypto
class VirgilHelper {
    static private(set) var sharedInstance: VirgilHelper!

    /// Typealias for callback used below
    public typealias JwtStringCallback = (String?, Error?) -> Void
    /// Typealias for callback used below
    public typealias RenewJwtCallback = (@escaping JwtStringCallback) -> Void

    let identity: String
    let crypto: VirgilCrypto
    let keychainStorage: KeychainStorage
    let privateKeyExporter: PrivateKeyExporter
    let cardManager: CardManager

    private var historyKeyPair_: VirgilKeyPair?

    var historyKeyPair: VirgilKeyPair? {
        set {
            self.historyKeyPair_ = newValue
        }
        get {
            if self.historyKeyPair_ == nil {
                try? fetchHistoryKeyPair()
            }
            return self.historyKeyPair_
        }
    }
    var sessionKeys: [VirgilPublicKey]

    /// Declares error types and codes
    ///
    /// - keyIsNotVirgil: Converting Public or Private Key to Virgil one failed
    /// - gettingJwtFailed: Failed getting Jwt from server
    /// - strToDataFailed: Converting utf8 string to data failed
    /// - strFromDataFailed: Building string from data failed
    enum VirgilHelperError: String, Error {
        case keyIsNotVirgil = "Converting Public or Private Key to Virgil one failed"
        case missingKeys = "Missing channel or self keys"
        case gettingJwtFailed = "Getting JWT failed"
        case strToDataFailed = "Converting utf8 string to data failed"
        case strFromDataFailed = "Building string from data failed"
        case verifierInitFailed = "VirgilCardVerifier initialization failed"
    }

    public static func initialize(tokenCallback: @escaping VirgilHelper.RenewJwtCallback, completion: @escaping (Error?) -> ()) {
        let renewTokenCallback: CachingJwtProvider.RenewJwtCallback = { _, completion in
            tokenCallback(completion)
        }
        let accessTokenProvider = CachingJwtProvider(renewTokenCallback: renewTokenCallback)
        let tokenContext = TokenContext(service: "cards", operation: "publish")
        accessTokenProvider.getToken(with: tokenContext) { token, error in
            guard let identity = token?.identity(), error == nil else {
                completion(VirgilHelperError.gettingJwtFailed)
                return
            }

            let cardCrypto = VirgilCardCrypto()
            guard let verifier = VirgilCardVerifier(cardCrypto: cardCrypto) else {
                completion(VirgilHelperError.verifierInitFailed)
                return
            }
            let params = CardManagerParams(cardCrypto: cardCrypto,
                                           accessTokenProvider: accessTokenProvider,
                                           cardVerifier: verifier)
            let cardManager = CardManager(params: params)

            VirgilHelper.sharedInstance = VirgilHelper(identity: identity, cardManager: cardManager)

            completion(nil)
        }
    }

    /// Initializer
    private init(identity: String, cardManager: CardManager, crypto: VirgilCrypto? = nil,
                 privateKeyExporter: PrivateKeyExporter? = nil, keychainStorageParams: KeychainStorageParams? = nil) {
        self.identity = identity
        self.crypto = crypto ?? VirgilCrypto()
        self.privateKeyExporter = privateKeyExporter ?? VirgilPrivateKeyExporter()
        let keychainStorageParams = try! keychainStorageParams ?? KeychainStorageParams.makeKeychainStorageParams()
        self.keychainStorage = KeychainStorage(storageParams: keychainStorageParams)
        self.cardManager = cardManager
        self.sessionKeys = []
    }

    func fetchHistoryKeyPair() throws {
        let keyEntry = try self.keychainStorage.retrieveEntry(withName: self.identity)

        let key = try self.privateKeyExporter.importPrivateKey(from: keyEntry.data)

        guard let historyKey = key as? VirgilPrivateKey else {
            throw VirgilHelperError.keyIsNotVirgil
        }
        let publicKey = try self.crypto.extractPublicKey(from: historyKey)

        self.historyKeyPair = VirgilKeyPair(privateKey: historyKey, publicKey: publicKey)
    }

    func logout() throws {
        self.closeSession()
        self.historyKeyPair = nil
        try self.keychainStorage.deleteEntry(withName: self.identity)
    }

    /// Makes SHA256 hash
    ///
    /// - Parameter string: String, from which to make hash
    /// - Returns: hex encoded String with SHA256 hash
    func makeHash(from string: String) -> String? {
        guard let data = string.data(using: .utf8) else {
            Log.error("String to data failed")
            return nil
        }
        return self.crypto.computeHash(for: data, using: .SHA256).hexEncodedString()
    }
}
