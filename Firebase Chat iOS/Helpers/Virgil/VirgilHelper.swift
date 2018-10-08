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

    let identity: String
    let crypto: VirgilCrypto
    let keychainStorage: KeychainStorage
    let privateKeyExporter: PrivateKeyExporter
    private(set) var cardManager: CardManager

    private var historyKeyPair_: VirgilKeyPair?

    var historyKeyPair: VirgilKeyPair? {
        set {
            self.historyKeyPair_ = historyKeyPair
        }
        get {
            if self.historyKeyPair_ == nil {
                try? fetchHistoryKeyPair()
            }
            return self.historyKeyPair_
        }
    }
    var channelKey: VirgilPublicKey?

    func fetchHistoryKeyPair() throws {
        let keyEntry = try self.keychainStorage.retrieveEntry(withName: self.identity)

        let key = try self.privateKeyExporter.importPrivateKey(from: keyEntry.data)

        guard let historyKey = key as? VirgilPrivateKey else {
            throw VirgilHelperError.keyIsNotVirgil
        }
        let publicKey = try self.crypto.extractPublicKey(from: historyKey)

        self.historyKeyPair = VirgilKeyPair(privateKey: historyKey, publicKey: publicKey)
    }

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
    }

    public static func initialize(identity: String, tokenCallback: @escaping CachingJwtProvider.RenewJwtCallback) {
        let accessTokenProvider = CachingJwtProvider(renewTokenCallback: tokenCallback)
        let cardCrypto = VirgilCardCrypto()
        guard let verifier = VirgilCardVerifier(cardCrypto: cardCrypto) else {
            Log.error("VirgilCardVerifier init failed")
            return
        }
        let params = CardManagerParams(cardCrypto: cardCrypto,
                                       accessTokenProvider: accessTokenProvider,
                                       cardVerifier: verifier)
        let cardManager = CardManager(params: params)

        VirgilHelper.sharedInstance = VirgilHelper(identity: identity, cardManager: cardManager)
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
    }

    /// Encrypts given String
    ///
    /// - Parameter text: String to encrypt
    /// - Returns: encrypted String
    /// - Throws: error if fails
    func encrypt(_ text: String) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw VirgilHelperError.strToDataFailed
        }
        guard let channelKey = self.channelKey, let selfKey = self.historyKeyPair?.publicKey else {
            throw VirgilHelperError.missingKeys
        }

        return try self.crypto.encrypt(data, for: [channelKey, selfKey]).base64EncodedString()
    }

    /// Decrypts given String
    ///
    /// - Parameter encrypted: String to decrypt
    /// - Returns: decrypted String
    /// - Throws: error if fails
    func decrypt(_ encrypted: String) throws -> String {
        guard let privateKey = self.historyKeyPair?.privateKey,
            let data = Data(base64Encoded: encrypted)
            else {
                throw VirgilHelperError.strToDataFailed
        }
        let decryptedData = try self.crypto.decrypt(data, with: privateKey)

        guard let decrypted = String(data: decryptedData, encoding: .utf8) else {
            Log.error("Building string from data failed")
            throw VirgilHelperError.strFromDataFailed
        }

        return decrypted
    }

    /// Searches and sets Public Key to encrypt for
    ///
    /// - Parameters:
    ///   - identity: identity of user
    ///   - completion: completion handler, called with error if failed
    func setChannelKey(for identity: String, completion: @escaping (Error?) -> ()) {
        Log.debug("Searching cards with identity: \(identity)")

        cardManager.searchCards(identity: identity) { cards, error in
            guard error == nil, let cards = cards else {
                Log.error("Search self cards failed with error: \(error?.localizedDescription ?? "unknown error")")
                DispatchQueue.main.async {
                    completion(error)
                }
                return
            }

            let keys = cards.map { $0.publicKey }
            guard let virgilKeys = keys as? [VirgilPublicKey] else {
                Log.error("Converting keys to Virgil failed")
                DispatchQueue.main.async {
                    completion(VirgilHelperError.keyIsNotVirgil)
                }
                return
            }
            self.channelKey = virgilKeys.first

            DispatchQueue.main.async {
                completion(nil)
            }
        }
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

    /// Resets variables
    func reset() {
        self.historyKeyPair = nil
        self.channelKey = nil
    }
}
