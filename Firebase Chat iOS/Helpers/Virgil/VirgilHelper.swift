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

    struct IdentityKeyPair {
        let privateKey: VirgilPrivateKey
        let publicKey: VirgilPublicKey
        let isPublished: Bool
    }

    enum Keys: String {
        case isPublished
    }

    var identityKeyPair: IdentityKeyPair? {
        get {
            guard let keyEntry = try? self.keychainStorage.retrieveEntry(withName: self.identity),
                let key = try? self.privateKeyExporter.importPrivateKey(from: keyEntry.data),
                let meta = keyEntry.meta,
                let isPublished = meta[Keys.isPublished.rawValue]?.bool(),
                let identityKey = key as? VirgilPrivateKey,
                let publicKey = try? self.crypto.extractPublicKey(from: identityKey) else {
                    return nil
            }

            return IdentityKeyPair(privateKey: identityKey, publicKey: publicKey, isPublished: isPublished)
        }
    }

    enum VirgilHelperError: String, Error {
        case keyIsNotVirgil = "Converting Public or Private Key to Virgil one failed"
        case missingKeys = "Missing channel or self keys"
        case gettingJwtFailed = "Getting JWT failed"
        case strToDataFailed = "Converting utf8 string to data failed"
        case strFromDataFailed = "Building string from data failed"
        case verifierInitFailed = "VirgilCardVerifier initialization failed"
        case passwordRequired = "Password required"
        case entryExists = "Entry already exists"
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

            VirgilHelper.sharedInstance.bootstrapUser { error in
                completion(error)
            }
        }
    }

    private init(identity: String, cardManager: CardManager, crypto: VirgilCrypto? = nil,
                 privateKeyExporter: PrivateKeyExporter? = nil, keychainStorageParams: KeychainStorageParams? = nil) {
        self.identity = identity
        self.crypto = crypto ?? VirgilCrypto()
        let keychainStorageParams = try! KeychainStorageParams.makeKeychainStorageParams()
        self.keychainStorage = KeychainStorage(storageParams: keychainStorageParams)
        self.privateKeyExporter = privateKeyExporter ?? VirgilPrivateKeyExporter()
        self.cardManager = cardManager
    }

    func logout() throws {
        try self.keychainStorage.deleteEntry(withName: self.identity)
    }

    func storeLocal(data: Data, isPublished: Bool) throws {
        let meta = [Keys.isPublished.rawValue: String(isPublished)]
        _ = try self.keychainStorage.store(data: data, withName: self.identity, meta: meta)
    }

    func updateLocal(isPublished: Bool) throws {
        let meta = [Keys.isPublished.rawValue: String(isPublished)]
        let data = try self.keychainStorage.retrieveEntry(withName: self.identity).data
        try self.keychainStorage.updateEntry(withName: self.identity, data: data, meta: meta)
    }

    func publishCardThenUpdateLocal(keyPair: VirgilKeyPair, completion: @escaping (Error?) -> ()) {
        self.cardManager.publishCard(privateKey: keyPair.privateKey, publicKey: keyPair.publicKey, identity: self.identity)
        { cards, error in
            guard error == nil else {
                completion(error)
                return
            }

            do {
                try self.updateLocal(isPublished: true)
                completion(nil)
            } catch {
                completion(error)
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
}
