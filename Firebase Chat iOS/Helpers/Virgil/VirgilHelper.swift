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

/// Provides usage of VirgilSDK and VirgilCrypto
class VirgilHelper {
    static let sharedInstance = VirgilHelper()
    let crypto: VirgilCrypto
    let keyStorage: PrivateKeyStorage
    let connection: ServiceConnection

    var cardManager: CardManager?
    var privateKey: VirgilPrivateKey?
    var channelKeys: [VirgilPublicKey] = []
    var selfKeys: [VirgilPublicKey] = []
    var cashedJwt: String?

    /// URL to your cloud function for getting JWT
    /// - Important: change it to your own from [Firebase Console](https://console.firebase.google.com)
    let jwtEndpoint = "https://us-central1-fir-chat-ios-2c1d0.cloudfunctions.net/api/generate_jwt"

    /// Initializer
    private init() {
        self.crypto = VirgilCrypto()
        self.keyStorage = PrivateKeyStorage(privateKeyExporter: VirgilPrivateKeyExporter())
        self.connection = ServiceConnection()
        self.cardManager = nil
    }

    /// Encrypts given String
    ///
    /// - Parameter text: String to encrypt
    /// - Returns: encrypted String
    /// - Throws: error if fails
    func encrypt(_ text: String) throws -> String {
        guard let data = text.data(using: .utf8)
            else {
                Log.error("Encrypting failed")
                throw NSError()
        }

        return try self.crypto.encrypt(data, for: self.channelKeys + self.selfKeys).base64EncodedString()
    }

    /// Decrypts given String
    ///
    /// - Parameter encrypted: String to decrypt
    /// - Returns: decrypted String
    /// - Throws: error if fails
    func decrypt(_ encrypted: String) throws -> String {
        guard let privateKey = self.privateKey,
            let data = Data(base64Encoded: encrypted)
            else {
                Log.error("Decrypting failed")
                throw NSError()
        }
        let decryptedData = try self.crypto.decrypt(data, with: privateKey)

        guard let decrypted = String(data: decryptedData, encoding: .utf8) else {
            Log.error("Building string from data failed")
            throw NSError()
        }

        return decrypted
    }

    /// Searches and sets Public Keys to encrypt for
    ///
    /// - Parameters:
    ///   - identity: identity of user
    ///   - completion: completion handler, called with error if failed
    func setChannelKeys(for identity: String, completion: @escaping (Error?) -> ()) {
        Log.debug("Searching cards with identity: \(identity)")
        guard let cardManager = self.cardManager else {
            Log.error("Missing CardManager")
            DispatchQueue.main.async {
                completion(NSError())
            }
            return
        }

        self.channelKeys = []

        cardManager.searchCards(identity: identity) { cards, error in
            guard error == nil, let cards = cards else {
                Log.error("Search self cards failed with error: \(error?.localizedDescription ?? "unknown error")")
                DispatchQueue.main.async {
                    completion(NSError())
                }
                return
            }
            let keys = cards.map { $0.publicKey }
            guard let virgilKeys = keys as? [VirgilPublicKey] else {
                Log.error("Converting keys to Virgil failed")
                DispatchQueue.main.async {
                    completion(NSError())
                }
                return
            }
            self.channelKeys = virgilKeys

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
            Log.error("string to data failed")
            return nil
        }
        return self.crypto.computeHash(for: data, using: .SHA256).hexEncodedString()
    }

    /// Resets variables
    func reset() {
        self.privateKey = nil
        self.cashedJwt = nil
        self.channelKeys = []
        self.selfKeys = []
    }
}
