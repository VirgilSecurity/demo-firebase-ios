//
//  VirgilHelper+Sessions.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 10/9/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import VirgilCryptoApiImpl

extension VirgilHelper {
    /// Searches and sets Public Key to encrypt for
    ///
    /// - Parameters:
    ///   - identity: identity of user
    ///   - completion: completion handler, called with error if failed
    func startSession(with identities: [String], completion: @escaping (Error?) -> ()) {
        self.closeSession()

        for identity in identities {
            Log.debug("Searching cards with identity: \(identity)")

            cardManager.searchCards(identity: identity) { cards, error in
                guard error == nil, let cards = cards else {
                    completion(error)
                    return
                }

                let keys = cards.map { $0.publicKey }
                guard let virgilKeys = keys as? [VirgilPublicKey] else {
                    completion(VirgilHelperError.keyIsNotVirgil)
                    return
                }
                self.sessionKeys = self.sessionKeys + virgilKeys

                completion(nil)
            }
        }
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
        guard !self.sessionKeys.isEmpty, let selfKey = self.historyKeyPair?.publicKey else {
            throw VirgilHelperError.missingKeys
        }

        return try self.crypto.encrypt(data, for: self.sessionKeys + [selfKey]).base64EncodedString()
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
            throw VirgilHelperError.strFromDataFailed
        }

        return decrypted
    }

    func closeSession() {
        self.sessionKeys = []
    }
}
