//
//  VirgilHelper+Encryption.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 10/9/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import VirgilCryptoApiImpl

extension VirgilHelper {
    func lookupPublicKeys(of identities: [String], completion: @escaping ([VirgilPublicKey], [Error]) -> ()) {
        guard !identities.isEmpty else {
            completion([], [])
            return
        }

        let group = DispatchGroup()
        var result: [VirgilPublicKey] = []
        var errors: [Error] = []

        for identity in identities {
            group.enter()
            self.cardManager.searchCards(identity: identity) { cards, error in
                if let error = error {
                    errors.append(error)
                    return
                }
                guard let publicKey = cards?.first?.publicKey, let virgilPublicKey = publicKey as? VirgilPublicKey else {
                    errors.append(VirgilHelperError.keyIsNotVirgil)
                    return
                }

                result.append(virgilPublicKey)

                defer { group.leave() }
            }
        }

        group.notify(queue: .main) {
            completion(result, errors)
        }
    }

    /// Encrypts given String
    ///
    /// - Parameter text: String to encrypt
    /// - Returns: encrypted String
    /// - Throws: error if fails
    func encrypt(_ text: String, for publicKeys: [VirgilPublicKey]) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw VirgilHelperError.strToDataFailed
        }
        guard !publicKeys.isEmpty, let selfKey = self.identityKeyPair?.publicKey else {
            throw VirgilHelperError.missingKeys
        }

        return try self.crypto.encrypt(data, for: publicKeys + [selfKey]).base64EncodedString()
    }

    /// Decrypts given String
    ///
    /// - Parameter encrypted: String to decrypt
    /// - Returns: decrypted String
    /// - Throws: error if fails
    func decrypt(_ encrypted: String) throws -> String {
        guard let privateKey = self.identityKeyPair?.privateKey,
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
}
