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
import VirgilCryptoApiImpl
import VirgilCrypto

/// Declares error types and codes for KeyknoxCrypto
///
/// - signerNotFound: Data signer is not present in PublicKeys array
/// - signatureVerificationFailed: Signature is not verified
/// - decryptionFailed: Decryption failed
/// - emptyPublicKeysList: Public keys list is empty
/// - emptyData: Trying to encrypt empty data
@objc(VSKKeyknoxCryptoError) public enum KeyknoxCryptoError: Int, Error {
    case signerNotFound = 1
    case signatureVerificationFailed = 2
    case decryptionFailed = 3
    case emptyPublicKeysList = 4
    case emptyData = 5
}

/// KeyknoxCryptoProtocol implementation using VirgilCrypto
open class KeyknoxCrypto {
    /// VirgilCrypto
    public let crypto: VirgilCrypto

    /// Init
    ///
    /// - Parameter crypto: VirgilCrypto instance
    public init(crypto: VirgilCrypto = VirgilCrypto()) {
        self.crypto = crypto
    }
}

// MARK: - KeyknoxCryptoProtocol implementation
extension KeyknoxCrypto: KeyknoxCryptoProtocol {
    /// Decrypts EncryptedKeyknoxValue
    ///
    /// - Parameters:
    ///   - encryptedKeyknoxValue: encrypted value from Keyknox service
    ///   - privateKey: private key to decrypt data. Should be of type VirgilPrivateKey
    ///   - publicKeys: allowed public keys to verify signature. Should be of type VirgilPublicKey
    /// - Returns: DecryptedKeyknoxValue
    /// - Throws: VirgilCryptoError.passedKeyIsNotVirgil if passed keys have wrong type
    ///           KeyknoxManagerError.decryptionFailed if decryption failed
    ///           KeyknoxManagerError.signerNotFound if data signer is not present in PublicKeys array
    ///           KeyknoxManagerError.signatureVerificationFailed signature is not verified
    ///           Rethrows from Cipher
    open func decrypt(encryptedKeyknoxValue: EncryptedKeyknoxValue, privateKey: PrivateKey,
                      publicKeys: [PublicKey]) throws -> DecryptedKeyknoxValue {
        if encryptedKeyknoxValue.value.isEmpty && encryptedKeyknoxValue.meta.isEmpty {
            return DecryptedKeyknoxValue(meta: Data(),
                                         value: Data(),
                                         version: encryptedKeyknoxValue.version,
                                         keyknoxHash: encryptedKeyknoxValue.keyknoxHash)
        }

        guard let virgilPrivateKey = privateKey as? VirgilPrivateKey,
            let virgilPublicKeys = publicKeys as? [VirgilPublicKey] else {
                throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        let cipher = Cipher()
        try cipher.setContentInfo(encryptedKeyknoxValue.meta)
        let privateKeyData = self.crypto.exportPrivateKey(virgilPrivateKey)
        let decryptedData: Data
        do {
            decryptedData = try cipher.decryptData(encryptedKeyknoxValue.value,
                                                   recipientId: virgilPrivateKey.identifier,
                                                   privateKey: privateKeyData, keyPassword: nil)
        }
        catch {
            throw KeyknoxCryptoError.decryptionFailed
        }

        let meta = try cipher.contentInfo()

        let signedId = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignerId)
        let signature = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignature)

        let signer = Signer(hash: kHashNameSHA512)

        guard let publicKey = virgilPublicKeys.first(where: { $0.identifier == signedId }) else {
            throw KeyknoxCryptoError.signerNotFound
        }

        let publicKeyData = self.crypto.exportPublicKey(publicKey)

        do {
            try signer.verifySignature(signature, data: decryptedData, publicKey: publicKeyData)
        }
        catch {
            throw KeyknoxCryptoError.signatureVerificationFailed
        }

        return DecryptedKeyknoxValue(meta: meta, value: decryptedData,
                                     version: encryptedKeyknoxValue.version,
                                     keyknoxHash: encryptedKeyknoxValue.keyknoxHash)
    }

    /// Encrypts data for Keyknox
    ///
    /// - Parameters:
    ///   - data: Data to encrypt
    ///   - privateKey: Private key to sign data. Should be of type VirgilPrivateKey
    ///   - publicKeys: Public keys to encrypt data. Should be of type VirgilPublicKey
    /// - Returns: Meta information and encrypted blob
    /// - Throws: VirgilCryptoError.passedKeyIsNotVirgil if passed keys have wrong type
    ///           KeyknoxCryptoError.emptyPublicKeysList is public keys list is empty
    ///           KeyknoxCryptoError.emptyData if data if empty
    ///           Rethrows from Cipher, Signer
    open func encrypt(data: Data, privateKey: PrivateKey, publicKeys: [PublicKey]) throws -> (Data, Data) {
        guard let virgilPrivateKey = privateKey as? VirgilPrivateKey,
            let virgilPublicKeys = publicKeys as? [VirgilPublicKey] else {
                throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        guard !virgilPublicKeys.isEmpty else {
            throw KeyknoxCryptoError.emptyPublicKeysList
        }

        guard !data.isEmpty else {
            throw KeyknoxCryptoError.emptyData
        }

        let signer = Signer(hash: kHashNameSHA512)
        let privateKeyData = self.crypto.exportPrivateKey(virgilPrivateKey)
        let signature = try signer.sign(data, privateKey: privateKeyData, keyPassword: nil)

        let cipher = Cipher()
        try cipher.setData(virgilPrivateKey.identifier, forKey: VirgilCrypto.CustomParamKeySignerId)
        try cipher.setData(signature, forKey: VirgilCrypto.CustomParamKeySignature)
        try virgilPublicKeys
            .map { return ($0.identifier, self.crypto.exportPublicKey($0)) }
            .forEach { try cipher.addKeyRecipient($0, publicKey: $1) }
        let encryptedData = try cipher.encryptData(data, embedContentInfo: false)
        let meta = try cipher.contentInfo()

        return (meta, encryptedData)
    }
}
