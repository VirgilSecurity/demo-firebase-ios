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
import VirgilCrypto
import VirgilCryptoAPI

/// Class for high level interactions with crypto library
@objc(VSMVirgilCrypto) open class VirgilCrypto: NSObject {
    /// Key used to embed Data Signature into ASN.1 structure
    /// Used in signThenEncrypt & decryptThenVerify
    @objc public static let CustomParamKeySignature = "VIRGIL-DATA-SIGNATURE"
    /// Key used to embed signer identity into ASN.1 structure
    /// Used in signThenEncrypt & decryptThenVerify
    @objc public static let CustomParamKeySignerId = "VIRGIL-DATA-SIGNER-ID"

    /// Default key type used to generate keys.
    @objc public let defaultKeyType: VSCKeyType
    /// Use old algorithm to generate key fingerprints
    /// Current algorithm: first 8 bytes of SHA512 of public key in DER format
    /// Old algorithm: SHA256 of public key in DER format
    /// NOTE: Use SHA256 fingerprint only if you need to work with encrypted data,
    ///       that was encrypted using those fingerprint. (e.g. version 2 of this library)
    @objc public let useSHA256Fingerprints: Bool

    /// Initializer
    ///
    /// - Parameters:
    ///   - defaultKeyType: Key type used to generate keys by default
    ///   - useSHA256Fingerprints: Use old algorithm to generate key fingerprints
    ///                            Current algorithm: first 8 bytes of SHA512 of public key in DER format
    ///                            Old algorithm SHA256 of public key in DER format
    ///                            NOTE: Use SHA256 fingerprint only if you need to work with encrypted data,
    ///                                  that was encrypted using those fingerprint. (e.g. version 2 of this library)
    @objc public init(defaultKeyType: VSCKeyType = .FAST_EC_ED25519, useSHA256Fingerprints: Bool = false) {
        self.defaultKeyType = defaultKeyType
        self.useSHA256Fingerprints = useSHA256Fingerprints

        super.init()
    }

    /// Encrypts data for passed PublicKeys
    ///
    /// 1. Generates random AES-256 KEY1
    /// 2. Encrypts data with KEY1 using AES-256-GCM
    /// 3. Generates ephemeral key pair for each recipient
    /// 4. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key
    /// 5. Computes KDF to obtain AES-256 key from shared secret for each recipient
    /// 6. Encrypts KEY1 with this key using AES-256-CBC for each recipient
    ///
    /// - Parameters:
    ///   - data: Data to be encrypted
    ///   - recipients: Recipients
    /// - Returns: Encrypted data
    /// - Throws: Rethrows from Cipher class
    @objc open func encrypt(_ data: Data, for recipients: [VirgilPublicKey]) throws -> Data {
        let cipher = Cipher()

        try recipients.forEach {
            try cipher.addKeyRecipient($0.identifier, publicKey: $0.rawKey)
        }

        let encryptedData = try cipher.encryptData(data, embedContentInfo: true)

        return encryptedData
    }

    /// Encrypts data stream for passed PublicKeys
    ///
    /// 1. Generates random AES-256 KEY1
    /// 2. Encrypts data with KEY1 using AES-256-GCM
    /// 3. Generates ephemeral key pair for each recipient
    /// 4. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key
    /// 5. Computes KDF to obtain AES-256 key from shared secret for each recipient
    /// 6. Encrypts KEY1 with this key using AES-256-CBC for each recipient
    ///
    /// - Parameters:
    ///   - stream: data Stream to be encrypted
    ///   - outputStream: Stream with encrypted data
    ///   - recipients: Recipients
    /// - Throws: Rethrows from ChunkCipher
    @objc open func encrypt(_ stream: InputStream, to outputStream: OutputStream,
                            for recipients: [VirgilPublicKey]) throws {
        let cipher = ChunkCipher()

        try recipients.forEach {
            try cipher.addKeyRecipient($0.identifier, publicKey: $0.rawKey)
        }

        try cipher.encryptData(from: stream, to: outputStream)
    }

    /// Verifies digital signature of data
    ///
    /// Note: Verification algorithm depends on PublicKey type. Default: EdDSA
    ///
    /// - Parameters:
    ///   - signature: Digital signature
    ///   - data: Data that was signed
    ///   - publicKey: Signer public key
    /// - Returns: True if signature is verified, else - otherwise
    @objc open func verifySignature(_ signature: Data, of data: Data, with publicKey: VirgilPublicKey) -> Bool {
        let signer = Signer()

        do {
            try signer.verifySignature(signature, data: data, publicKey: publicKey.rawKey)
        }
        catch {
            return false
        }

        return true
    }

    /// Verifies digital signature of data stream
    ///
    /// Note: Verification algorithm depends on PublicKey type. Default: EdDSA
    ///
    /// - Parameters:
    ///   - signature: Digital signature
    ///   - stream: Data stream that was signed
    ///   - publicKey: Signed public key
    /// - Returns: True if signature is verified, else - otherwise
    @objc open func verifyStreamSignature(_ signature: Data, of stream: InputStream,
                                          with publicKey: VirgilPublicKey) -> Bool {
        let signer = StreamSigner()

        do {
            try signer.verifySignature(signature, from: stream, publicKey: publicKey.rawKey)
        }
        catch {
            return false
        }

        return true
    }

    /// Decrypts data using passed PrivateKey
    ///
    /// 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
    /// 2. Computes KDF to obtain AES-256 KEY2 from shared secret
    /// 3. Decrypts KEY1 using AES-256-CBC
    /// 4. Decrypts data using KEY1 and AES-256-GCM
    ///
    /// - Parameters:
    ///   - data: Encrypted data
    ///   - privateKey: Recipient's private key
    /// - Returns: Decrypted data
    /// - Throws: Rethrows from Cipher
    @objc open func decrypt(_ data: Data, with privateKey: VirgilPrivateKey) throws -> Data {
        let cipher = Cipher()

        return try cipher.decryptData(data, recipientId: privateKey.identifier,
                                      privateKey: privateKey.rawKey, keyPassword: nil)
    }

    /// Decrypts data stream using passed PrivateKey
    ///
    /// 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
    /// 2. Computes KDF to obtain AES-256 KEY2 from shared secret
    /// 3. Decrypts KEY1 using AES-256-CBC
    /// 4. Decrypts data using KEY1 and AES-256-GCM
    //
    /// - Parameters:
    ///   - stream: Stream with encrypted data
    ///   - outputStream: Stream with decrypted data
    ///   - privateKey: Recipient's private key
    /// - Throws: Rethrows from ChunkCipher
    @objc open func decrypt(_ stream: InputStream, to outputStream: OutputStream,
                            with privateKey: VirgilPrivateKey) throws {
        let cipher = ChunkCipher()

        try cipher.decrypt(from: stream, to: outputStream, recipientId: privateKey.identifier,
                           privateKey: privateKey.rawKey, keyPassword: nil)
    }

    /// Signs (with private key) Then Encrypts data for passed PublicKeys
    ///
    /// 1. Generates signature depending on KeyType
    /// 2. Generates random AES-256 KEY1
    /// 3. Encrypts both data and signature with KEY1 using AES-256-GCM
    /// 4. Generates ephemeral key pair for each recipient
    /// 5. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key
    /// 6. Computes KDF to obtain AES-256 key from shared secret for each recipient
    /// 7. Encrypts KEY1 with this key using AES-256-CBC for each recipient
    ///
    /// - Parameters:
    ///   - data: Data to be signedThenEncrypted
    ///   - privateKey: Sender private key
    ///   - recipients: Recipients' public keys
    /// - Returns: SignedThenEncrypted data
    /// - Throws: Rethrows from Signer and Cipher
    @objc open func signThenEncrypt(_ data: Data, with privateKey: VirgilPrivateKey,
                                    for recipients: [VirgilPublicKey]) throws -> Data {
        let signer = Signer(hash: kHashNameSHA512)

        let signature = try signer.sign(data, privateKey: privateKey.rawKey, keyPassword: nil)

        let cipher = Cipher()

        try cipher.setData(signature, forKey: VirgilCrypto.CustomParamKeySignature)

        let signerId = privateKey.identifier

        try cipher.setData(signerId, forKey: VirgilCrypto.CustomParamKeySignerId)

        try recipients.forEach {
            try cipher.addKeyRecipient($0.identifier, publicKey: $0.rawKey)
        }

        return try cipher.encryptData(data, embedContentInfo: true)
    }

    /// Decrypts (with private key) Then Verifies data using signer PublicKey
    ///
    /// 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
    /// 2. Computes KDF to obtain AES-256 KEY2 from shared secret
    /// 3. Decrypts KEY1 using AES-256-CBC
    /// 4. Decrypts both data and signature using KEY1 and AES-256-GCM
    /// 5. Verifies signature
    ///
    /// - Parameters:
    ///   - data: SignedThenEncrypted data
    ///   - privateKey: Receiver's private key
    ///   - signerPublicKey: Signer public key
    /// - Returns: DecryptedThenVerified data
    /// - Throws: Rethrows from Cipher and Signer
    @objc open func decryptThenVerify(_ data: Data, with privateKey: VirgilPrivateKey,
                                      using signerPublicKey: VirgilPublicKey) throws -> Data {
        let cipher = Cipher()

        let decryptedData = try cipher.decryptData(data, recipientId: privateKey.identifier,
                                                   privateKey: privateKey.rawKey, keyPassword: nil)
        let signature = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignature)

        let signer = Signer()

        try signer.verifySignature(signature, data: decryptedData, publicKey: signerPublicKey.rawKey)

        return decryptedData
    }

    /// Decrypts (with private key) Then Verifies data using any of signers' PublicKeys
    ///
    /// 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
    /// 2. Computes KDF to obtain AES-256 KEY2 from shared secret
    /// 3. Decrypts KEY1 using AES-256-CBC
    /// 4. Decrypts both data and signature using KEY1 and AES-256-GCM
    /// 5. Finds corresponding PublicKey according to signer id inside data
    /// 6. Verifies signature
    ///
    /// - Parameters:
    ///   - data: Signed Then Ecnrypted data
    ///   - privateKey: Receiver's private key
    ///   - signersPublicKeys: Array of possible signers public keys.
    ///                        WARNING: Data should have signature of ANY public key from array.
    /// - Returns: DecryptedThenVerified data
    /// - Throws: Rethrows from Cipher and Signer.
    ///           Throws VirgilCryptoError.signerNotFound if signer with such id is not found
    @objc open func decryptThenVerify(_ data: Data, with privateKey: VirgilPrivateKey,
                                      usingOneOf signersPublicKeys: [VirgilPublicKey]) throws -> Data {
        let cipher = Cipher()

        let decryptedData = try cipher.decryptData(data, recipientId: privateKey.identifier,
                                                   privateKey: privateKey.rawKey, keyPassword: nil)

        let signature = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignature)
        let signerId = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignerId)

        guard let signerPublicKey = signersPublicKeys.first(where: { $0.identifier == signerId }) else {
            throw VirgilCryptoError.signerNotFound
        }

        let signer = Signer()

        try signer.verifySignature(signature, data: decryptedData, publicKey: signerPublicKey.rawKey)

        return decryptedData
    }

    /// Generates digital signature of data using private key
    ///
    /// NOTE: Returned value contains only digital signature, not data itself.
    ///
    /// NOTE: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
    ///       It's secure to pass raw data here.
    ///
    /// - Parameters:
    ///   - data: Data to sign
    ///   - privateKey: Private key used to generate signature
    /// - Returns: Digital signature
    /// - Throws: Rethrows from Signer
    @objc open func generateSignature(of data: Data, using privateKey: VirgilPrivateKey) throws -> Data {
        let signer = Signer(hash: kHashNameSHA512)

        return try signer.sign(data, privateKey: privateKey.rawKey, keyPassword: nil)
    }

    /// Generates digital signature of data stream using private key
    ///
    /// NOTE: Returned value contains only digital signature, not data itself.
    ///
    /// NOTE: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
    ///       It's secure to pass raw data here.
    ///
    /// - Parameters:
    ///   - stream: Data stream to sign
    ///   - privateKey: Private key used to generate signature
    /// - Returns: Digital signature
    /// - Throws: Rethrows from StreamSigner
    @objc open func generateStreamSignature(of stream: InputStream,
                                            using privateKey: VirgilPrivateKey) throws -> Data {
        let signer = StreamSigner(hash: kHashNameSHA512)

        let signature = try signer.signStreamData(stream, privateKey: privateKey.rawKey, keyPassword: nil)

        return signature
    }

    /// Computes hash
    ///
    /// - Parameters:
    ///   - data: Data to be hashed
    ///   - algorithm: Hash algorithm to use
    /// - Returns: Hash value
    @objc open func computeHash(for data: Data, using algorithm: VSCHashAlgorithm) -> Data {
        let hash = Hash(algorithm: algorithm)

        return hash.hash(data)
    }
}
