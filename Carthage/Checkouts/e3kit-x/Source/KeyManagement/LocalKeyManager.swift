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

import VirgilCryptoApiImpl
import VirgilSDK

internal struct IdentityKeyPair {
    internal let privateKey: VirgilPrivateKey
    internal let publicKey: VirgilPublicKey
    internal let isPublished: Bool
}

internal class LocalKeyManager {
    internal let identity: String
    internal let keychainStorage: KeychainStorage
    internal let crypto: VirgilCrypto

    internal enum Keys: String {
        case isPublished = "isPublished"
    }

    internal init(identity: String, crypto: VirgilCrypto, keychainStorage: KeychainStorage) {
        self.identity = identity
        self.crypto = crypto
        self.keychainStorage = keychainStorage
    }

    internal func retrieveKeyPair() -> IdentityKeyPair? {
        guard let keyEntry = try? self.keychainStorage.retrieveEntry(withName: self.identity),
            let identityKey = try? self.crypto.importPrivateKey(from: keyEntry.data),
            let meta = keyEntry.meta,
            let isPublishedString = meta[Keys.isPublished.rawValue],
            let publicKey = try? self.crypto.extractPublicKey(from: identityKey) else {
                return nil
        }
        let isPublished = NSString(string: isPublishedString).boolValue

        return IdentityKeyPair(privateKey: identityKey, publicKey: publicKey, isPublished: isPublished)
    }

    internal func store(data: Data, isPublished: Bool) throws {
        let meta = [Keys.isPublished.rawValue: String(isPublished)]
        _ = try self.keychainStorage.store(data: data, withName: self.identity, meta: meta)
    }

    internal func update(isPublished: Bool) throws {
        let meta = [Keys.isPublished.rawValue: String(isPublished)]
        let data = try self.keychainStorage.retrieveEntry(withName: self.identity).data
        try self.keychainStorage.updateEntry(withName: self.identity, data: data, meta: meta)
    }

    internal func delete() throws {
        try self.keychainStorage.deleteEntry(withName: self.identity)
    }
}
