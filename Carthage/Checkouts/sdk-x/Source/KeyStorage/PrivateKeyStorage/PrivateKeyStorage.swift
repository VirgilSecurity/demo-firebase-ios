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

/// Class responsible for storing Private Keys
@objc(VSSPrivateKeyStorage) open class PrivateKeyStorage: NSObject {
    /// Instance for storing, loading, deleting KeyEntries
    @objc public let keyStorage: KeyStorage
    /// PrivateKeyExporter implementation instance for import/export PrivateKey
    @objc public let privateKeyExporter: PrivateKeyExporter

    /// PrivateKeyStorage initializer
    ///
    /// - Parameters:
    ///   - privateKeyExporter: PrivateKeyExporter to use it for import/export stored Private Keys
    ///   - keyStorage: keychain key storage
    @objc public init(privateKeyExporter: PrivateKeyExporter, keyStorage: KeyStorage = KeyStorage()) {
        self.privateKeyExporter = privateKeyExporter
        self.keyStorage = keyStorage

        super.init()
    }

    /// Stores Private Key with meta
    ///
    /// - Parameters:
    ///   - privateKey: PrivateKey to store
    ///   - name: identifier for loading key back
    ///   - meta: Dictionary with any meta data
    /// - Throws: Rethrows from PrivateKeyExporter, KeyStorage
    @objc public func store(privateKey: PrivateKey, name: String, meta: [String: String]?) throws {
        let privateKeyInstance = try self.privateKeyExporter.exportPrivateKey(privateKey: privateKey)
        let keyEntry = KeyEntry(name: name, value: privateKeyInstance, meta: meta)

        try self.keyStorage.store(keyEntry)
    }

    /// Loads `PrivateKeyEntry` with imported Private Key and meta
    ///
    /// - Parameter name: stored entry name
    /// - Returns: `PrivateKeyEntry` with imported Private Key and meta
    /// - Throws: Rethrows from PrivateKeyExporter, KeyStorage
    @objc public func load(withName name: String) throws -> PrivateKeyEntry {
        let keyEntry = try self.keyStorage.loadKeyEntry(withName: name)
        let privateKey = try self.privateKeyExporter.importPrivateKey(from: keyEntry.value)
        let meta = keyEntry.meta

        return PrivateKeyEntry(privateKey: privateKey, meta: meta)
    }

    /// Checks whether key entry with given name exists
    ///
    /// - Parameter name: stored entry name
    /// - Returns: true if entry with this name exists, false otherwise
    @objc public func exists(withName name: String) -> Bool {
        return self.keyStorage.existsKeyEntry(withName: name)
    }

    /// Removes key entry with given name
    ///
    /// - Parameter name: key entry name to delete
    /// - Throws: Rethrows from KeyStorage
    @objc public func delete(withName name: String) throws {
        try self.keyStorage.deleteKeyEntry(withName: name)
    }
}
