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
import VirgilSDK
import XCTest
import VirgilCryptoApiImpl

class VSS007_KeyStorageiOSSpecificTests: XCTestCase {
    private var crypto: VirgilCrypto!
    private var storage: KeyStorage!
    private let numberOfKeys = 10
    
    // MARK: Setup
    override func setUp() {
        super.setUp()
        
        self.crypto = VirgilCrypto()
        self.storage = KeyStorage()
    }
    
    override func tearDown() {
        self.crypto = nil
        self.storage = nil
        
        super.tearDown()
    }
    
    func test001_AddMultiple() {
        var keyEntries = Array<KeyEntry>()
        for _ in 0..<self.numberOfKeys {
            let keyPair = try! self.crypto.generateKeyPair()
            
            let privateKeyRawData = self.crypto.exportPrivateKey(keyPair.privateKey)
            let privateKeyName = UUID().uuidString
            
            keyEntries.append(KeyEntry(name: privateKeyName, value: privateKeyRawData))
        }
        
        try! self.storage.storeKeyEntries(keyEntries)
        
        for entry in keyEntries {
            let loadedEntry = try! self.storage.loadKeyEntry(withName: entry.name)
            
            XCTAssert(loadedEntry.name == entry.name)
            XCTAssert(loadedEntry.value == entry.value)
        }
    }

    func test002_DeleteMultiple() {
        var names = Array<String>()
        for _ in 0..<self.numberOfKeys {
            let keyPair = try! self.crypto.generateKeyPair()
            
            let privateKeyRawData = self.crypto.exportPrivateKey(keyPair.privateKey)
            let privateKeyName = UUID().uuidString
            names.append(privateKeyName)
            
            let keyEntry = KeyEntry(name: privateKeyName, value: privateKeyRawData)
            
            try! self.storage.store(keyEntry)
        }
        
        try! self.storage.deleteKeyEntries(withNames: names)
        
        for name in names {
            var errorWasThrown = false
            do {
                try self.storage.loadKeyEntry(withName: name)
            }
            catch {
                errorWasThrown = true
            }
            
            XCTAssert(errorWasThrown)
        }
    }
    
    func test003_GetAllKeys() {
        let keys0 = try! self.storage.getAllKeys()
        
        for _ in 0..<self.numberOfKeys {
            let keyPair = try! self.crypto.generateKeyPair()
            
            let privateKeyRawData = self.crypto.exportPrivateKey(keyPair.privateKey)
            let privateKeyName = UUID().uuidString
            
            let keyEntry = KeyEntry(name: privateKeyName, value: privateKeyRawData)
            
            try! self.storage.store(keyEntry)
        }
        
        let keys1 = try! self.storage.getAllKeys()
        
        XCTAssert(keys1.count == keys0.count + self.numberOfKeys)
        
        for (k1, k2) in zip(keys0, Array(keys1.dropLast(self.numberOfKeys))) {
            XCTAssert(k1.name == k2.name)
            XCTAssert(k1.value == k2.value)
        }
    }
    
    func test004_GetAllKeysAttrs() {
        let keys0 = try! self.storage.getAllKeysAttrs()
        
        var keysInfo = Array<(String, Date)>()
        for _ in 0..<self.numberOfKeys {
            let keyPair = try! self.crypto.generateKeyPair()
            
            let privateKeyRawData = self.crypto.exportPrivateKey(keyPair.privateKey)
            let privateKeyName = UUID().uuidString
            
            keysInfo.append((privateKeyName, Date()))
            
            let keyEntry = KeyEntry(name: privateKeyName, value: privateKeyRawData)
            
            try! self.storage.store(keyEntry)
        }
        
        let keys1 = try! self.storage.getAllKeysAttrs()
        
        XCTAssert(keys1.count == keys0.count + keysInfo.count)
        
        let newKeysAttrs = keys1
            .filter({ !keys0.map({ $0.name }).contains($0.name) })
            .sorted(by: { $0.creationDate < $1.creationDate })
        XCTAssert(newKeysAttrs.count == keysInfo.count)
        
        let eps: TimeInterval = 1
        for elem in zip(newKeysAttrs, keysInfo) {
            XCTAssert(elem.0.name == elem.1.0)
            
            let diff = abs(elem.0.creationDate.timeIntervalSince1970 - elem.1.1.timeIntervalSince1970)
            XCTAssert(diff < eps)
        }
    }
    
    func test005_Reset() {
        var keyEntries = Array<KeyEntry>()
        for _ in 0..<self.numberOfKeys {
            let keyPair = try! self.crypto.generateKeyPair()
            
            let privateKeyRawData = self.crypto.exportPrivateKey(keyPair.privateKey)
            let privateKeyName = UUID().uuidString
            
            keyEntries.append(KeyEntry(name: privateKeyName, value: privateKeyRawData))
        }
        
        try! self.storage.storeKeyEntries(keyEntries)
        
        XCTAssert((try! self.storage.getAllKeysAttrs()).count != 0)
        
        try! self.storage.reset()
        
        XCTAssert((try! self.storage.getAllKeysAttrs()).count == 0)
    }
}
