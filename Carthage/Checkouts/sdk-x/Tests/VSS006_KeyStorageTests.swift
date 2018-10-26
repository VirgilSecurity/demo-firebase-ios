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
import XCTest
import VirgilCryptoApiImpl
import VirgilSDK

class VSS006_KeyStorageTests: XCTestCase {
    private var crypto: VirgilCrypto!
    private var storage: KeyStorage!
    private var keyEntry: KeyEntry!
    private var privateKeyName: String!
    
    // MARK: Setup
    override func setUp() {
        super.setUp()
        
        self.crypto = VirgilCrypto()
        self.storage = KeyStorage()
        let keyPair = try! self.crypto.generateKeyPair()
        
        let privateKeyRawData = self.crypto.exportPrivateKey(keyPair.privateKey)
        let privateKeyName = UUID().uuidString
        
        self.keyEntry = KeyEntry(name: privateKeyName, value: privateKeyRawData)
    }
    
    override func tearDown() {
        try? self.storage.deleteKeyEntry(withName: self.keyEntry.name)
        
        self.crypto = nil
        self.storage = nil
        self.keyEntry = nil
        self.privateKeyName = nil
        
        super.tearDown()
    }

    // MARK: Tests
    func test001_StoreKey() {
        try! self.storage.store(self.keyEntry)
    }
    
    func test002_StoreKeyWithDuplicateName() {
        try! self.storage.store(self.keyEntry)
    
        let keyPair = try! self.crypto.generateKeyPair()
        
        let privateKeyRawData = self.crypto.exportPrivateKey(keyPair.privateKey)
        let privateKeyName = self.keyEntry.name
        
        let keyEntry = KeyEntry(name: privateKeyName, value: privateKeyRawData)
        
        var errorWasThrown = false
        do {
            try self.storage.store(keyEntry)
        }
        catch {
            errorWasThrown = true
        }
        
        XCTAssert(errorWasThrown)
    }
    
    func test003_LoadKey() {
        try! self.storage.store(self.keyEntry)
        
        let loadedKeyEntry = try! self.storage.loadKeyEntry(withName: self.keyEntry.name)
    
        XCTAssert(loadedKeyEntry.name == self.keyEntry.name)
        XCTAssert(loadedKeyEntry.value == self.keyEntry.value)
    }
    
    func test004_ExistsKey() {
        var exists = self.storage.existsKeyEntry(withName: self.keyEntry.name)
        XCTAssert(!exists)
    
        try! self.storage.store(self.keyEntry)
    
        exists = self.storage.existsKeyEntry(withName: self.keyEntry.name)
    
        XCTAssert(exists);
    }
    
    func test005_DeleteKey() {
        try! self.storage.store(self.keyEntry)
        
        try! self.storage.deleteKeyEntry(withName: self.keyEntry.name)
    
        let exists = self.storage.existsKeyEntry(withName: self.keyEntry.name)
        
        XCTAssert(!exists);
    }
    
    func test006_UpdateKey() {
        try! self.storage.store(self.keyEntry)
        
        let keyPair = try! self.crypto.generateKeyPair()
        
        let privateKeyRawData = self.crypto.exportPrivateKey(keyPair.privateKey)
        let privateKeyName = self.keyEntry.name
        
        let keyEntry = KeyEntry(name: privateKeyName, value: privateKeyRawData)
        
        try! self.storage.update(keyEntry)
        
        let newKeyEntry = try! self.storage.loadKeyEntry(withName: privateKeyName)
        
        XCTAssert(newKeyEntry.name == privateKeyName)
        XCTAssert(newKeyEntry.value == privateKeyRawData)
    }
}
