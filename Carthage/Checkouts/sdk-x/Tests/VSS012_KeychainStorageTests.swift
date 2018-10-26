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

class VSS012_KeychainStorageTests: XCTestCase {
    private var storage: KeychainStorage!
    
    // MARK: Setup
    override func setUp() {
        super.setUp()

    #if os(iOS) || os(tvOS) || os(watchOS)
        let storageParams = try! KeychainStorageParams.makeKeychainStorageParams()
    #elseif os(macOS)
        let storageParams = KeychainStorageParams(appName: "test", trustedApplications: [])
    #endif

        self.storage = KeychainStorage(storageParams: storageParams)
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    // MARK: Tests
    func test001_StoreEntry() {
        let data = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        
        let keychainEntry = try! self.storage.store(data: data, withName: name, meta: nil)
        
        XCTAssert(keychainEntry.name == name)
        XCTAssert(keychainEntry.data == data)
        let eps: TimeInterval = 1
        XCTAssert(abs(keychainEntry.creationDate.timeIntervalSince1970 - Date().timeIntervalSince1970) < eps)
        XCTAssert(abs(keychainEntry.modificationDate.timeIntervalSince1970 - Date().timeIntervalSince1970) < eps)
        XCTAssert(keychainEntry.meta == nil)
    }
    
    func test002_RetrieveEntry() {
        let data = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        
        let keychainEntry = try! self.storage.store(data: data, withName: name, meta: nil)
        
        let retrievedEntry = try! self.storage.retrieveEntry(withName: name)
        
        XCTAssert(retrievedEntry == keychainEntry)
    }
    
    func test003_RetrieveAllEntries() {
        let keychainEntries1 = try! self.storage.retrieveAllEntries()
        
        let data = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        
        let newEntry = try! self.storage.store(data: data, withName: name, meta: nil)
        
        let keychainEntries2 = try! self.storage.retrieveAllEntries()
        
        XCTAssert(keychainEntries2.count - keychainEntries1.count == 1)
        
        keychainEntries2.forEach { entry in
            let foundKeys = keychainEntries1.filter {
                $0.name == entry.name
            }
            
            if foundKeys.count == 1 {
                XCTAssert(foundKeys[0] == entry)
            }
            else {
                XCTAssert(entry == newEntry)
            }
        }
    }
    
    func test004_DeleteEntries() {
        let data = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        
        let _ = try! self.storage.store(data: data, withName: name, meta: nil)
        
        try! self.storage.deleteEntry(withName: name)
        
        var errorWasThrown = false
        do {
            let _ = try self.storage.retrieveEntry(withName: name)
        }
        catch(let error as KeychainStorageError) {
            errorWasThrown = true
            XCTAssert(error.errCode == .keychainError)
            XCTAssert(error.osStatus! == -25300)
        }
        catch {
            XCTFail()
        }
        
        XCTAssert(errorWasThrown)
    }
    
    func test005_StoreEntryWithMeta() {
        let data = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        let meta = [
            "test_key": "test_value"
        ]
        
        let keychainEntry = try! self.storage.store(data: data, withName: name, meta: meta)
        
        XCTAssert(keychainEntry.name == name)
        XCTAssert(keychainEntry.data == data)
        let eps: TimeInterval = 1
        XCTAssert(abs(keychainEntry.creationDate.timeIntervalSince1970 - Date().timeIntervalSince1970) < eps)
        XCTAssert(abs(keychainEntry.modificationDate.timeIntervalSince1970 - Date().timeIntervalSince1970) < eps)
        XCTAssert(keychainEntry.meta == meta)
    }
    
    func test006_UpdateEntry() {
        let data1 = NSUUID().uuidString.data(using: .utf8)!
        let data2 = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        
        let keychainEntry1 = try! self.storage.store(data: data1, withName: name, meta: nil)
        
        try! self.storage.updateEntry(withName: name, data: data2, meta: nil)
        
        let keychainEntry2 = try! self.storage.retrieveEntry(withName: name)
        
        let waitTime: TimeInterval = 2
        sleep(UInt32(waitTime))
        
        XCTAssert(keychainEntry2.name == name)
        XCTAssert(keychainEntry2.data == data2)
        XCTAssert(keychainEntry2.meta == nil)
        XCTAssert(keychainEntry2.creationDate == keychainEntry1.creationDate)
        let eps: TimeInterval = 1
        XCTAssert((keychainEntry2.modificationDate.timeIntervalSince1970 - keychainEntry2.creationDate.timeIntervalSince1970 - waitTime) < eps)
    }
    
    func test007_DeleteAllEntries() {
        let data = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        
        let _ = try! self.storage.store(data: data, withName: name, meta: nil)
        
        try! self.storage.deleteAllEntries()
        XCTAssert(try! self.storage.retrieveAllEntries().count == 0)        
    }
    
    func test008_ExistsEntry() {
        let data = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        
        XCTAssert(!(try! self.storage.existsEntry(withName: name)))
        let _ = try! self.storage.store(data: data, withName: name, meta: nil)
        XCTAssert((try! self.storage.existsEntry(withName: name)))
        
        try! self.storage.deleteEntry(withName: name)
        XCTAssert(!(try! self.storage.existsEntry(withName: name)))
    }
}
