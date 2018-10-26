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
@testable import VirgilSDKKeyknox
import VirgilSDK
import XCTest

class VSK007_KeyStorageWrapperTests: XCTestCase {
    private var keychainStorageWrapper: KeychainStorageProtocol!
    private var keychainStorage: KeychainStorage!
    
    override func setUp() {
        super.setUp()
        
    #if os(macOS)
        let params = KeychainStorageParams(appName: "Tests", trustedApplications: [])
    #elseif os(iOS) || os(tvOS)
        let params = try! KeychainStorageParams.makeKeychainStorageParams()
    #endif
        self.keychainStorage = KeychainStorage(storageParams: params)
        try! self.keychainStorage.deleteAllEntries()
        
        self.keychainStorageWrapper = KeychainStorageWrapper(identity: "identity", keychainStorage: self.keychainStorage)
    }
    
    func test001() {
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 0)
        XCTAssert(try! self.keychainStorage.retrieveAllEntries().count == 0)
        
        let name = NSUUID().uuidString
        let wrapperName = "VIRGIL.IDENTITY=identity.\(name)"
        let data1 = NSUUID().uuidString.data(using: .utf8)!
        let data2 = NSUUID().uuidString.data(using: .utf8)!

        _ = try! self.keychainStorageWrapper.store(data: data1, withName: name, meta: nil)
        
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 1)
        XCTAssert(try! self.keychainStorage.retrieveAllEntries().count == 1)
        
        let entry1 = try! self.keychainStorageWrapper.retrieveEntry(withName: name)
        XCTAssert(entry1.name == name)
        XCTAssert(entry1.data == data1)
        
        _ = try! self.keychainStorage.store(data: data2, withName: name, meta: nil)
        
        let wrappedEntries = try! self.keychainStorageWrapper.retrieveAllEntries()
        XCTAssert(wrappedEntries.count == 1)
        XCTAssert(wrappedEntries[0].name == name)
        XCTAssert(wrappedEntries[0].data == data1)
        
        let entries = try! self.keychainStorage.retrieveAllEntries()
        XCTAssert(entries.count == 2)
        XCTAssert(entries[1].name == name)
        XCTAssert(entries[1].data == data2)
        XCTAssert(entries[0].name == wrapperName)
        XCTAssert(entries[0].data == data1)
        
        let entry2 = try! self.keychainStorageWrapper.retrieveEntry(withName: name)
        XCTAssert(entry2.name == name)
        XCTAssert(entry2.data == data1)
        
        try! self.keychainStorageWrapper.deleteEntry(withName: name)
        XCTAssert(try! self.keychainStorageWrapper.retrieveAllEntries().count == 0)
        XCTAssert(try! self.keychainStorage.retrieveAllEntries().count == 1)
        
        do {
            _ = try self.keychainStorageWrapper.retrieveEntry(withName: name)
            XCTFail()
        }
        catch { }
        
        do {
            _ = try self.keychainStorage.retrieveEntry(withName: wrapperName)
            XCTFail()
        }
        catch { }
        
        let entry3 = try! self.keychainStorage.retrieveEntry(withName: name)
        XCTAssert(entry3.name == name)
        XCTAssert(entry3.data == data2)
    }
    
    func test002() {
        let name1 = NSUUID().uuidString
        let name2 = NSUUID().uuidString
        let data1 = NSUUID().uuidString.data(using: .utf8)!
        let data2 = NSUUID().uuidString.data(using: .utf8)!

        _ = try! self.keychainStorageWrapper.store(data: data1, withName: name1, meta: nil)
        _ = try! self.keychainStorage.store(data: data2, withName: name2, meta: nil)

        XCTAssert(try self.keychainStorageWrapper.existsEntry(withName: name1))
        XCTAssert(!(try self.keychainStorageWrapper.existsEntry(withName: name2)))
    }

    func test003() {
        let name1 = NSUUID().uuidString
        let name2 = NSUUID().uuidString
        let data1 = NSUUID().uuidString.data(using: .utf8)!
        let data2 = NSUUID().uuidString.data(using: .utf8)!
        let data3 = NSUUID().uuidString.data(using: .utf8)!
        
        _ = try! self.keychainStorageWrapper.store(data: data1, withName: name1, meta: nil)
        _ = try! self.keychainStorage.store(data: data2, withName: name2, meta: nil)
        
        _ = try! self.keychainStorageWrapper.updateEntry(withName: name1, data: data3, meta: nil)
        
        do {
            _ = try self.keychainStorageWrapper.updateEntry(withName: name2, data: data3, meta: nil)
            XCTFail()
        }
        catch { }

        let entry = try! self.keychainStorageWrapper.retrieveEntry(withName: name1)
        XCTAssert(entry.name == name1)
        XCTAssert(entry.data == data3)
    }
}
