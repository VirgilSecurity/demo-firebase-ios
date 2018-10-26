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
import XCTest
@testable import VirgilSDKKeyknox

class VSK006_SyncKeyStorageKeychainUtilsTests: XCTestCase {
    private let keychainUtils = KeychainUtils()
    
    func test001_testMeta() {
        let data = NSUUID().uuidString.data(using: .utf8)!
        let creationDate = Date(timeIntervalSince1970: 1529330258.105006)
        let modificationDate = Date(timeIntervalSince1970: 1529330279.8317609)
        
        let cloudEntry1 = CloudEntry(name: "name", data: data, creationDate: creationDate, modificationDate: modificationDate, meta: nil)
        let cloudEntry2 = CloudEntry(name: "name", data: data, creationDate: creationDate, modificationDate: modificationDate, meta: ["key": "value"])
        let cloudEntry3 = CloudEntry(name: "name", data: data, creationDate: creationDate, modificationDate: modificationDate, meta: [KeychainUtils.keyknoxMetaCreationDateKey: "value"])
        let cloudEntry4 = CloudEntry(name: "name", data: data, creationDate: creationDate, modificationDate: modificationDate, meta: [KeychainUtils.keyknoxMetaModificationDateKey: "value"])
        
        let meta1 = try! self.keychainUtils.createMetaForKeychain(from: cloudEntry1)
        let meta2 = try! self.keychainUtils.createMetaForKeychain(from: cloudEntry2)
        
        do {
            _ = try self.keychainUtils.createMetaForKeychain(from: cloudEntry3)
            XCTFail()
        }
        catch SyncKeyStorageError.invalidKeysInEntryMeta {
        }
        catch {
            XCTFail()
        }
        do {
            _ = try self.keychainUtils.createMetaForKeychain(from: cloudEntry4)
            XCTFail()
        }
        catch SyncKeyStorageError.invalidKeysInEntryMeta {
        }
        catch {
            XCTFail()
        }
        
        let expectedMeta1 = [
            "k_cda": "1529330258105",
            "k_mda": "1529330279831"
        ]
        let expectedMeta2 = [
            "k_cda": "1529330258105",
            "k_mda": "1529330279831",
            "key": "value"
        ]
        
        XCTAssert(meta1 == expectedMeta1)
        XCTAssert(meta2 == expectedMeta2)
    }
}
