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

class VSK005_CloudEntrySerializerTests: XCTestCase {
    private var cloud: NSDictionary!
    
    override func setUp() {
        super.setUp()
        
        let bundle = Bundle(for: VSK005_CloudEntrySerializerTests.self)
        let fileUrl = bundle.url(forResource: "Cloud", withExtension: "json")!
        let data = try! Data(contentsOf: fileUrl)
        
        self.cloud = try! JSONSerialization.jsonObject(with: data, options: []) as! NSDictionary
    }
    
    func test01_KTC17_serialize_deserialize() {
        let serializer = CloudEntrySerializer()

        let name1 = self.cloud["kName1"] as! String
        let name2 = self.cloud["kName2"] as! String

        let data1 = Data(base64Encoded: self.cloud["kData1"] as! String)!
        let data2 = Data(base64Encoded: self.cloud["kData2"] as! String)!

        let date11 = Date(timeIntervalSince1970: TimeInterval(self.cloud["kCreationDate1"] as! Int) / 1000)
        let date12 = Date(timeIntervalSince1970: TimeInterval(self.cloud["kModificationDate1"] as! Int) / 1000)

        let date21 = Date(timeIntervalSince1970: TimeInterval(self.cloud["kCreationDate2"] as! Int) / 1000)
        let date22 = Date(timeIntervalSince1970: TimeInterval(self.cloud["kModificationDate2"] as! Int) / 1000)

        let meta1 = self.cloud["kMeta1"] as? [String: String]
        let meta2 = self.cloud["kMeta2"] as? [String: String]

        let dict1 = [
            name1: CloudEntry(name: name1, data: data1, creationDate: date11, modificationDate: date12, meta: meta1),
            name2: CloudEntry(name: name2, data: data2, creationDate: date21, modificationDate: date22, meta: meta2)
        ]

        let serialized1 = try! serializer.serialize(dict: dict1)
        let serialized2 = Data(base64Encoded: self.cloud["kExpectedResult"] as! String)!

        XCTAssert(serialized1 == serialized2)
        
        let dict2 = try! serializer.deserialize(data: serialized2)
        
        XCTAssert(dict1[name1]! == dict2[name1]!)
        XCTAssert(dict1[name2]! == dict2[name2]!)
        XCTAssert(dict1.keys.count == dict2.keys.count)
    }
    
    func test02_KTC18_deserialize_empty() {
        let serializer = CloudEntrySerializer()

        let dict = try! serializer.deserialize(data: Data())
        
        XCTAssert(dict.isEmpty)
    }
}
