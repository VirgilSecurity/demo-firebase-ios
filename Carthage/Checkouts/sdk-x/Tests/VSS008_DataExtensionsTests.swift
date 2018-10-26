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

class VSS008_DataExtensionsTests: XCTestCase {
    func test001_base64Url() {
        let base64encoded = "MFEwDQYJYIZIAWUDBAIDBQAEQJuTxlQ7r+RG2P8D12OFOdgPsIDmZMd4UBMIG1c1Amqm/oc1wRUzk7ccz1RbTWEt2XP+1GbkF0Z6s6FYf1QEUQI="
        let base64UrlEncoded = "MFEwDQYJYIZIAWUDBAIDBQAEQJuTxlQ7r-RG2P8D12OFOdgPsIDmZMd4UBMIG1c1Amqm_oc1wRUzk7ccz1RbTWEt2XP-1GbkF0Z6s6FYf1QEUQI"

        let data = Data(base64Encoded: base64encoded)!
        
        let base64url = data.base64UrlEncodedString()

        XCTAssert(base64url == base64UrlEncoded)

        let newData = Data(base64UrlEncoded: base64url)
        
        XCTAssert(newData != nil)
        
        XCTAssert(data == newData!)
    }
    
    func test002_hex() {
        let str = "This is a test."
        let strHex = "54686973206973206120746573742e"
        
        XCTAssert(str.data(using: .utf8)!.hexEncodedString() == strHex)
        
        XCTAssert(String(data: Data(hexEncodedString: strHex)!, encoding: .utf8) == str)
    }
}
