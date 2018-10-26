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
import VirgilCrypto
import VirgilCryptoApiImpl

class VSM003_CryptoFormatsTests: XCTestCase {
    func test001_SignatureHash() {
        let crypto = VirgilCrypto()
        let keyPair = try! crypto.generateKeyPair()
        let signature = try! crypto.generateSignature(of: "test".data(using: .utf8)!, using: keyPair.privateKey)
        
        XCTAssert(signature.subdata(in: 0..<17) == Data(base64Encoded: "MFEwDQYJYIZIAWUDBAIDBQA="))
    }
    
    func test002_PrivateKeyIsDER() {
        let crypto = VirgilCrypto()
        
        let keyPair1 = try! crypto.generateKeyPair()
        let privateKeyData1 = crypto.exportPrivateKey(keyPair1.privateKey)
        XCTAssert(KeyPair.privateKey(toDER: privateKeyData1)! == privateKeyData1)
        
        let keyPair3 = try! crypto.generateMultipleKeyPairs(numberOfKeyPairs: 1)[0]
        let privateKeyData3 = crypto.exportPrivateKey(keyPair3.privateKey)
        XCTAssert(KeyPair.privateKey(toDER: privateKeyData3)! == privateKeyData3)
        
        let privateKey4 = try! crypto.importPrivateKey(from: Data(base64Encoded: "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUg4bnIyV05nblkya1ZScjRValp4UnJWVGpiMW4wWGdBZkhOWE1ocVkwaVAKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=")!)
        let privateKeyData4 = crypto.exportPrivateKey(privateKey4)
        XCTAssert(KeyPair.privateKey(toDER: privateKeyData4)! == privateKeyData4)
        
        let privateKey5 = try! crypto.importPrivateKey(from: Data(base64Encoded: "LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQpNSUdoTUYwR0NTcUdTSWIzRFFFRkRUQlFNQzhHQ1NxR1NJYjNEUUVGRERBaUJCQ3kzSkk3V0VDcGVHZGFIdEc2CktHcjRBZ0lkWXpBS0JnZ3Foa2lHOXcwQ0NqQWRCZ2xnaGtnQlpRTUVBU29FRUp1Wlpqb0oyZGJGdUpZN0ZNSisKN3g0RVFEcnRpZjNNb29rQk5PRTBUaGZmSEtrV0R3K3lvZ0ZRRk1RRFJtU0kwSXl2T2w4RTVnck5QcFNxU3dQNApIL2lzYzJvQVJzSW03alVRQXkrQjl5aTRZK3c9Ci0tLS0tRU5EIEVOQ1JZUFRFRCBQUklWQVRFIEtFWS0tLS0tCg==")!, password: "qwerty")
        let privateKeyData5 = crypto.exportPrivateKey(privateKey5)
        XCTAssert(KeyPair.privateKey(toDER: privateKeyData5)! == privateKeyData5)
    }
    
    func test003_PublicKeyIsDER() {
        let crypto = VirgilCrypto()
        
        let keyPair1 = try! crypto.generateKeyPair()
        let publicKeyData1 = crypto.exportPublicKey(keyPair1.publicKey)
        XCTAssert(KeyPair.publicKey(toDER: publicKeyData1)! == publicKeyData1)
        
        let keyPair2 = try! crypto.generateMultipleKeyPairs(numberOfKeyPairs: 1)[0]
        let publicKeyData2 = crypto.exportPublicKey(keyPair2.publicKey)
        XCTAssert(KeyPair.publicKey(toDER: publicKeyData2)! == publicKeyData2)
        
        let publicKey3 = try! crypto.importPublicKey(from: Data(base64Encoded: "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQXYycWRHa0w2RmRxc0xpLzdPQTA1NjJPOVYvVDhFN3F6RmF0RjZMcW9TY3M9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=")!)
        let publicKeyData3 = crypto.exportPublicKey(publicKey3)
        XCTAssert(KeyPair.publicKey(toDER: publicKeyData3)! == publicKeyData3)
    }
    
    func test004_PrivateKeyIdentifierIsCorrect() {
        let crypto1 = VirgilCrypto()
        let keyPair1 = try! crypto1.generateKeyPair()
        
        XCTAssert(Hash(algorithm: .SHA512).hash(crypto1.exportPublicKey(keyPair1.publicKey)).subdata(in: 0..<8) == keyPair1.publicKey.identifier)
        
        let crypto2 = VirgilCrypto(useSHA256Fingerprints: true)
        let keyPair2 = try! crypto2.generateKeyPair()
        
        XCTAssert(Hash(algorithm: .SHA256).hash(crypto2.exportPublicKey(keyPair2.publicKey)) == keyPair2.publicKey.identifier)
    }
    
    func test005_PublicKeyIdentifierIsCorrect() {
        let crypto1 = VirgilCrypto()
        let keyPair1 = try! crypto1.generateKeyPair()
        
        let publicKey1 = try! crypto1.extractPublicKey(from: keyPair1.privateKey)
        
        XCTAssert(publicKey1.identifier == keyPair1.publicKey.identifier)
        XCTAssert(crypto1.exportPublicKey(publicKey1) == crypto1.exportPublicKey(keyPair1.publicKey))
        
        XCTAssert(Hash(algorithm: .SHA512).hash(crypto1.exportPublicKey(keyPair1.publicKey)).subdata(in: 0..<8) == keyPair1.publicKey.identifier)
        
        let crypto2 = VirgilCrypto(useSHA256Fingerprints: true)
        let keyPair2 = try! crypto2.generateKeyPair()
        
        let publicKey2 = try! crypto2.extractPublicKey(from: keyPair2.privateKey)
        
        XCTAssert(publicKey2.identifier == keyPair2.publicKey.identifier)
        XCTAssert(crypto1.exportPublicKey(publicKey2) == crypto1.exportPublicKey(keyPair2.publicKey))
        
        XCTAssert(Hash(algorithm: .SHA256).hash(crypto1.exportPublicKey(keyPair2.publicKey)) == keyPair2.publicKey.identifier)
    }
}
