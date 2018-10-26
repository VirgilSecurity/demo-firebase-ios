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

class VSC001_KeyPairTests: XCTestCase {
    func test001_createKeyPair() {
        let keyPair = KeyPair()
        XCTAssertTrue(keyPair.publicKey().count > 0, "Public key should have actual content.");
        XCTAssertTrue(keyPair.privateKey().count > 0, "Private key should have actual content.");
        
        if let keyString = NSString(data: keyPair.privateKey(), encoding: String.Encoding.utf8.rawValue) {
            let range = keyString.range(of: "ENCRYPTED", options: [.literal, .caseInsensitive])
            XCTAssertTrue(range.length == 0, "Private key should be generated in plain form.");
        }
    }
    
    func test002_createKeyPairWithPassword() {
        let password = "secret"
        let keyPair = KeyPair(keyPairType: .RSA_512, password: password)
        XCTAssert(keyPair.publicKey().count > 0)
        XCTAssert(keyPair.privateKey().count > 0)
        
        let privateKeyString = String(data: keyPair.privateKey(), encoding: .utf8)!
        
        XCTAssert(privateKeyString.range(of: "ENCRYPTED", options: [.literal, .caseInsensitive]) != nil)
        
        XCTAssertTrue(keyPair.publicKey().count > 0, "Public key should be generated for the new key pair.");
        XCTAssertTrue(keyPair.privateKey().count > 0, "Private key should be generated for the new key pair.");
    }
    
    func test003_encryptDecryptPrivateKeyWithPassword() {
        let keyPair = KeyPair()
        let password = "secret"
        
        let encryptedPrivateKey = KeyPair.encryptPrivateKey(keyPair.privateKey(), privateKeyPassword: password)!
        XCTAssert(encryptedPrivateKey.count > 0)
        
        let decryptedPrivateKey = KeyPair.decryptPrivateKey(encryptedPrivateKey, privateKeyPassword: password)!
        
        XCTAssert(decryptedPrivateKey.count > 0)
        
        XCTAssert(decryptedPrivateKey == keyPair.privateKey())
    }
    
    func test004_extractPublicKeyWithPassword() {
        let password = "secret"
        let keyPair = KeyPair(keyPairType: .RSA_512, password: password)
        
        let publicKeyData = KeyPair.extractPublicKey(fromPrivateKey: keyPair.privateKey(), privateKeyPassword: password)!
        XCTAssert(publicKeyData.count > 0)
    }
    
    func test005_extractPublicKeyWithoutPassword() {
        let keyPair = KeyPair(keyPairType: .RSA_512, password: nil)
        
        let publicKeyData = KeyPair.extractPublicKey(fromPrivateKey: keyPair.privateKey(), privateKeyPassword: nil)!
        XCTAssert(publicKeyData.count > 0)
    }

    func test006_extractPublicKeysToPemAndDer() {
        let keyPair = KeyPair()
        
        let pemData = KeyPair.publicKey(toPEM: keyPair.publicKey())!
        XCTAssert(pemData.count > 0)
        let derData = KeyPair.publicKey(toDER: keyPair.publicKey())!
        XCTAssert(derData.count > 0)
    }
    
    func test007_extractPrivateKeyToPemAndDer() {
        let keyPair = KeyPair()
        
        let pemData = KeyPair.privateKey(toPEM: keyPair.privateKey())!
        XCTAssert(pemData.count > 0)
        let derData = KeyPair.privateKey(toDER: keyPair.privateKey())!
        XCTAssert(derData.count > 0)
    }
    
    func test008_extractPrivateKeyWithPasswordToPemAndDer() {
        let password = "secret"
        let keyPair = KeyPair()
        
        let pemData = KeyPair.privateKey(toPEM: keyPair.privateKey(), privateKeyPassword: password)!
        XCTAssert(pemData.count > 0)
        let derData = KeyPair.privateKey(toDER: keyPair.privateKey(), privateKeyPassword: password)!
        XCTAssert(derData.count > 0)
    }
    
    func test009_createMultipleKeyPairs() {
        let number = 10
        let keypairs = KeyPair.generateMultipleKeys(UInt(number), keyPairType: VSCKeyType.FAST_EC_ED25519)
        XCTAssert(keypairs.count == number)
    }
    
    func test010_createKeyPairFromKeyMaterial() {
        let random = VirgilRandom(personalInfo: "some info")
        
        let keyMaterial = random.randomize(withBytesNum: 32)
        
        let iterations = 10
        
        var lastKeyPair: KeyPair?
        for _ in 0..<iterations {
            guard let keyPair = KeyPair(keyPairType: .FAST_EC_ED25519, keyMaterial: keyMaterial, password: nil) else {
                XCTFail()
                return
            }
            
            if let lastKeyPair = lastKeyPair {
                XCTAssert(lastKeyPair.privateKey() == keyPair.privateKey())
                XCTAssert(lastKeyPair.publicKey() == keyPair.publicKey())
            }
            else {
                lastKeyPair = keyPair
            }
        }
    }

    func test011_createKeyPairFromKeyMaterial_SmallMaterial() {
        let random = VirgilRandom(personalInfo: "some info")

        let keyMaterial = random.randomize(withBytesNum: 20)

        let keyPair = KeyPair(keyPairType: .FAST_EC_ED25519, keyMaterial: keyMaterial, password: nil)

        XCTAssert(keyPair == nil)
    }
}
