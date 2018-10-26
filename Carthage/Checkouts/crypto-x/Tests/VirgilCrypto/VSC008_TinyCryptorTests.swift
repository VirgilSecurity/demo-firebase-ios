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

class VSC008_TinyCipherTests: XCTestCase {
    private var toEncrypt: Data!
    
    override func setUp() {
        self.toEncrypt = "Secret message which should be encrypted.".data(using: .utf8)
    }
    
    func test001_encryptDecrypt() {
        let keyPair = KeyPair()
        
        let cipher = TinyCipher(packageSize: .shortSMSPackageSize)
        
        try! cipher.encryptData(self.toEncrypt, recipientPublicKey: keyPair.publicKey())
        
        let packageCount = cipher.packageCount()
        XCTAssert(packageCount != 0)
        
        var encryptedData = Data()
        for i in 0..<packageCount {
            let package = try! cipher.package(at: i)
            encryptedData.append(package)
        }
        
        try! cipher.reset()
        
        let decipher = TinyCipher(packageSize: .shortSMSPackageSize)
        
        let len = min(encryptedData.count, decipher.packageSize)
        
        for i in stride(from: 0, to: encryptedData.count-1, by: len) {
            let package = encryptedData.subdata(in: Range(uncheckedBounds: (i, min(i + len, encryptedData.count))))
            try! decipher.addPackage(package)
        }
        
        XCTAssert(decipher.packagesAccumulated())
        
        let decryptedData = try! decipher.decrypt(withRecipientPrivateKey: keyPair.privateKey(), recipientKeyPassword: nil)
        XCTAssert(decryptedData == self.toEncrypt)
        
        try! decipher.reset()
    }
    
    func test002_encryptSignVerifyDecrypt() {
        let keyPairRec = KeyPair()
        let keyPairSen = KeyPair()
        
        let cipher = TinyCipher(packageSize: .shortSMSPackageSize)
        
        try! cipher.encryptAndSign(self.toEncrypt, recipientPublicKey: keyPairRec.publicKey(), senderPrivateKey: keyPairSen.privateKey(), senderKeyPassword: nil)
        
        let packageCount = cipher.packageCount()
        XCTAssert(packageCount != 0)
        
        var encryptedData = Data()
        for i in 0..<packageCount {
            let package = try! cipher.package(at: i)
            encryptedData.append(package)
        }
        
        try! cipher.reset()
        
        let decipher = TinyCipher(packageSize: .shortSMSPackageSize)
        
        let len = min(encryptedData.count, decipher.packageSize)
        
        for i in stride(from: 0, to: encryptedData.count-1, by: len) {
            let package = encryptedData.subdata(in: Range(uncheckedBounds: (i, min(i + len, encryptedData.count))))
            try! decipher.addPackage(package)
        }
        
        XCTAssert(decipher.packagesAccumulated())
        
        let decryptedData = try! decipher.verifyAndDecrypt(withSenderPublicKey: keyPairSen.publicKey(), recipientPrivateKey: keyPairRec.privateKey(), recipientKeyPassword: nil)
        XCTAssert(decryptedData == self.toEncrypt)
        
        try! decipher.reset()
    }
}
