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
import VirgilCryptoApiImpl
import XCTest

class VSC001_CryptoTests: XCTestCase {
    private let crypto = VirgilCrypto()
    
    func testGK001() {
        let keypairs = try! self.crypto.generateMultipleKeyPairs(numberOfKeyPairs: 100)
        XCTAssert(keypairs.count == 100)
    }
    
    // MARK: Encryption tests
    
    func testED001_EncryptRandomData_SingleCorrectKey_ShouldDecrypt() {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair = try! self.crypto.generateKeyPair()
        
        let encryptedData = try! self.crypto.encrypt(data, for: [keyPair.publicKey])
        
        let decryptedData = try! self.crypto.decrypt(encryptedData, with: keyPair.privateKey)
        
        XCTAssert(data == decryptedData)
    }
    
    func testED002_EncryptRandomData_SingleIncorrectKey_ShouldNotDecrypt() {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair = try! self.crypto.generateKeyPair()
        let wrongKeyPair = try! self.crypto.generateKeyPair()
        
        let encryptedData = try! self.crypto.encrypt(data, for: [keyPair.publicKey])
        
        let decryptedData = try? self.crypto.decrypt(encryptedData, with: wrongKeyPair.privateKey)
        
        XCTAssert(decryptedData == nil)
    }
    
    func testED003_EncryptRandomData_TwoCorrectKeys_ShouldDecrypt() {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair1 = try! self.crypto.generateKeyPair()
        let keyPair2 = try! self.crypto.generateKeyPair()
        
        let encryptedData = try! self.crypto.encrypt(data, for: [keyPair1.publicKey, keyPair2.publicKey])
        
        let decryptedData1 = try! self.crypto.decrypt(encryptedData, with: keyPair1.privateKey)
        let decryptedData2 = try! self.crypto.decrypt(encryptedData, with: keyPair2.privateKey)
        
        XCTAssert(data == decryptedData1)
        XCTAssert(data == decryptedData2)
    }
    
    func testES001_EncryptRandomDataStream_SingleCorrectKey_ShouldDecrypt() {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair = try! self.crypto.generateKeyPair()
        
        let inputStreamForEncryption = InputStream(data: data)
        let outputStreamForEncryption = OutputStream.toMemory()
        
        try! self.crypto.encrypt(inputStreamForEncryption, to: outputStreamForEncryption, for: [keyPair.publicKey])
        
        let encryptedDataProperty = outputStreamForEncryption.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey)
        
        guard let encryptedData = encryptedDataProperty as? Data else {
            XCTFail("No encrypted data")
            return
        }
        
        let inputStreamForDecryption = InputStream(data: encryptedData)
        let outputStreamForDecryption = OutputStream.toMemory()
        
        try! self.crypto.decrypt(inputStreamForDecryption, to: outputStreamForDecryption, with: keyPair.privateKey)
        
        let decryptedDataProperty = outputStreamForDecryption.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey)
        
        guard let decryptedData = decryptedDataProperty as? Data else {
            XCTFail("No decrypted data")
            return
        }
        
        XCTAssert(data == decryptedData)
    }
    
    func testES002_EncryptRandomDataStream_SingleIncorrectKey_ShouldNotDecrypt() {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair = try! self.crypto.generateKeyPair()
        let wrongKeyPair = try! self.crypto.generateKeyPair()
        
        let inputStreamForEncryption = InputStream(data: data)
        let outputStreamForEncryption = OutputStream.toMemory()
        
        try! self.crypto.encrypt(inputStreamForEncryption, to: outputStreamForEncryption, for: [keyPair.publicKey])
        
        let encryptedDataProperty = outputStreamForEncryption.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey)
        
        guard let encryptedData = encryptedDataProperty as? Data else {
            XCTFail("No encrypted data")
            return
        }
        
        let inputStreamForDecryption = InputStream(data: encryptedData)
        let outputStreamForDecryption = OutputStream.toMemory()
        
        var errorWasThrown = false
        do {
            try self.crypto.decrypt(inputStreamForDecryption, to: outputStreamForDecryption, with: wrongKeyPair.privateKey)
        }
        catch {
            errorWasThrown = true
        }
        
        XCTAssert(errorWasThrown)
        
        let decryptedDataProperty = outputStreamForDecryption.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey)
        
        guard let decryptedData = decryptedDataProperty as? Data else {
            XCTFail("No decrypted data")
            return
        }
        
        XCTAssert(decryptedData.count == 0)
    }
    
    func testES003_EncryptRandomDataStream_TwoCorrectKeys_ShouldDecrypt() {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair1 = try! self.crypto.generateKeyPair()
        let keyPair2 = try! self.crypto.generateKeyPair()
        
        let inputStreamForEncryption = InputStream(data: data)
        let outputStreamForEncryption = OutputStream.toMemory()
        
        try! self.crypto.encrypt(inputStreamForEncryption, to: outputStreamForEncryption, for: [keyPair1.publicKey, keyPair2.publicKey])
        
        let encryptedDataProperty = outputStreamForEncryption.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey)
        
        guard let encryptedData = encryptedDataProperty as? Data else {
            XCTFail("No encrypted data")
            return
        }
        
        let inputStreamForDecryption1 = InputStream(data: encryptedData)
        let outputStreamForDecryption1 = OutputStream.toMemory()
        
        try! self.crypto.decrypt(inputStreamForDecryption1, to: outputStreamForDecryption1, with: keyPair1.privateKey)
        
        let decryptedDataProperty1 = outputStreamForDecryption1.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey)
        
        guard let decryptedData1 = decryptedDataProperty1 as? Data else {
            XCTFail("No decrypted data")
            return
        }
        
        XCTAssert(data == decryptedData1)
        
        let inputStreamForDecryption2 = InputStream(data: encryptedData)
        let outputStreamForDecryption2 = OutputStream.toMemory()
        
        try! self.crypto.decrypt(inputStreamForDecryption2, to: outputStreamForDecryption2, with: keyPair2.privateKey)
        
        let decryptedDataProperty2 = outputStreamForDecryption2.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey)
        
        guard let decryptedData2 = decryptedDataProperty2 as? Data else {
            XCTFail("No decrypted data")
            return
        }
        
        XCTAssert(data == decryptedData2)
    }
    
    func testES004_EncryptFileDataStream_SingleCorrectKey_ShouldDecrypt() {
        let testFileURL = Bundle(for: type(of: self)).url(forResource: "testData", withExtension: "txt")!
        let inputStreamForEncryption = InputStream(url: testFileURL)!
        
        let keyPair = try! self.crypto.generateKeyPair()
        
        let outputStreamForEncryption = OutputStream.toMemory()
        
        try! self.crypto.encrypt(inputStreamForEncryption, to: outputStreamForEncryption, for: [keyPair.publicKey])
        
        let encryptedDataProperty = outputStreamForEncryption.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey)
        
        guard let encryptedData = encryptedDataProperty as? Data else {
            XCTFail("No encrypted data")
            return
        }
 
        let inputStreamForDecryption = InputStream(data: encryptedData)
        let outputStreamForDecryption = OutputStream.toMemory()
        
        try! self.crypto.decrypt(inputStreamForDecryption, to: outputStreamForDecryption, with: keyPair.privateKey)
        
        let decryptedDataProperty = outputStreamForDecryption.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey)
        
        guard let decryptedData = decryptedDataProperty as? Data else {
            XCTFail("No decrypted data")
            return
        }
        
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        
        XCTAssert(decryptedString == "Hello, Bob!\n")
    }
    
    // MARK: Signatures tests
    func testSD001_SignRandomData_CorrectKeys_ShouldValidate() {
        let data = UUID().uuidString.data(using: .utf8)!

        let keyPair = try! self.crypto.generateKeyPair()
        
        let signature = try! self.crypto.generateSignature(of: data, using: keyPair.privateKey)
        
        XCTAssert(self.crypto.verifySignature(signature, of: data, with: keyPair.publicKey) == true)
    }
    
    func testSD002_SignRandomData_IncorrectKeys_ShouldNotValidate() {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair = try! self.crypto.generateKeyPair()
        let wrongKeyPair = try! self.crypto.generateKeyPair()
        
        let signature = try! self.crypto.generateSignature(of: data, using: keyPair.privateKey)
        
        XCTAssert(self.crypto.verifySignature(signature, of: data, with: wrongKeyPair.publicKey) == false)
    }
    
    func testESD001_SignThenEncryptRandomData_CorrectKeys_ShouldDecryptValidate() {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let senderKeyPair = try! self.crypto.generateKeyPair()
        let receiverKeyPair = try! self.crypto.generateKeyPair()
        
        let signedThenEncryptedData = try! self.crypto.signThenEncrypt(data, with: senderKeyPair.privateKey, for: [receiverKeyPair.publicKey])
        
        let decryptedThenVerifiedData = try! self.crypto.decryptThenVerify(signedThenEncryptedData, with: receiverKeyPair.privateKey, using: senderKeyPair.publicKey)
        
        XCTAssert(data == decryptedThenVerifiedData)
    }
    
    func testESD002_SignThenEncryptRandomData_TwoKeys_ShouldDecryptValidate() {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let senderKeyPair = try! self.crypto.generateKeyPair()
        let oneMoreKeyPair = try! self.crypto.generateKeyPair()
        let receiverKeyPair = try! self.crypto.generateKeyPair()
        
        let signedThenEncryptedData = try! self.crypto.signThenEncrypt(data, with: senderKeyPair.privateKey, for: [receiverKeyPair.publicKey])
        
        let decryptedThenVerifiedData = try! self.crypto.decryptThenVerify(signedThenEncryptedData, with: receiverKeyPair.privateKey, usingOneOf: [oneMoreKeyPair.publicKey, senderKeyPair.publicKey])
        
        XCTAssert(data == decryptedThenVerifiedData)
    }
    
    func testESD003_SignThenEncryptRandomData_NoSenderKeys_ShouldNotValidate() {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let senderKeyPair = try! self.crypto.generateKeyPair()
        let oneMoreKeyPair = try! self.crypto.generateKeyPair()
        let receiverKeyPair = try! self.crypto.generateKeyPair()
        
        let signedThenEncryptedData = try! self.crypto.signThenEncrypt(data, with: senderKeyPair.privateKey, for: [receiverKeyPair.publicKey])
        
        var errorWasThrown = false
        do {
            _ = try self.crypto.decryptThenVerify(signedThenEncryptedData, with: receiverKeyPair.privateKey, usingOneOf: [oneMoreKeyPair.publicKey])
        }
        catch {
            errorWasThrown = true
        }
        
        XCTAssert(errorWasThrown)
    }
}
