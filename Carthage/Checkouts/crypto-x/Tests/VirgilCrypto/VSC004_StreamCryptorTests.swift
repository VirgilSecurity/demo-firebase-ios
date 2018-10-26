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

class VSC004_StreamCipherTests: XCTestCase {
    var toEncrypt: Data! = nil
    
    override func setUp() {
        super.setUp()
        
        let message = NSString(string: "Secret message which is necessary to be encrypted.")
        self.toEncrypt = message.data(using: String.Encoding.utf8.rawValue, allowLossyConversion: false)
    }
    
    override func tearDown() {
        self.toEncrypt = nil
        
        super.tearDown()
    }
    
    func test001_keyBasedEncryptDecrypt() {
        // Generate a new key pair
        let keyPair = KeyPair()
        // Generate a public key id
        let recipientId = UUID().uuidString
        // Encrypt:
        // Create a cipher instance
        let cipher = StreamCipher()
        // Add a key recepient to enable key-based encryption
        try! cipher.addKeyRecipient(recipientId.data(using: .utf8)!, publicKey: keyPair.publicKey())
        
        let eis = InputStream(data: self.toEncrypt)
        let eos = OutputStream(toMemory: ())
        try! cipher.encryptData(from: eis, to: eos, embedContentInfo: true)
        
        let encryptedData = eos.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey) as! Data
        XCTAssertTrue(encryptedData.count > 0, "The data encrypted with key-based encryption should have an actual content.")
        
        // Decrypt:
        // Create a completely new instance of the VCCipher object
        let decipher = StreamCipher()
        
        let dis = InputStream(data: encryptedData)
        let dos = OutputStream(toMemory: ())
        try! decipher.decrypt(from: dis, to: dos, recipientId: recipientId.data(using: .utf8)!, privateKey: keyPair.privateKey(), keyPassword: nil)
        
        let plainData = dos.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey) as! Data
        XCTAssertTrue(plainData.count > 0, "Decrypted data should contain actual data.")
        XCTAssertEqual(plainData, self.toEncrypt, "Initial data and decrypted data should be equal.")
    }
    
    func test002_passwordBasedEncryptDecrypt() {
        // Encrypt:
        let password = "secret"
        // Create a cipher instance
        let cipher = StreamCipher()
        // Add a password recepient to enable password-based encryption
        try! cipher.addPasswordRecipient(password)
        
        let eis = InputStream(data: self.toEncrypt)
        let eos = OutputStream(toMemory: ())
        try! cipher.encryptData(from: eis, to: eos, embedContentInfo: false)
        
        let encryptedData = eos.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey) as! Data
        XCTAssertTrue(encryptedData.count > 0, "The data encrypted with password-based encryption should have an actual content.");
        
        var contentInfo = try! cipher.contentInfo()
        
        XCTAssertTrue(contentInfo.count > 0, "Content Info should contain necessary information.");
        // Decrypt:
        // Create a completely new instance of the VCCipher object
        let decipher = StreamCipher()
        try! decipher.setContentInfo(contentInfo)

        let dis = InputStream(data: encryptedData)
        let dos = OutputStream(toMemory: ())
        try! decipher.decrypt(from: dis, to: dos, password: password)
        
        let plainData = dos.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey) as! Data
        XCTAssertTrue(plainData.count > 0, "The data decrypted with password-based decryption should have an actual content.");
        XCTAssertEqual(plainData, self.toEncrypt, "Initial data and decrypted data should be equal.")
    }
}
