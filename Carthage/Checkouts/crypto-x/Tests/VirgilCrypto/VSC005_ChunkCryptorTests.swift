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

let kPlainDataLength: Int = 5120
let kDesiredDataChunkLength: Int = 1024

class VSC005_ChunkCipherTests: XCTestCase {
    var toEncrypt: Data! = nil
    
    override func setUp() {
        super.setUp()
        
        self.toEncrypt = self.randomDataWithBytes(kPlainDataLength)
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
        // Create a cipher instance
        let cipher = ChunkCipher()
        // Add a key recepient to enable key-based encryption
        do {
            try cipher.addKeyRecipient(recipientId.data(using: .utf8)!, publicKey: keyPair.publicKey())
        }
        catch {
            print("Error adding key recipient: \(error.localizedDescription)")
            XCTFail()
        }
        
        let istream = InputStream(data: self.toEncrypt)
        let ostream = OutputStream.toMemory()
        
        try! cipher.encryptData(from: istream, to: ostream, preferredChunkSize: kDesiredDataChunkLength, embedContentInfo: true)
        
        let encryptedData = ostream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        XCTAssert(encryptedData.count > 0)
        
        let decipher = ChunkCipher()
        
        let idecstream = InputStream(data: encryptedData)
        let odecstream = OutputStream.toMemory()
        
        try! decipher.decrypt(from: idecstream, to: odecstream, recipientId: recipientId.data(using: .utf8)!, privateKey: keyPair.privateKey(), keyPassword: nil)
        
        let plainData = odecstream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        
        XCTAssert(plainData == self.toEncrypt)
    }
    
    func test002_passwordBasedEncryptDecrypt() {
        let passwd = "secret"
        // Create a cipher instance
        let cipher = ChunkCipher()
        // Add a key recepient to enable key-based encryption
        do {
            try cipher.addPasswordRecipient(passwd)
        }
        catch {
            print("Error adding key recipient: \(error.localizedDescription)")
            XCTFail()
        }
        
        let istream = InputStream(data: self.toEncrypt)
        let ostream = OutputStream.toMemory()
        
        try! cipher.encryptData(from: istream, to: ostream, preferredChunkSize: kDesiredDataChunkLength, embedContentInfo: true)
        
        let encryptedData = ostream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        XCTAssert(encryptedData.count > 0)
        
        let decipher = ChunkCipher()
        
        let idecstream = InputStream(data: encryptedData)
        let odecstream = OutputStream.toMemory()
        
        try! decipher.decrypt(from: idecstream, to: odecstream, password: passwd)
        
        let plainData = odecstream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        
        XCTAssert(plainData == self.toEncrypt)
    }
    
    func randomDataWithBytes(_ length: Int) -> Data {
        var array = Array<UInt8>(repeating: 0, count: length)
        arc4random_buf(&array, length)
        return Data(bytes: UnsafePointer<UInt8>(array), count: length)
    }
}
