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
import VirgilCrypto
import XCTest

class VSP001_PFSTests: XCTestCase {
    private func generateSessions(additionalDataPresent: Bool, oneTimePresent: Bool) -> (Pfs, PfsSession, Pfs, PfsSession) {
        let initiatorIdentityKeyPair = KeyPair()
        let initiatorEphemeralKeyPair = KeyPair()
        let initiatorIdentityPrivateKey = PfsPrivateKey(key: initiatorIdentityKeyPair.privateKey(), password: nil)!
        let initiatorIdentityPublicKey = PfsPublicKey(key: initiatorIdentityKeyPair.publicKey())!
        let initiatorEphemeralPrivateKey = PfsPrivateKey(key: initiatorEphemeralKeyPair.privateKey(), password: nil)!
        let initiatorEphemeralPublicKey = PfsPublicKey(key: initiatorEphemeralKeyPair.publicKey())!
        let initiatorAdditionalData = additionalDataPresent ? "Alice+Bob".data(using: .utf8) : nil
        
        let responderIdentityKeyPair = KeyPair()
        let responderLongTermKeyPair = KeyPair()
        let responderOneTimeKeyPair = KeyPair()
        let responderIdentityPublicKey = PfsPublicKey(key: responderIdentityKeyPair.publicKey())!
        let responderIdentityPrivateKey = PfsPrivateKey(key: responderIdentityKeyPair.privateKey(), password: nil)!
        let responderLongTermPublicKey = PfsPublicKey(key: responderLongTermKeyPair.publicKey())!
        let responderLongTermPrivateKey = PfsPrivateKey(key: responderLongTermKeyPair.privateKey(), password: nil)!
        let responderAdditionalData = additionalDataPresent ? "Alice+Bob".data(using: .utf8) : nil
        
        let responderOneTimePublicKey = oneTimePresent ? PfsPublicKey(key: responderOneTimeKeyPair.publicKey())! : nil
        let responderOneTimePrivateKey = oneTimePresent ? PfsPrivateKey(key: responderOneTimeKeyPair.privateKey(), password: nil)! : nil
        
        let initiatorPrivateInfo = PfsInitiatorPrivateInfo(identityPrivateKey: initiatorIdentityPrivateKey, ephemeralPrivateKey: initiatorEphemeralPrivateKey)!
        let responderPublicInfo = PfsResponderPublicInfo(identityPublicKey: responderIdentityPublicKey, longTermPublicKey: responderLongTermPublicKey, oneTime: responderOneTimePublicKey)!
        
        let initiatorPfs = Pfs()
        let initiatorSession = initiatorPfs.startInitiatorSession(with: initiatorPrivateInfo, respondrerPublicInfo: responderPublicInfo, additionalData: initiatorAdditionalData)!
        
        let initiatorPublicInfo = PfsInitiatorPublicInfo(identityPublicKey: initiatorIdentityPublicKey, ephemeralPublicKey: initiatorEphemeralPublicKey)!
        let responderPrivateInfo = PfsResponderPrivateInfo(identityPrivateKey: responderIdentityPrivateKey, longTermPrivateKey: responderLongTermPrivateKey, oneTime: responderOneTimePrivateKey)!
        
        let responderPfs = Pfs()
        let responderSession = responderPfs.startResponderSession(with: responderPrivateInfo, initiatorPublicInfo: initiatorPublicInfo, additionalData: responderAdditionalData)!
        
        return (initiatorPfs, initiatorSession, responderPfs, responderSession)
    }
    
    func test001_encryptDecrypt_oneTimePresent() {
        let (initiatorPfs, _, responderPfs, _) = self.generateSessions(additionalDataPresent: false, oneTimePresent: true)
        
        let data = "Hello, Bob!".data(using: .utf8)!
        
        let encryptedData = initiatorPfs.encryptData(data)!
        
        let decryptedData = responderPfs.decryptMessage(encryptedData)!
        
        XCTAssert(data == decryptedData)
    }
    
    func test002_encryptDecrypt_oneTimeAbsent() {
        let (initiatorPfs, _, responderPfs, _) = self.generateSessions(additionalDataPresent: false, oneTimePresent: false)
        
        let data = "Hello, Bob!".data(using: .utf8)!
        
        let encryptedData = initiatorPfs.encryptData(data)!
        
        let decryptedData = responderPfs.decryptMessage(encryptedData)!
        
        XCTAssert(data == decryptedData)
    }
    
    func test003_validateSessionData_addionalDataAbsent() {
        let (_, initiatorSession, _, responderSession) = self.generateSessions(additionalDataPresent: false, oneTimePresent: true)
        
        XCTAssert(initiatorSession.identifier == responderSession.identifier);
        
        XCTAssert(initiatorSession.additionalData.count != 0)
        XCTAssert(initiatorSession.decryptionSecretKey.count != 0)
        XCTAssert(initiatorSession.encryptionSecretKey.count != 0)
        XCTAssert(initiatorSession.identifier.count != 0)
        
        XCTAssert(responderSession.additionalData.count != 0)
        XCTAssert(responderSession.decryptionSecretKey.count != 0)
        XCTAssert(responderSession.encryptionSecretKey.count != 0)
        XCTAssert(responderSession.identifier.count != 0)
        
        XCTAssert(initiatorSession.identifier == responderSession.identifier);
    }
    
    func test004_validateSessionData_addionalDataPresent() {
        let (_, initiatorSession, _, responderSession) = self.generateSessions(additionalDataPresent: true, oneTimePresent: true)
        XCTAssert(initiatorSession.additionalData.count != 0)
        XCTAssert(initiatorSession.decryptionSecretKey.count != 0)
        XCTAssert(initiatorSession.encryptionSecretKey.count != 0)
        XCTAssert(initiatorSession.identifier.count != 0)
        
        XCTAssert(responderSession.additionalData.count != 0)
        XCTAssert(responderSession.decryptionSecretKey.count != 0)
        XCTAssert(responderSession.encryptionSecretKey.count != 0)
        XCTAssert(responderSession.identifier.count != 0)
        
        XCTAssert(initiatorSession.identifier == responderSession.identifier);
    }
}
