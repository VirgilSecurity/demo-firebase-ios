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
import VirgilCryptoApiImpl
import VirgilSDK

class CardClientStub_STC34: CardClientProtocol {
    private var testsDict: Dictionary<String, Any>!

    init() {
        let testFileURL = Bundle(for: type(of: self)).url(forResource: "data", withExtension: "json")!
        let testFileData = try! Data(contentsOf: testFileURL)
        self.testsDict = try! JSONSerialization.jsonObject(with: testFileData, options: JSONSerialization.ReadingOptions.init(rawValue: 0)) as! Dictionary<String, Any>
    }

    @objc func getCard(withId cardId: String, token: String) throws -> GetCardResponse {
        let response = try RawSignedModel.import(fromBase64Encoded: self.testsDict["STC-3.as_string"] as! String)
        
        return GetCardResponse(rawCard: response, isOutdated: false)
    }

    @objc func publishCard(model: RawSignedModel, token: String) throws -> RawSignedModel {
        return try RawSignedModel.import(fromBase64Encoded: self.testsDict["STC-34.as_string"] as! String)
    }

    @objc func searchCards(identity: String, token: String) throws -> [RawSignedModel] {
        return [try RawSignedModel.import(fromBase64Encoded: self.testsDict["STC-34.as_string"] as! String)]
    }
}

class VerifierStubFalse: CardVerifier {
    func verifyCard(_ card: Card) -> Bool {
        return false
    }
}

class VerifierStubTrue: CardVerifier {
    func verifyCard(_ card: Card) -> Bool {
        return true
    }
}

class VSS009_ExtraCardManagerTests: XCTestCase {
    private var crypto: VirgilCrypto!
    private var consts: VSSTestsConst!
    private var cardCrypto: VirgilCardCrypto!
    private var utils: VSSTestUtils!
    private var modelSigner: ModelSigner!
    private var testsDict: Dictionary<String, Any>!
    private var cardClient: CardClient!

    // MARK: Setup
    override func setUp() {
        super.setUp()

        let testFileURL = Bundle(for: type(of: self)).url(forResource: "data", withExtension: "json")!
        let testFileData = try! Data(contentsOf: testFileURL)
        self.testsDict = try! JSONSerialization.jsonObject(with: testFileData, options: JSONSerialization.ReadingOptions.init(rawValue: 0)) as! Dictionary<String, Any>

        self.crypto = VirgilCrypto()
        self.consts = VSSTestsConst()
        self.utils = VSSTestUtils(crypto: self.crypto, consts: self.consts)
        self.cardCrypto = VirgilCardCrypto(virgilCrypto: self.crypto)
        self.modelSigner = ModelSigner(cardCrypto: self.cardCrypto)
        if let serviceURL = self.consts.serviceURL {
            self.cardClient = CardClient(serviceUrl: serviceURL)
        }
        else {
            self.cardClient = CardClient()
        }
    }

    override func tearDown() {
        self.crypto = nil
        self.consts = nil
        self.cardCrypto = nil
        self.modelSigner = nil
        
        super.tearDown()
    }

    // MARK: Tests
    func test001_STC_13() {
        let generator = self.utils.getGeneratorJwtProvider(withIdentity: "identity", error: nil)
        
        let cardManagerParams = CardManagerParams(cardCrypto: self.cardCrypto, accessTokenProvider: generator, cardVerifier: VerifierStubFalse())
        cardManagerParams.cardClient = self.cardClient
        
        let cardManager = CardManager(params: cardManagerParams)
        
        var errorWasThrown = false
        do {
          _ = try cardManager.importCard(fromBase64Encoded: self.testsDict["STC-3.as_string"] as! String)
        } catch CardManagerError.cardIsNotVerified {
            errorWasThrown = true
        }
        catch {
            XCTFail()
        }

        XCTAssert(errorWasThrown)
        errorWasThrown = false

        do {
            let data = (self.testsDict["STC-3.as_json"] as! String).data(using: .utf8)!
            let dic = try JSONSerialization.jsonObject(with: data, options: [])
            _ = try  cardManager.importCard(fromJson: dic)
        } catch CardManagerError.cardIsNotVerified {
            errorWasThrown = true
        }
        catch {
            XCTFail()
        }
        XCTAssert(errorWasThrown)
        errorWasThrown = false

        let keyPair1 = try! self.crypto.generateKeyPair()
        let operation1 = cardManager.publishCard(privateKey: keyPair1.privateKey, publicKey: keyPair1.publicKey, identity: nil)

        switch operation1.startSync() {
        case .success: XCTFail()
        case .failure(let error):
            guard let error = error as? CardManagerError,
                error == .cardIsNotVerified else {
                    XCTFail()
                    return
            }
        }

        let keyPair2 = try! self.crypto.generateKeyPair()
        let rawCard = try! cardManager.generateRawCard(privateKey: keyPair2.privateKey, publicKey: keyPair2.publicKey, identity: "identity")
        let operation2 = cardManager.publishCard(rawCard: rawCard)

        switch operation2.startSync() {
        case .success: XCTFail()
        case .failure(let error):
            guard let error = error as? CardManagerError,
                error == .cardIsNotVerified else {
                    XCTFail()
                    return
            }
        }

        let operation3 = cardManager.getCard(withId: self.consts.existentCardId)

        switch operation3.startSync() {
        case .success: XCTFail()
        case .failure(let error):
            guard let error = error as? CardManagerError,
                error == .cardIsNotVerified else {
                    XCTFail()
                    return
            }
        }

        let operation4 = cardManager.searchCards(identity: self.consts.existentCardIdentity)

        switch operation4.startSync() {
        case .success: XCTFail()
        case .failure(let error):
            guard let error = error as? CardManagerError,
                error == .cardIsNotVerified else {
                    XCTFail()
                    return
            }
        }
    }

    func test002_STC_34() {
        let generator = self.utils.getGeneratorJwtProvider(withIdentity: "identity", error: nil)
        
        let cardManagerParams = CardManagerParams(cardCrypto: self.cardCrypto, accessTokenProvider: generator, cardVerifier: VerifierStubTrue())
        cardManagerParams.cardClient = CardClientStub_STC34()
        
        let cardManager = CardManager(params: cardManagerParams)
        
        switch cardManager.getCard(withId: "375f795bf6799b18c4836d33dce5208daf0895a3f7aacbcd0366529aed2345d4").startSync() {
        case .success: XCTFail()
        case .failure(let error):
            guard let error = error as? CardManagerError,
                error == .gotWrongCard else {
                    XCTFail()
                    return
            }
        }
    }

    func test003_STC_35() {
        let generator = self.utils.getGeneratorJwtProvider(withIdentity: "identity", error: nil)
        
        let cardManagerParams = CardManagerParams(cardCrypto: self.cardCrypto, accessTokenProvider: generator, cardVerifier: VerifierStubTrue())
        cardManagerParams.cardClient = CardClientStub_STC34()
        
        let cardManager = CardManager(params: cardManagerParams)

        let publicKeyBase64 = self.testsDict["STC-34.public_key_base64"] as! String
        let publicKeyData = Data(base64Encoded: publicKeyBase64)!

        let cardContent = RawCardContent(identity: "some identity", publicKey: publicKeyData, createdAt: Date())
        let snapshot = try! JSONEncoder().encode(cardContent)
        let rawCard1 = RawSignedModel(contentSnapshot: snapshot)

        let privateKeyBase64 = self.testsDict["STC-34.private_key_base64"] as! String
        let exporter = VirgilPrivateKeyExporter(virgilCrypto: self.crypto, password: nil)
        let privateKey = try! exporter.importPrivateKey(from: Data(base64Encoded: privateKeyBase64)!)
        let extraDataSnapshot = self.testsDict["STC-34.self_signature_snapshot_base64"] as! String
        try! self.modelSigner.selfSign(model: rawCard1, privateKey: privateKey, additionalData: Data(base64Encoded: extraDataSnapshot)!)

        switch cardManager.publishCard(rawCard: rawCard1).startSync() {
        case .success: XCTFail()
        case .failure(let error):
            guard let error = error as? CardManagerError,
                error == .gotWrongCard else {
                    XCTFail()
                    return
            }
        }

        let contentStnapshot = testsDict["STC-34.content_snapshot_base64"] as! String
        let rawCard2 = RawSignedModel(contentSnapshot: Data(base64Encoded: contentStnapshot)!)

        switch cardManager.publishCard(rawCard: rawCard2).startSync() {
        case .success: XCTFail()
        case .failure(let error):
            guard let error = error as? CardManagerError,
                error == .gotWrongCard else {
                    XCTFail()
                    return
            }
        }
    }
    
    func test004_STC_36() {
        let generator = self.utils.getGeneratorJwtProvider(withIdentity: "identity", error: nil)
        
        let cardManagerParams = CardManagerParams(cardCrypto: self.cardCrypto, accessTokenProvider: generator, cardVerifier: VerifierStubTrue())
        cardManagerParams.cardClient = CardClientStub_STC34()
        
        let cardManager = CardManager(params: cardManagerParams)
        
        switch cardManager.searchCards(identity: "Alice").startSync() {
        case .success(_): XCTFail()
        case .failure(let error):
            guard let error = error as? CardManagerError,
                error == .gotWrongCard else {
                    XCTFail()
                    return
            }
        }
    }
}
