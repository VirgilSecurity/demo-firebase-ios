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
import VSCCrypto
@testable import VirgilCrypto

class VSY001_PythiaTests: XCTestCase {
    private var testsDict: Dictionary<String, String>!
    private let pythia = VirgilPythia()
    
    var kTransformationKeyID: Data!
    var kPythiaSecret: Data!
    var kPythiaScopeSecret: Data!
    var kPassword: Data!
    var kTweak: Data!
    var kDeblindedPassword: Data!
    var kTransformationPrivateKey: Data!
    var kTransformationPublicKey: Data!
    
    override func setUp() {
        super.setUp()
        
        let testFileURL = Bundle(for: type(of: self)).url(forResource: "pythia-crypto", withExtension: "json")!
        let testFileData = try! Data(contentsOf: testFileURL)
        
        self.testsDict = try! JSONSerialization.jsonObject(with: testFileData, options: JSONSerialization.ReadingOptions.init(rawValue: 0)) as! Dictionary<String, String>
        
        self.kTransformationKeyID = self.testsDict["kTransformationKeyID"]!.data(using: .utf8)!
        self.kPythiaSecret = self.testsDict["kPythiaSecret"]!.data(using: .utf8)!
        self.kPythiaScopeSecret = self.testsDict["kPythiaScopeSecret"]!.data(using: .utf8)!
        self.kPassword = self.testsDict["kPassword"]!.data(using: .utf8)!
        self.kTweak = self.testsDict["kTweak"]!.data(using: .utf8)!
        self.kDeblindedPassword = ByteArrayUtils.data(fromHexString: self.testsDict["kDeblindedPassword"]!)!
        self.kTransformationPrivateKey = ByteArrayUtils.data(fromHexString: self.testsDict["kTransformationPrivateKey"]!)!
        self.kTransformationPublicKey = ByteArrayUtils.data(fromHexString: self.testsDict["kTransformationPublicKey"]!)!
    }
    
    override func tearDown() {
        self.testsDict = nil
        
        super.tearDown()
    }
    
    func test_YTC_2() {
        let (transformationPrivateKey, transformationPublicKey) = try! self.pythia.computeTransformationKey(transformationKeyId: self.kTransformationKeyID, pythiaSecret: self.kPythiaSecret, pythiaScopeSecret: self.kPythiaScopeSecret)
        
        XCTAssert(transformationPrivateKey == kTransformationPrivateKey)
        XCTAssert(transformationPublicKey == kTransformationPublicKey)
    }
    
    func test_YTC_3() {
        let (transformationPrivateKey, _) = try! self.pythia.computeTransformationKey(transformationKeyId: self.kTransformationKeyID, pythiaSecret: self.kPythiaSecret, pythiaScopeSecret: self.kPythiaScopeSecret)
        
        let iterations = 10
        
        var lastBlindedPassword: Data? = nil
        var lastBlindingSecret: Data? = nil
        
        for _ in 0..<iterations {
            let blindedResult = try! self.pythia.blind(password: self.kPassword)
            
            XCTAssert(blindedResult.blindedPassword != lastBlindedPassword)
            XCTAssert(blindedResult.blindingSecret != lastBlindingSecret)
            
            lastBlindedPassword = blindedResult.blindedPassword
            lastBlindingSecret  = blindedResult.blindingSecret
            
            let (transformedPassword, _) = try! self.pythia.transform(blindedPassword: blindedResult.blindedPassword, tweak: self.kTweak, transformationPrivateKey: transformationPrivateKey)
            
            let deblinded = try! self.pythia.deblind(transformedPassword: transformedPassword, blindingSecret: blindedResult.blindingSecret)
            
            XCTAssert(self.kDeblindedPassword == deblinded)
        }
    }
    
    func test_YTC_4() {
        let (transformationPrivateKey, transformationPublicKey) = try! self.pythia.computeTransformationKey(transformationKeyId: self.kTransformationKeyID, pythiaSecret: self.kPythiaSecret, pythiaScopeSecret: self.kPythiaScopeSecret)
        
        let blindedResult = try! self.pythia.blind(password: self.kPassword)
        
        let (transformedPassword, transformedTweak) = try! self.pythia.transform(blindedPassword: blindedResult.blindedPassword, tweak: self.kTweak, transformationPrivateKey: transformationPrivateKey)
        
        let (proofValueC, proofValueU) = try! self.pythia.prove(transformedPassword: transformedPassword, blindedPassword: blindedResult.blindedPassword, transformedTweak: transformedTweak, transformationPrivateKey: transformationPrivateKey, transformationPublicKey: transformationPublicKey)
        
        let verified = self.pythia.verify(transformedPassword: transformedPassword, blindedPassword: blindedResult.blindedPassword, tweak: self.kTweak, transformationPublicKey: transformationPublicKey, proofValueC: proofValueC, proofValueU: proofValueU)
        
        XCTAssert(verified)
    }
}
