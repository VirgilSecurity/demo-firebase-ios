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
import VirgilSDKPythia
import VirgilSDK
import VirgilCryptoApiImpl
@testable import VirgilCrypto

class VSY001_BrainKeyTests: XCTestCase {
    let config = TestConfig.readFromBundle()
    
    class FakeAccessToken: AccessToken {
        func stringRepresentation() -> String {
            return ""
        }
        
        func identity() -> String {
            return ""
        }
    }
    
    class FakeAccessTokenProvider: AccessTokenProvider {
        func getToken(with tokenContext: TokenContext, completion: @escaping (AccessToken?, Error?) -> ()) {
            completion(FakeAccessToken(), nil)
        }
    }
    
    class FakeClient: PythiaClientProtocol {
        let virgilPythia = VirgilPythia()
        
        func generateSeed(blindedPassword: Data, brainKeyId: String?, token: String) throws -> Data {
            let tweak = "userId".data(using: .utf8)! + (brainKeyId?.data(using: .utf8) ?? Data())
            
            let transformationKey = try self.virgilPythia.computeTransformationKey(transformationKeyId: "test".data(using: .utf8)!, pythiaSecret: "secret".data(using: .utf8)!, pythiaScopeSecret: "scope secret".data(using: .utf8)!)
            
            return try self.virgilPythia.transform(blindedPassword: blindedPassword, tweak: tweak, transformationPrivateKey: transformationKey.0).0
        }
    }
    
    func test001_FakeClient() {
        let brainKeyContext = BrainKeyContext(client: FakeClient(), pythiaCrypto: PythiaCrypto(), accessTokenProvider: FakeAccessTokenProvider(), keyPairType: .FAST_EC_ED25519)
        let brainKey = BrainKey(context: brainKeyContext)
        
        let keyPair1 = try! brainKey.generateKeyPair(password: "some password").startSync().getResult()
        let keyPair2 = try! brainKey.generateKeyPair(password: "some password").startSync().getResult()
        let keyPair3 = try! brainKey.generateKeyPair(password: "another password").startSync().getResult()
        let keyPair4 = try! brainKey.generateKeyPair(password: "some password", brainKeyId: "my password 1").startSync().getResult()
        
        XCTAssert(keyPair1.publicKey.identifier == keyPair2.publicKey.identifier)
        XCTAssert(keyPair1.publicKey.identifier != keyPair3.publicKey.identifier)
        XCTAssert(keyPair1.publicKey.identifier != keyPair4.publicKey.identifier)
    }
    
    func test002_RealClient() {
        let client = PythiaClient(serviceUrl: URL(string: self.config.ServiceURL)!)
        let apiKey = try! VirgilCrypto().importPrivateKey(from: Data(base64Encoded: self.config.ApiPrivateKey)!)
        
        let generator = JwtGenerator(apiKey: apiKey, apiPublicKeyIdentifier: self.config.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(), appId: self.config.AppId, ttl: 3600)
        let identity = UUID().uuidString
        let provider = GeneratorJwtProvider(jwtGenerator: generator, defaultIdentity: identity)
        
        let brainKeyContext = BrainKeyContext(client: client, accessTokenProvider: provider)
        let brainKey = BrainKey(context: brainKeyContext)
        
        let keyPair1 = try! brainKey.generateKeyPair(password: "some password").startSync().getResult()
        sleep(5)
        let keyPair2 = try! brainKey.generateKeyPair(password: "some password").startSync().getResult()
        sleep(5)
        let keyPair3 = try! brainKey.generateKeyPair(password: "another password").startSync().getResult()
        sleep(5)
        let keyPair4 = try! brainKey.generateKeyPair(password: "some password", brainKeyId: "my password 1").startSync().getResult()
        
        XCTAssert(keyPair1.publicKey.identifier == keyPair2.publicKey.identifier)
        XCTAssert(keyPair1.publicKey.identifier != keyPair3.publicKey.identifier)
        XCTAssert(keyPair1.publicKey.identifier != keyPair4.publicKey.identifier)
    }
}
