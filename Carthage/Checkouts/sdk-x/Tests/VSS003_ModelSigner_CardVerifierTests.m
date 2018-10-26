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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
@import VirgilSDK;
@import VirgilCryptoApiImpl;
@import VirgilCrypto;

#import "VSSTestsConst.h"
#import "VSSTestUtils.h"

@interface VSS003_ModelSignerCardVerifierTests : XCTestCase

@property (nonatomic) VSSTestsConst *consts;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VSMVirgilCardCrypto *cardCrypto;
@property (nonatomic) VSSTestUtils *utils;
@property (nonatomic) VSSCardClient *cardClient;
@property (nonatomic) VSSModelSigner *modelSigner;
@property (nonatomic) VSSVirgilCardVerifier *verifier;
@property (nonatomic) NSDictionary *testData;

@end

@implementation VSS003_ModelSignerCardVerifierTests

- (void)setUp {
    [super setUp];
    
    self.consts = [[VSSTestsConst alloc] init];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:true];
    self.cardCrypto = [[VSMVirgilCardCrypto alloc] initWithVirgilCrypto:self.crypto];
    self.utils = [[VSSTestUtils alloc] initWithCrypto:self.crypto consts:self.consts];
    self.cardClient = self.consts.serviceURL == nil ? [[VSSCardClient alloc] init] : [[VSSCardClient alloc] initWithServiceUrl:self.consts.serviceURL];
    self.modelSigner = [[VSSModelSigner alloc] initWithCardCrypto:self.cardCrypto];
    self.verifier = [[VSSVirgilCardVerifier alloc] initWithCardCrypto:self.cardCrypto whitelists:@[]];
    
    self.verifier.verifySelfSignature = false;
    self.verifier.verifyVirgilSignature = false;
    
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    NSString *path = [bundle pathForResource:@"data" ofType:@"json"];
    NSData *dicData = [[NSData alloc] initWithContentsOfFile:path];
    XCTAssert(dicData != nil);
    
    self.testData = [NSJSONSerialization JSONObjectWithData:dicData options:kNilOptions error:nil];
}

- (void)tearDown {
    [super tearDown];
}

- (void)test001_STC_8 {
    NSError *error;
    VSMVirgilKeyPair *keyPair1 = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    NSData *data = [self.utils getRandomData];
    
    VSSRawSignedModel *rawCard = [[VSSRawSignedModel alloc] initWithContentSnapshot:data];
    XCTAssert(rawCard.signatures.count == 0);
    
    [self.modelSigner selfSignWithModel:rawCard privateKey:keyPair1.privateKey additionalData:nil error:&error];
    XCTAssert(rawCard.signatures.count == 1 && error == nil);
    
    VSSRawSignature *signature1 = rawCard.signatures[0];
    XCTAssert(signature1.snapshot == nil);
    XCTAssert([signature1.signer isEqualToString:@"self"]);
    XCTAssert(signature1.signature.length != 0);

    BOOL success = [self.crypto verifySignature:signature1.signature of:data with:keyPair1.publicKey];
    XCTAssert(success);
    
    [self.modelSigner selfSignWithModel:rawCard privateKey:keyPair1.privateKey additionalData:nil error:&error];
    XCTAssert(error != nil);
    error = nil;
    
    VSMVirgilKeyPair *keyPair2 = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    
    [self.modelSigner signWithModel:rawCard signer:@"test" privateKey:keyPair2.privateKey additionalData:nil error:&error];
    XCTAssert(rawCard.signatures.count == 2 && error == nil);
    
    VSSRawSignature *signature2 = rawCard.signatures[1];
    XCTAssert(signature2.snapshot == nil && [signature2.signer isEqualToString:@"test"]);
    XCTAssert(signature2.signature.length != 0);
    
    success = [self.crypto verifySignature:signature2.signature of:data with:keyPair2.publicKey];
    XCTAssert(success);
    
    [self.modelSigner signWithModel:rawCard signer:@"test" privateKey:keyPair2.privateKey additionalData:nil error:&error];
    XCTAssert(error != nil);
}

-(void)test002_STC_9_Dict {
    NSError *error;
    VSMVirgilKeyPair *keyPair1 = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    NSData *data = [self.utils getRandomData];
    
    VSSRawSignedModel *rawCard = [[VSSRawSignedModel alloc] initWithContentSnapshot:data];
    XCTAssert(rawCard.signatures.count == 0);
    
    NSDictionary *dict = @{
                           @"key": @"value"
                           };
    
    [self.modelSigner selfSignWithModel:rawCard privateKey:keyPair1.privateKey extraFields:dict error:&error];
    XCTAssert(rawCard.signatures.count == 1 && error == nil);
    
    VSSRawSignature *signature1 = rawCard.signatures[0];
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dict options:0 error:nil];
    
    XCTAssert([jsonData isEqualToData:signature1.snapshot]);
    XCTAssert([signature1.signer isEqualToString:@"self"]);
    XCTAssert(signature1.signature.length != 0);
    
    NSMutableData *selfData = [rawCard.contentSnapshot mutableCopy];
    [selfData appendData:jsonData];
    
    BOOL success = [self.crypto verifySignature:signature1.signature of:selfData with:keyPair1.publicKey];
    XCTAssert(success);
    
    VSMVirgilKeyPair *keyPair2 = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    
    [self.modelSigner signWithModel:rawCard signer:@"test" privateKey:keyPair2.privateKey extraFields:dict error:&error];
    XCTAssert(rawCard.signatures.count == 2 && error == nil);
    
    VSSRawSignature *signature2 = rawCard.signatures[1];
    XCTAssert([jsonData isEqualToData:signature2.snapshot]);
    XCTAssert([signature2.signer isEqualToString:@"test"]);
    XCTAssert(signature2.signature.length != 0);
    
    success = [self.crypto verifySignature:signature2.signature of:selfData with:keyPair2.publicKey];
    XCTAssert(success);
}

-(void)test002_STC_9_RawData {
    NSError *error;
    VSMVirgilKeyPair *keyPair1 = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    NSData *data = [self.utils getRandomData];
    
    VSSRawSignedModel *rawCard = [[VSSRawSignedModel alloc] initWithContentSnapshot:data];
    XCTAssert(rawCard.signatures.count == 0);
    
    NSDictionary *dict = @{
                           @"key": @"value"
                           };
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dict options:0 error:nil];
    
    [self.modelSigner selfSignWithModel:rawCard privateKey:keyPair1.privateKey additionalData:jsonData error:&error];
    XCTAssert(rawCard.signatures.count == 1 && error == nil);
    
    VSSRawSignature *signature1 = rawCard.signatures[0];
    XCTAssert([jsonData isEqualToData:signature1.snapshot]);
    XCTAssert([signature1.signer isEqualToString:@"self"]);
    XCTAssert(signature1.signature.length != 0);
    
    NSMutableData *selfData = [rawCard.contentSnapshot mutableCopy];
    [selfData appendData:jsonData];
    
    BOOL success = [self.crypto verifySignature:signature1.signature of:selfData with:keyPair1.publicKey];
    XCTAssert(success);
    
    VSMVirgilKeyPair *keyPair2 = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    
    [self.modelSigner signWithModel:rawCard signer:@"test" privateKey:keyPair2.privateKey additionalData:jsonData error:&error];
    XCTAssert(rawCard.signatures.count == 2 && error == nil);
    
    VSSRawSignature *signature2 = rawCard.signatures[1];
    XCTAssert([jsonData isEqualToData:signature2.snapshot]);
    XCTAssert([signature2.signer isEqualToString:@"test"]);
    XCTAssert(signature2.signature.length != 0);
    
    success = [self.crypto verifySignature:signature2.signature of:selfData with:keyPair2.publicKey];
    XCTAssert(success);
}

-(void)test003_STC_10 {
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    NSString *cardString = self.testData[@"STC-10.as_string"];
    XCTAssert(error == nil);
    
    VSSCard *card = [cardManager importCardFromBase64Encoded:cardString error:&error];
    XCTAssert(card != nil && error == nil);

    NSString *privateKey1Base64 = self.testData[@"STC-10.private_key1_base64"];
    VSMVirgilPrivateKeyExporter *exporter = [[VSMVirgilPrivateKeyExporter alloc] initWithVirgilCrypto:self.crypto password:nil];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:privateKey1Base64 options:0];
    VSMVirgilPrivateKey *privateKey = (VSMVirgilPrivateKey *)[exporter importPrivateKeyFrom:data error:&error];
    XCTAssert(error == nil);

    VSMVirgilPublicKey *publicKey1 = [self.crypto extractPublicKeyFrom:privateKey error:&error];
    NSData *publicKey1Data = [self.crypto exportPublicKey:publicKey1];
    XCTAssert(error == nil);
    
    XCTAssert([self.verifier verifyCard:card]);
    
    self.verifier.verifySelfSignature = true;
    XCTAssert([self.verifier verifyCard:card]);

    self.verifier.verifyVirgilSignature = true;
    XCTAssert([self.verifier verifyCard:card]);
    
    NSData *publicKeyData2 = [self.crypto exportPublicKey:[self.crypto generateKeyPairAndReturnError:nil].publicKey];
    NSData *publicKeyData3 = [self.crypto exportPublicKey:[self.crypto generateKeyPairAndReturnError:nil].publicKey];
    
    VSSVerifierCredentials *creds1 = [[VSSVerifierCredentials alloc] initWithSigner:@"extra" publicKey:publicKey1Data];
    VSSWhitelist *whitelist1 = [[VSSWhitelist alloc] initWithVerifiersCredentials:@[creds1] error:&error];
    XCTAssert(error == nil);
    self.verifier.whitelists = @[whitelist1];

    XCTAssert([self.verifier verifyCard:card]);
    
    VSSVerifierCredentials *creds21 = [[VSSVerifierCredentials alloc] initWithSigner:@"extra" publicKey:publicKey1Data];
    VSSVerifierCredentials *creds22 = [[VSSVerifierCredentials alloc] initWithSigner:@"test1" publicKey:publicKeyData2];
    VSSWhitelist *whitelist2 = [[VSSWhitelist alloc] initWithVerifiersCredentials:@[creds21, creds22] error:&error];
    XCTAssert(error == nil);
    self.verifier.whitelists = @[whitelist2];
    
    XCTAssert([self.verifier verifyCard:card]);
    
    VSSVerifierCredentials *creds31 = [[VSSVerifierCredentials alloc] initWithSigner:@"extra" publicKey:publicKey1Data];
    VSSVerifierCredentials *creds32 = [[VSSVerifierCredentials alloc] initWithSigner:@"test1" publicKey:publicKeyData2];
    VSSVerifierCredentials *creds33 = [[VSSVerifierCredentials alloc] initWithSigner:@"test2" publicKey:publicKeyData3];
    VSSWhitelist *whitelist31 = [[VSSWhitelist alloc] initWithVerifiersCredentials:@[creds31, creds32] error:&error];
    XCTAssert(error == nil);
    VSSWhitelist *whitelist32 = [[VSSWhitelist alloc] initWithVerifiersCredentials:@[creds33] error:&error];
    XCTAssert(error == nil);
    self.verifier.whitelists = @[whitelist31, whitelist32];
    
    XCTAssert(![self.verifier verifyCard:card]);
}

-(void)test004_STC_11 {
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    NSString *cardString = self.testData[@"STC-11.as_string"];
    XCTAssert(error == nil);
    VSSCard *card = [cardManager importCardFromBase64Encoded:cardString error:&error];
    XCTAssert(card != nil);
    
    XCTAssert([self.verifier verifyCard:card]);
    
    self.verifier.verifySelfSignature = true;
    XCTAssert(![self.verifier verifyCard:card]);
}

-(void)test005_STC_12 {
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    NSString *cardString = self.testData[@"STC-12.as_string"];
    XCTAssert(error == nil);
    VSSCard *card = [cardManager importCardFromBase64Encoded:cardString error:&error];
    XCTAssert(card != nil);
    
    XCTAssert([self.verifier verifyCard:card]);
    
    self.verifier.verifyVirgilSignature = true;
    XCTAssert(![self.verifier verifyCard:card]);
}

-(void)test006_STC_14 {
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    NSString *cardString = self.testData[@"STC-14.as_string"];
    XCTAssert(error == nil);
    VSSCard *card = [cardManager importCardFromBase64Encoded:cardString error:&error];
    XCTAssert(card != nil);
    
    self.verifier.verifyVirgilSignature = true;
    XCTAssert(![self.verifier verifyCard:card]);
}

-(void)test007_STC_15 {
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);

    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    NSString *cardString = self.testData[@"STC-15.as_string"];
    XCTAssert(error == nil);
    VSSCard *card = [cardManager importCardFromBase64Encoded:cardString error:&error];
    XCTAssert(card != nil);
    
    self.verifier.verifySelfSignature = true;
    XCTAssert(![self.verifier verifyCard:card]);
}

-(void)test008_STC_16 {
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    NSString *cardString = self.testData[@"STC-16.as_string"];
    XCTAssert(error == nil);
    VSSCard *card = [cardManager importCardFromBase64Encoded:cardString error:&error];
    XCTAssert(card != nil);
    
    NSData *pubicKeyBase64 = [[NSData alloc] initWithBase64EncodedString:self.testData[@"STC-16.public_key1_base64"] options:0];
    XCTAssert(pubicKeyBase64 != nil);
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
    NSData *publicKeyData = [self.crypto exportPublicKey:keyPair.publicKey];
    
    VSSVerifierCredentials *creds1 = [[VSSVerifierCredentials alloc] initWithSigner:@"extra" publicKey:publicKeyData];
    VSSWhitelist *whitelist1 = [[VSSWhitelist alloc] initWithVerifiersCredentials:@[creds1] error:&error];
    XCTAssert(error == nil);
    self.verifier.whitelists = @[whitelist1];
    
    XCTAssert(![self.verifier verifyCard:card]);
    
    VSSVerifierCredentials *creds2 = [[VSSVerifierCredentials alloc] initWithSigner:@"extra" publicKey:pubicKeyBase64];
    VSSWhitelist *whitelist2 = [[VSSWhitelist alloc] initWithVerifiersCredentials:@[creds2] error:&error];
    XCTAssert(error == nil);
    self.verifier.whitelists = @[whitelist2];
    
    XCTAssert([self.verifier verifyCard:card]);
}

@end
