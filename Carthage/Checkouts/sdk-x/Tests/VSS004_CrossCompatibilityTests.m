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

@interface VSS004_CrossCompatibilityTests: XCTestCase

@property (nonatomic) VSSTestsConst *consts;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VSMVirgilCardCrypto *cardCrypto;
@property (nonatomic) VSSTestUtils *utils;
@property (nonatomic) VSSCardClient *cardClient;
@property (nonatomic) VSSModelSigner *modelSigner;
@property (nonatomic) VSSVirgilCardVerifier *verifier;
@property (nonatomic) NSDictionary *testData;

@end

@implementation VSS004_CrossCompatibilityTests

- (void)setUp {
    [super setUp];
    
    self.consts = [[VSSTestsConst alloc] init];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:true];
    self.cardCrypto = [[VSMVirgilCardCrypto alloc] initWithVirgilCrypto:self.crypto];
    self.utils = [[VSSTestUtils alloc] initWithCrypto:self.crypto consts:self.consts];
    self.modelSigner = [[VSSModelSigner alloc] initWithCardCrypto:self.cardCrypto];
    self.verifier = [[VSSVirgilCardVerifier alloc] initWithCardCrypto:self.cardCrypto whitelists:@[]];
    self.cardClient = self.consts.serviceURL == nil ? [[VSSCardClient alloc] init] : [[VSSCardClient alloc] initWithServiceUrl:self.consts.serviceURL];
    
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

- (void)test001_STC_1 {
    NSString *rawCardString = self.testData[@"STC-1.as_string"];
    
    NSError *error;
    VSSRawSignedModel *rawCard1 = [VSSRawSignedModel importFromBase64Encoded:rawCardString error:&error];
    XCTAssert(error == nil && rawCard1 != nil);
    
    VSSRawCardContent *cardContent1 = [[VSSRawCardContent alloc] initWithSnapshot:rawCard1.contentSnapshot error:nil];
    XCTAssert(cardContent1 != nil);
    
    XCTAssert([cardContent1.identity isEqualToString:@"test"]);
    XCTAssert([[cardContent1.publicKey base64EncodedStringWithOptions:0] isEqualToString:@"MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk="]);
    XCTAssert([cardContent1.version isEqualToString:@"5.0"]);
    XCTAssert(cardContent1.createdAt == 1515686245);
    XCTAssert(cardContent1.previousCardId == nil);
    XCTAssert(rawCard1.signatures.count == 0);

    NSData *rawCardDictData = [self.testData[@"STC-1.as_json"] dataUsingEncoding:NSUTF8StringEncoding];
    XCTAssert(rawCardDictData != nil);
    
    NSDictionary *rawCardDict = [NSJSONSerialization JSONObjectWithData:rawCardDictData options:kNilOptions error:nil];
    XCTAssert(rawCardDict != nil);
    
    VSSRawSignedModel *rawCard2 = [VSSRawSignedModel importFromJson:rawCardDict error:&error];
    XCTAssert(error == nil && rawCard2 != nil);
    
    XCTAssert([rawCard2.contentSnapshot isEqualToData:rawCard1.contentSnapshot]);
    XCTAssert(rawCard2.signatures.count == 0);
    
    NSDictionary *rawCardContentDict = [NSJSONSerialization JSONObjectWithData:[cardContent1 snapshotAndReturnError:nil] options:0 error:nil];
    XCTAssert(rawCardContentDict != nil);
    NSDictionary *rawCardContentDictImported = [NSJSONSerialization JSONObjectWithData:rawCard1.contentSnapshot options:0 error:nil];
    XCTAssert([rawCardContentDict isEqualToDictionary:rawCardContentDictImported]);
    
    NSDictionary *exportedRawCard1 = [rawCard1 exportAsJsonAndReturnError:&error];
    XCTAssert(error == nil);
    XCTAssert([exportedRawCard1 isEqualToDictionary:rawCardDict]);

    NSString *exportedRawCard1String = [rawCard1 exportAsBase64EncodedStringAndReturnError:&error];
    XCTAssert(error == nil);
    NSDictionary *exportedRawCard1Dict = [NSJSONSerialization JSONObjectWithData:[[NSData alloc] initWithBase64EncodedString:exportedRawCard1String options:0] options:0 error:nil];
    XCTAssert([exportedRawCard1Dict isEqualToDictionary:rawCardDict]);
}

- (void)test002_STC_2 {
    NSString *rawCardString = self.testData[@"STC-2.as_string"];
    XCTAssert(rawCardString != nil);
    
    NSError *error;
    VSSRawSignedModel *rawCard1 = [VSSRawSignedModel importFromBase64Encoded:rawCardString error:&error];
    XCTAssert(error == nil && rawCard1 != nil);
    
    VSSRawCardContent *cardContent1 = [[VSSRawCardContent alloc] initWithSnapshot:rawCard1.contentSnapshot error:nil];
    XCTAssert(cardContent1 != nil);
    
    XCTAssert([cardContent1.identity isEqualToString:@"test"]);
    XCTAssert([[cardContent1.publicKey base64EncodedStringWithOptions:0] isEqualToString:@"MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk="]);
    XCTAssert([cardContent1.version isEqualToString:@"5.0"]);
    XCTAssert(cardContent1.createdAt == 1515686245);
    XCTAssert([cardContent1.previousCardId isEqualToString:@"a666318071274adb738af3f67b8c7ec29d954de2cabfd71a942e6ea38e59fff9"]);
    XCTAssert(rawCard1.signatures.count == 3);
    
    for (VSSRawSignature* signature in rawCard1.signatures) {
        if ([signature.signer isEqualToString:@"self"]) {
            XCTAssert([[signature.signature base64EncodedStringWithOptions:0] isEqualToString:@"MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8="]);
            XCTAssert(signature.snapshot == nil);
        } else if ([signature.signer isEqualToString:@"virgil"]) {
            XCTAssert([[signature.signature base64EncodedStringWithOptions:0] isEqualToString:@"MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8="]);
            XCTAssert(signature.snapshot == nil);
        } else if ([signature.signer isEqualToString:@"extra"]) {
            XCTAssert([[signature.signature base64EncodedStringWithOptions:0] isEqualToString:@"MFEwDQYJYIZIAWUDBAIDBQAEQCA3O35Rk+doRPHkHhJJKJyFxz2APDZOSBZi6QhmI7BP3yTb65gRYwu0HtNNYdMRsEqVj9IEKhtDelf4SKpbJwo="]);
            XCTAssert(signature.snapshot == nil);
        }
        else {
            XCTFail();
        }
    }
    
    NSData *rawCardDictData = [self.testData[@"STC-2.as_json"] dataUsingEncoding:NSUTF8StringEncoding];
    XCTAssert(rawCardDictData != nil);
    
    NSDictionary *rawCardDict = [NSJSONSerialization JSONObjectWithData:rawCardDictData options:kNilOptions error:nil];
    XCTAssert(rawCardDict != nil);
    
    VSSRawSignedModel *rawCard2 = [VSSRawSignedModel importFromJson:rawCardDict error:&error];
    XCTAssert(error == nil && rawCard2 != nil);
    
    XCTAssert([rawCard2.contentSnapshot isEqualToData:rawCard1.contentSnapshot]);
    XCTAssert(rawCard2.signatures.count == 3);
    
    XCTAssert([self.utils isRawSignaturesEqualWithSignatures:rawCard1.signatures and:rawCard2.signatures]);
    
    NSDictionary *rawCardContentDict = [NSJSONSerialization JSONObjectWithData:[cardContent1 snapshotAndReturnError:nil] options:0 error:nil];
    XCTAssert(rawCardContentDict != nil);
    NSDictionary *rawCardContentDictImported = [NSJSONSerialization JSONObjectWithData:rawCard1.contentSnapshot options:0 error:nil];
    XCTAssert([rawCardContentDict isEqualToDictionary:rawCardContentDictImported]);
    
    NSDictionary *exportedRawCard1 = [rawCard1 exportAsJsonAndReturnError:&error];
    XCTAssert(error == nil);
    XCTAssert([exportedRawCard1 isEqualToDictionary:rawCardDict]);
    
    NSString *exportedRawCard1String = [rawCard1 exportAsBase64EncodedStringAndReturnError:&error];
    XCTAssert(error == nil);
    NSDictionary *exportedRawCard1Dict = [NSJSONSerialization JSONObjectWithData:[[NSData alloc] initWithBase64EncodedString:exportedRawCard1String options:0] options:0 error:nil];
    XCTAssert([exportedRawCard1Dict isEqualToDictionary:rawCardDict]);
}

-(void)test003_STC_3 {
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    NSString *rawCardString = self.testData[@"STC-3.as_string"];
    XCTAssert(rawCardString != nil);
 
    VSSCard *card1 = [cardManager importCardFromBase64Encoded:rawCardString error:&error];
    XCTAssert(card1 != nil && error == nil);
    
    NSDate *date = [[NSDate alloc] initWithTimeIntervalSince1970:1515686245];
    
    XCTAssert([card1.identifier isEqualToString:self.testData[@"STC-3.card_id"]]);
    XCTAssert([card1.identity isEqualToString:@"test"]);
    XCTAssert(card1.publicKey != nil);
    XCTAssert([[[self.crypto exportPublicKey:(VSMVirgilPublicKey *)card1.publicKey] base64EncodedStringWithOptions:0] isEqualToString:self.testData[@"STC-3.public_key_base64"]]);
    XCTAssert([card1.version isEqualToString:@"5.0"]);
    XCTAssert(card1.previousCard == nil);
    XCTAssert(card1.previousCardId == nil);
    XCTAssert(card1.signatures.count == 0);
    XCTAssert([card1.createdAt isEqualToDate:date]);
    
    NSData *rawCardDic = [self.testData[@"STC-3.as_json"] dataUsingEncoding:NSUTF8StringEncoding];
    XCTAssert(rawCardDic != nil);
    
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:rawCardDic options:kNilOptions error:nil];
    XCTAssert(dic != nil);
    
    VSSCard *card2 = [cardManager importCardFromJson:dic error:&error];
    XCTAssert(card2 != nil);
    
    [self.utils isCardsEqualWithCard:card1 and:card2];
    
    NSString *exportedCardString = [cardManager exportCardAsBase64EncodedString:card1 error:&error];
    XCTAssert(error == nil);
    
    NSDictionary *exportedStringDict = [NSJSONSerialization JSONObjectWithData:[[NSData alloc] initWithBase64EncodedString:exportedCardString options:0] options:0 error:&error];
    XCTAssert(error == nil);
    XCTAssert([exportedStringDict isEqualToDictionary:dic]);
    
    NSDictionary *exportedJsonDict = [cardManager exportCardAsJson:card2 error:&error];
    XCTAssert(error == nil);
    XCTAssert([exportedJsonDict isEqualToDictionary:dic]);
}

-(void)test004_STC_4 {
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    NSString *rawCardString = self.testData[@"STC-4.as_string"];
    XCTAssert(rawCardString != nil);
    
    VSSCard *card1 = [cardManager importCardFromBase64Encoded:rawCardString error:&error];
    XCTAssert(card1 != nil);
    
    NSDate *date = [[NSDate alloc] initWithTimeIntervalSince1970:1515686245];
    
    XCTAssert([card1.identifier isEqualToString:self.testData[@"STC-4.card_id"]]);
    XCTAssert([card1.identity isEqualToString:@"test"]);
    XCTAssert([[[self.crypto exportPublicKey:(VSMVirgilPublicKey *)card1.publicKey] base64EncodedStringWithOptions:0] isEqualToString:self.testData[@"STC-4.public_key_base64"]]);
    XCTAssert([card1.version isEqualToString:@"5.0"]);
    XCTAssert(card1.previousCard == nil);
    XCTAssert(card1.previousCardId == nil);
    XCTAssert(card1.signatures.count == 3);
    XCTAssert([card1.createdAt isEqualToDate:date]);
    
    for (VSSCardSignature* signature in card1.signatures) {
        if ([signature.signer isEqualToString:@"self"]) {
            XCTAssert([[signature.signature base64EncodedStringWithOptions:0] isEqualToString:self.testData[@"STC-4.signature_self_base64"]]);
            XCTAssert(signature.snapshot == nil);
        } else if ([signature.signer isEqualToString:@"virgil"]) {
            XCTAssert([[signature.signature base64EncodedStringWithOptions:0] isEqualToString:self.testData[@"STC-4.signature_virgil_base64"]]);
            XCTAssert(signature.snapshot == nil);
        } else if ([signature.signer isEqualToString:@"extra"]) {
            XCTAssert([[signature.signature base64EncodedStringWithOptions:0] isEqualToString:self.testData[@"STC-4.signature_extra_base64"]]);
            XCTAssert(signature.snapshot == nil);
        }
        else {
            XCTFail();
        }
    }
    
    NSData *rawCardDic = [self.testData[@"STC-4.as_json"] dataUsingEncoding:NSUTF8StringEncoding];
    XCTAssert(rawCardDic != nil);
    
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:rawCardDic options:kNilOptions error:nil];
    XCTAssert(dic != nil);
    
    VSSCard *card2 = [cardManager importCardFromJson:dic error:&error];
    XCTAssert(card2 != nil);
    XCTAssert([self.utils isCardsEqualWithCard:card1 and:card2]);
    XCTAssert([self.utils isCardSignaturesEqualWithSignatures:card1.signatures and:card2.signatures]);
    
    NSString *exportedCardString = [cardManager exportCardAsBase64EncodedString:card1 error:&error];
    XCTAssert(error == nil);
    
    NSDictionary *exportedStringDict = [NSJSONSerialization JSONObjectWithData:[[NSData alloc] initWithBase64EncodedString:exportedCardString options:0] options:0 error:&error];
    XCTAssert(error == nil);
    XCTAssert([exportedStringDict isEqualToDictionary:dic]);
    
    NSDictionary *exportedJsonDict = [cardManager exportCardAsJson:card2 error:&error];
    XCTAssert(error == nil);
    XCTAssert([exportedJsonDict isEqualToDictionary:dic]);
}

-(void)test005_STC_22 {
    NSError *error;
    VSMVirgilAccessTokenSigner *signer = [[VSMVirgilAccessTokenSigner alloc] initWithVirgilCrypto:self.crypto];
    NSData *publicKeyBase64 = [[NSData alloc] initWithBase64EncodedString:self.testData[@"STC-22.api_public_key_base64"] options:0];
    VSMVirgilPublicKey *publicKey = [self.crypto importPublicKeyFrom:publicKeyBase64 error:&error];
    XCTAssert(error == nil);
    
    VSSJwtVerifier *verifier = [[VSSJwtVerifier alloc] initWithApiPublicKey:publicKey apiPublicKeyIdentifier:self.testData[@"STC-22.api_key_id"] accessTokenSigner:signer];
    
    VSSJwt *jwt = [[VSSJwt alloc] initWithStringRepresentation:self.testData[@"STC-22.jwt"] error:&error];
    XCTAssert(error == nil && jwt != nil);
    
    XCTAssert([jwt.headerContent.algorithm isEqualToString:@"VEDS512"]);
    XCTAssert([jwt.headerContent.contentType isEqualToString:@"virgil-jwt;v=1"]);
    XCTAssert([jwt.headerContent.type isEqualToString:@"JWT"]);
    XCTAssert([jwt.headerContent.keyIdentifier isEqualToString:self.testData[@"STC-22.api_key_id"]]);
    
    XCTAssert([jwt.bodyContent.identity isEqualToString:@"some_identity"]);
    XCTAssert([jwt.bodyContent.appId isEqualToString:@"13497c3c795e3a6c32643b0a76957b70d2332080762469cdbec89d6390e6dbd7"]);
    XCTAssert(jwt.bodyContent.issuedAt.timeIntervalSince1970 == 1518513309);
    XCTAssert(jwt.bodyContent.expiresAt.timeIntervalSince1970 == 1518513909);
    XCTAssert([jwt isExpiredWithDate:NSDate.date] == true);
    
    XCTAssert([jwt.stringRepresentation isEqualToString:self.testData[@"STC-22.jwt"]]);
    
    NSDictionary *dic = @{
                          @"username":@"some_username"
                          };
    XCTAssert([jwt.bodyContent.additionalData isEqualToDictionary:dic]);
    
    XCTAssert([verifier verifyWithToken:jwt]);
}

-(void)test006_STC_23 {
    NSError *error;
    
    VSMVirgilAccessTokenSigner *signer = [[VSMVirgilAccessTokenSigner alloc] initWithVirgilCrypto:self.crypto];
    NSData *publicKeyBase64 = [[NSData alloc] initWithBase64EncodedString:self.testData[@"STC-23.api_public_key_base64"] options:0];
    VSMVirgilPublicKey *publicKey = [self.crypto importPublicKeyFrom:publicKeyBase64 error:&error];
    XCTAssert(error == nil);
    VSSJwtVerifier *verifier = [[VSSJwtVerifier alloc] initWithApiPublicKey:publicKey apiPublicKeyIdentifier:self.testData[@"STC-23.api_key_id"] accessTokenSigner:signer];
    
    NSString *apiKeyStringBase64 = self.testData[@"STC-23.api_private_key_base64"];
    NSData *apiKeyDataBase64 = [[NSData alloc] initWithBase64EncodedString:apiKeyStringBase64 options:0];
    VSMVirgilPrivateKeyExporter *exporter = [[VSMVirgilPrivateKeyExporter alloc] initWithVirgilCrypto:self.crypto password:nil];
    VSMVirgilPrivateKey *privateKey = (VSMVirgilPrivateKey *)[exporter importPrivateKeyFrom:apiKeyDataBase64 error:&error];
    XCTAssert(error == nil);
    
    VSSJwtGenerator *generator = [[VSSJwtGenerator alloc] initWithApiKey:privateKey apiPublicKeyIdentifier:self.testData[@"STC-23.api_key_id"] accessTokenSigner:signer appId:self.testData[@"STC-23.app_id"] ttl:1000];
    
    NSString *identity = @"some_identity";
    NSDictionary *dic = @{
                          @"username": @"some_username"
                          };
    VSSJwt *jwt = [generator generateTokenWithIdentity:identity additionalData:dic error:&error];
    XCTAssert(error == nil);
    XCTAssert(jwt != nil);
    
    XCTAssert([jwt.headerContent.algorithm isEqualToString:@"VEDS512"]);
    XCTAssert([jwt.headerContent.contentType isEqualToString:@"virgil-jwt;v=1"]);
    XCTAssert([jwt.headerContent.type isEqualToString:@"JWT"]);
    XCTAssert([jwt.headerContent.keyIdentifier isEqualToString:self.testData[@"STC-23.api_key_id"]]);
    
    XCTAssert([jwt.bodyContent.identity isEqualToString:identity]);
    XCTAssert([jwt.bodyContent.appId isEqualToString:self.testData[@"STC-23.app_id"]]);
    XCTAssert(![jwt isExpiredWithDate:NSDate.date]);
    
    XCTAssert([jwt.bodyContent.additionalData isEqualToDictionary:dic]);
    
    XCTAssert([verifier verifyWithToken:jwt]);
}

@end
