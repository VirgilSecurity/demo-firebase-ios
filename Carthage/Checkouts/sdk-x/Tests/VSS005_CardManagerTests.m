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
@import VirgilCrypto;

#import "VSSTestsConst.h"
#import "VSSTestUtils.h"

static const NSTimeInterval timeout = 20.;

@interface VSSAccessTokenProviderMock: NSObject<VSSAccessTokenProvider>

@property (nonatomic) VSSTestsConst *consts;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VSSTestUtils *utils;
@property (nonatomic) NSString *identity;
@property (nonatomic) void (^forceCallback)(BOOL) ;
@property NSInteger counter;

-(id)initWithIdentity:(NSString *)identity forceCallback:(void (^)(BOOL))forceCallback;

- (void)getTokenWith:(VSSTokenContext * _Nonnull)tokenContext completion:(void (^ _Nonnull)(id<VSSAccessToken> _Nullable, NSError * _Nullable))completion;

@end

@implementation VSSAccessTokenProviderMock

-(id)initWithIdentity:(NSString *)identity forceCallback:(void (^)(BOOL))forceCallback {
    self = [super init];
    
    self.identity = [identity copy];
    self.consts = [[VSSTestsConst alloc] init];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:NO];
    self.utils = [[VSSTestUtils alloc] initWithCrypto:self.crypto consts:self.consts];
    self.forceCallback = forceCallback;
    self.counter = 0;
    
    return self;
}

- (void)getTokenWith:(VSSTokenContext * _Nonnull)tokenContext completion:(void (^ _Nonnull)(id<VSSAccessToken> _Nullable, NSError * _Nullable))completion {
    NSTimeInterval interval = (self.counter % 2) == 0 ? -1 : 1000;
    self.forceCallback(tokenContext.forceReload);
    self.counter++;
    
    NSError *error;
    id<VSSAccessToken> token = [self.utils getTokenWithIdentity:self.identity ttl:interval error:&error];
    
    sleep(2);
    
    completion(token, error);
}

@end

@interface VSS005_CardManagerTests : XCTestCase

@property (nonatomic) VSSTestsConst *consts;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VSMVirgilCardCrypto *cardCrypto;
@property (nonatomic) VSSTestUtils *utils;
@property (nonatomic) VSSCardClient *cardClient;
@property (nonatomic) VSSModelSigner *modelSigner;
@property (nonatomic) VSSVirgilCardVerifier *verifier;

@end

@implementation VSS005_CardManagerTests

- (void)setUp {
    [super setUp];
    
    self.consts = [[VSSTestsConst alloc] init];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:true];
    self.cardCrypto = [[VSMVirgilCardCrypto alloc] initWithVirgilCrypto:self.crypto];
    self.utils = [[VSSTestUtils alloc] initWithCrypto:self.crypto consts:self.consts];
    self.modelSigner = [[VSSModelSigner alloc] initWithCardCrypto:self.cardCrypto];
    if (self.consts.servicePublicKey == nil) {
        self.verifier = [[VSSVirgilCardVerifier alloc] initWithCardCrypto:self.cardCrypto whitelists:@[]];
    }
    else {
        NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:self.consts.servicePublicKey options:0];
        VSSVerifierCredentials *creds = [[VSSVerifierCredentials alloc] initWithSigner:@"virgil" publicKey:publicKeyData];
        NSError *error;
        VSSWhitelist *whitelist = [[VSSWhitelist alloc] initWithVerifiersCredentials:@[creds] error:&error];
        XCTAssert(error == nil);
        self.verifier = [[VSSVirgilCardVerifier alloc] initWithCardCrypto:self.cardCrypto whitelists:@[whitelist]];
        self.verifier.verifyVirgilSignature = NO;
    }
    self.cardClient = self.consts.serviceURL == nil ? [[VSSCardClient alloc] init] : [[VSSCardClient alloc] initWithServiceUrl:self.consts.serviceURL];
}

- (void)tearDown {
    [super tearDown];
}

-(void)test001_STC_17 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Card should be published and get"];
    
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    
    [cardManager publishCardWithPrivateKey:keyPair.privateKey publicKey:keyPair.publicKey identity:identity previousCardId:nil extraFields:nil completion:^(VSSCard *card, NSError *error) {
        XCTAssert(error == nil && card != nil);
        XCTAssert(card.isOutdated == false);
        
        [cardManager getCardWithId:card.identifier completion:^(VSSCard *card1, NSError *error) {
            XCTAssert(error == nil && card1 != nil);
            XCTAssert(card1.isOutdated == false);
            
            XCTAssert([self.utils isCardsEqualWithCard:card and:card1]);
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test002_STC_18 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Card should be published and get with extra data"];

    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);

    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);

    NSMutableDictionary *dic = [NSMutableDictionary dictionary];
    [dic setValue:@"data1" forKey:@"key1"];
    [dic setValue:@"data2" forKey:@"key2"];

    [cardManager publishCardWithPrivateKey:keyPair.privateKey publicKey:keyPair.publicKey identity:identity previousCardId:nil extraFields:dic completion:^(VSSCard *card, NSError *error) {
        XCTAssert(error == nil && card != nil);
        XCTAssert(card.isOutdated == false);
        XCTAssert([[self.utils getSelfSignatureFromCard:card].extraFields isEqualToDictionary:dic]);

        [cardManager getCardWithId:card.identifier completion:^(VSSCard *card1, NSError *error) {
            XCTAssert(error == nil && card1 != nil);
            XCTAssert(card1.isOutdated == false);

            XCTAssert([self.utils isCardsEqualWithCard:card and:card1]);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test003_STC_19 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Card should be replaced"];

    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);

    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];

    VSMVirgilKeyPair *keyPair1 = [self.crypto generateKeyPairAndReturnError:&error];
    VSMVirgilKeyPair *keyPair2 = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);

    [cardManager publishCardWithPrivateKey:keyPair1.privateKey publicKey:keyPair1.publicKey identity:identity previousCardId:nil extraFields:nil completion:^(VSSCard *card1, NSError *error) {
        XCTAssert(error == nil && card1 != nil);

        [cardManager publishCardWithPrivateKey:keyPair2.privateKey publicKey:keyPair2.publicKey identity:identity previousCardId:card1.identifier extraFields:nil completion:^(VSSCard *card2, NSError *error) {
            XCTAssert(error == nil && card2 != nil);
            XCTAssert(card2.isOutdated == false);

            [cardManager getCardWithId:card1.identifier completion:^(VSSCard *card11, NSError *error) {
                XCTAssert(error == nil && card11 != nil);
                XCTAssert(card11.isOutdated == YES);

                [cardManager getCardWithId:card2.identifier completion:^(VSSCard *card21, NSError *error) {
                    XCTAssert(error == nil && card21 != nil);
                    XCTAssert(card21.isOutdated == NO);
                    XCTAssert([card21.previousCardId isEqualToString:card1.identifier]);

                    [ex fulfill];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test004_STC_20 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Cards should be published and searched"];

    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);

    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];

    VSMVirgilKeyPair *keyPair1 = [self.crypto generateKeyPairAndReturnError:&error];
    VSMVirgilKeyPair *keyPair2 = [self.crypto generateKeyPairAndReturnError:&error];
    VSMVirgilKeyPair *keyPair3 = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    
    [cardManager publishCardWithPrivateKey:keyPair1.privateKey publicKey:keyPair1.publicKey identity:identity previousCardId:nil extraFields:nil completion:^(VSSCard *card1, NSError *error) {
        XCTAssert(error == nil && card1 != nil);

        [cardManager publishCardWithPrivateKey:keyPair2.privateKey publicKey:keyPair2.publicKey identity:identity previousCardId:card1.identifier extraFields:nil completion:^(VSSCard *card2, NSError *error) {
            XCTAssert(error == nil && card2 != nil);

            [cardManager publishCardWithPrivateKey:keyPair3.privateKey publicKey:keyPair3.publicKey identity:identity previousCardId:nil extraFields:nil completion:^(VSSCard *card3, NSError *error) {
                XCTAssert(error == nil && card3 != nil);

                [cardManager searchCardsWithIdentity:identity completion:^(NSArray<VSSCard *> * returnedCards, NSError *error) {
                    XCTAssert(error == nil);
                    XCTAssert(returnedCards.count == 2);
                    card2.previousCard = card1;
                    card1.isOutdated = true;

                    for (VSSCard* card in returnedCards) {
                        if ([card.identifier isEqualToString:card2.identifier]) {
                            XCTAssert([self.utils isCardsEqualWithCard:card and:card2]);
                            XCTAssert([self.utils isCardsEqualWithCard:card.previousCard and:card1]);
                            XCTAssert([card.previousCardId isEqualToString:card1.identifier]);
                        }
                        else if ([card.identifier isEqualToString:card3.identifier]) {
                            XCTAssert([self.utils isCardsEqualWithCard:card and:card3]);
                        }
                        else {
                            XCTFail();
                        }
                    }

                    [ex fulfill];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test005_STC_21 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Card should be published"];

    NSError *error;
    NSString *identity =[[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
    NSData *publicKeyData = [self.crypto exportPublicKey:keyPair.publicKey];
    VSSVerifierCredentials *creds = [[VSSVerifierCredentials alloc] initWithSigner:@"extra" publicKey:publicKeyData];
    
    VSSWhitelist *whitelist1 = [[VSSWhitelist alloc] initWithVerifiersCredentials:@[creds] error:&error];
    XCTAssert(error == nil);
    
    VSSVirgilCardVerifier *verifier;
    if (self.consts.servicePublicKey == nil) {
        verifier = [[VSSVirgilCardVerifier alloc] initWithCardCrypto:self.cardCrypto whitelists:@[whitelist1]];
    }
    else {
        NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:self.consts.servicePublicKey options:0];
        VSSVerifierCredentials *creds = [[VSSVerifierCredentials alloc] initWithSigner:@"virgil" publicKey:publicKeyData];
        NSError *error;
        VSSWhitelist *whitelist = [[VSSWhitelist alloc] initWithVerifiersCredentials:@[creds] error:&error];
        XCTAssert(error == nil);
        verifier = [[VSSVirgilCardVerifier alloc] initWithCardCrypto:self.cardCrypto whitelists:@[whitelist, whitelist1]];
        verifier.verifyVirgilSignature = NO;
    }
    
    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    cardManagerParams.signCallback = ^void(VSSRawSignedModel *model, void (^ completionHandler)(VSSRawSignedModel *signedModel, NSError* error)) {
        NSError *error;
        [self.modelSigner signWithModel:model signer:@"extra" privateKey:keyPair.privateKey additionalData:nil error:&error];
        
        completionHandler(model, error);
    };
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    VSMVirgilKeyPair *keyPair1 = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);

    [cardManager publishCardWithPrivateKey:keyPair1.privateKey publicKey:keyPair1.publicKey identity:identity previousCardId:nil extraFields:nil completion:^(VSSCard *card, NSError *error) {
        XCTAssert(error == nil && card != nil);
        
        XCTAssert(card.signatures.count == 3);
        
        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test006_PublishRawCard {
    XCTestExpectation *ex = [self expectationWithDescription:@"Card should be published and get"];
    
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    
    VSSRawSignedModel *rawCard = [cardManager generateRawCardWithPrivateKey:keyPair.privateKey publicKey:keyPair.publicKey identity:identity previousCardId:nil extraFields:nil error:&error];
    XCTAssert(error == nil);
    
    [cardManager publishCardWithRawCard:rawCard completion:^(VSSCard *card, NSError *error) {
        XCTAssert(error == nil && card != nil);
        XCTAssert(card.isOutdated == false);
        
        [cardManager getCardWithId:card.identifier completion:^(VSSCard *card1, NSError *error) {
            XCTAssert(error == nil && card1 != nil);
            XCTAssert(card1.isOutdated == false);
            
            XCTAssert([self.utils isCardsEqualWithCard:card and:card1]);
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test007_ImportExportRawCard {
    XCTestExpectation *ex = [self expectationWithDescription:@"Card should be published and get"];
    
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSGeneratorJwtProvider *generator = [self.utils getGeneratorJwtProviderWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:generator cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;
    
    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    
    VSSRawSignedModel *rawCard = [cardManager generateRawCardWithPrivateKey:keyPair.privateKey publicKey:keyPair.publicKey identity:identity previousCardId:nil extraFields:nil error:&error];
    XCTAssert(error == nil);
    
    [cardManager publishCardWithRawCard:rawCard completion:^(VSSCard *card, NSError *error) {
        NSError *err;
        
        VSSRawSignedModel *rawCard = [cardManager exportCardAsRawCard:card error:&err];
        XCTAssert(err == nil);
        XCTAssert([rawCard.contentSnapshot isEqualToData:card.contentSnapshot]);
        XCTAssert(rawCard.signatures.count == card.signatures.count);
        XCTAssert(rawCard.signatures.count == 2);
        
        NSData *signature1;
        NSData *signature2;
        for (VSSCardSignature *cardSignature in card.signatures) {
            if ([cardSignature.signer isEqualToString:@"self"]) {
                signature1 = cardSignature.signature;
            }
        }
        
        for (VSSRawSignature *rawSignature in rawCard.signatures) {
            if ([rawSignature.signer isEqualToString:@"self"]) {
                signature2 = rawSignature.signature;
            }
        }
        
        XCTAssert([signature1 isEqualToData:signature2]);
        
        VSSCard *card1 = [cardManager importCardFromRawCard:rawCard error:&err];
        XCTAssert(err == nil);
        
        XCTAssert([self.utils isCardsEqualWithCard:card and:card1]);
        
        [ex fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test008_STC_26 {
    XCTestExpectation *ex = [self expectationWithDescription:@"All operations should proceed on second calls"];
    NSError *error;

    NSInteger __block counter = 0;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    VSSAccessTokenProviderMock *tokenProvider = [[VSSAccessTokenProviderMock alloc] initWithIdentity:identity forceCallback:^(BOOL force) {
        if (counter % 2 == 0)
            XCTAssert(!force);
        else
            XCTAssert(force);
        
        counter++;
    }];

    VSSCardManagerParams *cardManagerParams = [[VSSCardManagerParams alloc] initWithCardCrypto:self.cardCrypto accessTokenProvider:tokenProvider cardVerifier:self.verifier];
    cardManagerParams.cardClient = self.cardClient;

    VSSCardManager *cardManager = [[VSSCardManager alloc] initWithParams:cardManagerParams];

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);

    [cardManager publishCardWithPrivateKey:keyPair.privateKey publicKey:keyPair.publicKey identity:identity previousCardId:nil extraFields:nil completion:^(VSSCard *publishedCard, NSError *error) {
        XCTAssert(error == nil && publishedCard != nil);

        [cardManager getCardWithId:publishedCard.identifier completion:^(VSSCard *returnedCard, NSError *error) {
            XCTAssert(error == nil && returnedCard != nil);

            [cardManager searchCardsWithIdentity:identity completion:^(NSArray<VSSCard *> *foundCards, NSError *error) {
                XCTAssert(error == nil && foundCards.count == 1);
                
                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
