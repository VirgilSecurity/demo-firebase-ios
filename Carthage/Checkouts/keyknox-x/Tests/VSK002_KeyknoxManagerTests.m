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
@import VirgilSDKKeyknox;
@import VirgilCrypto;
@import VirgilCryptoApiImpl;

#if TARGET_OS_IOS
    #import "VirgilSDKKeyknox_AppTests_iOS-Swift.h"
#elif TARGET_OS_TV
    #import "VirgilSDKKeyknox_AppTests_tvOS-Swift.h"
#elif TARGET_OS_OSX
    #import "VirgilSDKKeyknox_macOS_Tests-Swift.h"
#endif

static const NSTimeInterval timeout = 20.;

@interface VSK002_KeyknoxManagerTests : XCTestCase

@property (nonatomic) TestConfig *config;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VSKKeyknoxManager *keyknoxManager;
@property (nonatomic) NSInteger numberOfKeys;
@property (nonatomic) VSKKeyknoxClient *keyknoxClient;
@property (nonatomic) id<VSSAccessTokenProvider> provider;
@property (nonatomic) VSMVirgilKeyPair *keyPair;

@end

@implementation VSK002_KeyknoxManagerTests

- (void)setUp {
    [super setUp];
    
    self.config = [TestConfig readFromBundle];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:NO];
    self.keyknoxClient = [[VSKKeyknoxClient alloc] initWithServiceUrl:[[NSURL alloc] initWithString:self.config.ServiceURL]];
    
    VSMVirgilPrivateKey *apiKey = [self.crypto importPrivateKeyFrom:[[NSData alloc] initWithBase64EncodedString:self.config.ApiPrivateKey options:0] password:nil error:nil];
    VSSJwtGenerator *generator = [[VSSJwtGenerator alloc] initWithApiKey:apiKey apiPublicKeyIdentifier:self.config.ApiPublicKeyId accessTokenSigner:[[VSMVirgilAccessTokenSigner alloc] initWithVirgilCrypto:self.crypto] appId:self.config.AppId ttl:600];
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    
    self.provider = [[VSSCachingJwtProvider alloc] initWithRenewJwtCallback:^(VSSTokenContext *context, void (^completion)(VSSJwt *jwt, NSError *error)) {
        VSSJwt *jwt = [generator generateTokenWithIdentity:identity additionalData:nil error:nil];
        
        completion(jwt, nil);
    }];
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
    self.keyPair = keyPair;
    NSError *err;

    self.keyknoxManager = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:@[keyPair.publicKey] privateKey:keyPair.privateKey retryOnUnauthorized:NO error:&err];
    
    XCTAssert(err == nil);
    
    self.numberOfKeys = 50;
}

- (void)tearDown {
    [super tearDown];
}

- (void)test01_KTC6_pushValue {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    
    [self.keyknoxManager pushValue:someData previousHash:nil completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        
        XCTAssert([decryptedData.value isEqualToData:someData]);
        
        [ex fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test02_KTC7_pullValue {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    
    [self.keyknoxManager pushValue:someData previousHash:nil completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
        [self.keyknoxManager pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert([decryptedData.value isEqualToData:someData]);
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test03_KTC8_pullEmptyValue {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    [self.keyknoxManager pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        XCTAssert(decryptedData.value.length == 0 && decryptedData.meta.length == 0);
        XCTAssert([decryptedData.version isEqualToString:@"1.0"]);
        
        [ex fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test04_KTC9_pullMultiplePublicKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];

    VSMVirgilPrivateKey *privateKey = nil;
    NSMutableArray<VSMVirgilPublicKey *> *halfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *anotherHalfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];

    for (int i = 0; i < self.numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];

        if (i == 0)
            privateKey = keyPair.privateKey;

        if (i < self.numberOfKeys / 2)
            [halfPublicKeys addObject:keyPair.publicKey];
        else
            [anotherHalfPublicKeys addObject:keyPair.publicKey];
    }
    
    VSKKeyknoxManager *keyknoxManager1 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:halfPublicKeys privateKey:privateKey retryOnUnauthorized:NO error:nil];
    [keyknoxManager1 pushValue:someData previousHash:nil completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        XCTAssert([decryptedData.value isEqualToData:someData]);

        [keyknoxManager1 pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert([decryptedData.value isEqualToData:someData]);

            VSKKeyknoxManager *keyknoxManager2 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:anotherHalfPublicKeys privateKey:privateKey retryOnUnauthorized:NO error:nil];
            [keyknoxManager2 pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
                XCTAssert(decryptedData == nil && error != nil);
                XCTAssert([error.domain isEqualToString:VSKKeyknoxCryptoErrorDomain]);
                XCTAssert(error.code == VSKKeyknoxCryptoErrorSignerNotFound);

                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test05_KTC10_pullDifferentPrivateKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];

    NSMutableArray<VSMVirgilKeyPair *> *keyPairs = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *publicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *halfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];

    for (int i = 0; i < self.numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];

        [keyPairs addObject:keyPair];
        [publicKeys addObject:keyPair.publicKey];

        if (i < self.numberOfKeys / 2)
            [halfPublicKeys addObject:keyPair.publicKey];
    }

    VSCVirgilRandom *random = [[VSCVirgilRandom alloc] initWithPersonalInfo:@"info"];

    size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];

    VSKKeyknoxManager *keyknoxManager1 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
    [keyknoxManager1 pushValue:someData previousHash:nil completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        XCTAssert([decryptedData.value isEqualToData:someData]);

        size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];
        VSKKeyknoxManager *keyknoxManager2 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
        [keyknoxManager2 pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert([decryptedData.value isEqualToData:someData]);

            size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];
            VSKKeyknoxManager *keyknoxManager3 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
            [keyknoxManager3 pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
                XCTAssert(decryptedData == nil && error != nil);
                XCTAssert([error.domain isEqualToString:VSKKeyknoxCryptoErrorDomain]);
                XCTAssert(error.code == VSKKeyknoxCryptoErrorDecryptionFailed);

                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test06_KTC11_updateRecipients {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];

    NSMutableArray<VSMVirgilKeyPair *> *keyPairs = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *publicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *halfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *anotherHalfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];

    for (int i = 0; i < self.numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];

        [keyPairs addObject:keyPair];
        [publicKeys addObject:keyPair.publicKey];

        if (i < self.numberOfKeys / 2)
            [halfPublicKeys addObject:keyPair.publicKey];
        else
            [anotherHalfPublicKeys addObject:keyPair.publicKey];
    }

    VSCVirgilRandom *random = [[VSCVirgilRandom alloc] initWithPersonalInfo:@"info"];

    size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];

    VSKKeyknoxManager *keyknoxManager1 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
    [keyknoxManager1 pushValue:someData previousHash:nil completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        XCTAssert([decryptedData.value isEqualToData:someData]);

        size_t rand1 = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];
        size_t rand2 = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];

        VSKKeyknoxManager *keyknoxManager2 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:halfPublicKeys privateKey:keyPairs[rand1].privateKey retryOnUnauthorized:NO error:nil];
        [keyknoxManager2 updateRecipientsWithNewPublicKeys:anotherHalfPublicKeys newPrivateKey:keyPairs[rand2].privateKey completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert([decryptedData.value isEqualToData:someData]);
            
            XCTAssert([keyknoxManager2.publicKeys isEqualToArray:anotherHalfPublicKeys]);
            XCTAssert(keyknoxManager2.privateKey == keyPairs[rand2].privateKey);

            size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];

            VSKKeyknoxManager *keyknoxManager3 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:anotherHalfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
            [keyknoxManager3 pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
                XCTAssert(decryptedData != nil && error == nil);
                XCTAssert([decryptedData.value isEqualToData:someData]);

                size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];

                VSKKeyknoxManager *keyknoxManager4 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:anotherHalfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
                [keyknoxManager4 pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
                    XCTAssert(decryptedData == nil && error != nil);
                    XCTAssert([error.domain isEqualToString:VSKKeyknoxCryptoErrorDomain]);
                    XCTAssert(error.code == VSKKeyknoxCryptoErrorDecryptionFailed);

                    size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];

                    VSKKeyknoxManager *keyknoxManager5 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
                    [keyknoxManager5 pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
                        XCTAssert(decryptedData == nil && error != nil);
                        XCTAssert([error.domain isEqualToString:VSKKeyknoxCryptoErrorDomain]);
                        XCTAssert(error.code == VSKKeyknoxCryptoErrorSignerNotFound);

                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test07_KTC12_updateRecipientsWithValue {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];

    NSMutableArray<VSMVirgilKeyPair *> *keyPairs = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *publicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *halfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *anotherHalfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];

    for (int i = 0; i < self.numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];

        [keyPairs addObject:keyPair];
        [publicKeys addObject:keyPair.publicKey];

        if (i < self.numberOfKeys / 2)
            [halfPublicKeys addObject:keyPair.publicKey];
        else
            [anotherHalfPublicKeys addObject:keyPair.publicKey];
    }

    VSCVirgilRandom *random = [[VSCVirgilRandom alloc] initWithPersonalInfo:@"info"];

    size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];

    VSKKeyknoxManager *keyknoxManager1 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
    [keyknoxManager1 pushValue:someData previousHash:nil completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        XCTAssert([decryptedData.value isEqualToData:someData]);

        size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];
        
        [keyknoxManager1 updateRecipientsWithValue:decryptedData.value previousHash:decryptedData.keyknoxHash newPublicKeys:anotherHalfPublicKeys newPrivateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert([decryptedData.value isEqualToData:someData]);

            size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];

            VSKKeyknoxManager *keyknoxManager2 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:anotherHalfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
            [keyknoxManager2 pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
                XCTAssert(decryptedData != nil && error == nil);
                XCTAssert([decryptedData.value isEqualToData:someData]);

                size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];

                VSKKeyknoxManager *keyknoxManager3 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:anotherHalfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
                [keyknoxManager3 pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
                    XCTAssert(decryptedData == nil && error != nil);
                    XCTAssert([error.domain isEqualToString:VSKKeyknoxCryptoErrorDomain]);
                    XCTAssert(error.code == VSKKeyknoxCryptoErrorDecryptionFailed);
                    
                    VSKKeyknoxManager *keyknoxManager4 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:anotherHalfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
                    [keyknoxManager4 pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
                        XCTAssert(decryptedData == nil && error != nil);
                        XCTAssert([error.domain isEqualToString:VSKKeyknoxCryptoErrorDomain]);
                        XCTAssert(error.code == VSKKeyknoxCryptoErrorDecryptionFailed);
                        
                        size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];
                        VSKKeyknoxManager *keyknoxManager5 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey retryOnUnauthorized:NO error:nil];
                        [keyknoxManager5 pullValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
                            XCTAssert(decryptedData == nil && error != nil);
                            XCTAssert([error.domain isEqualToString:VSKKeyknoxCryptoErrorDomain]);
                            XCTAssert(error.code == VSKKeyknoxCryptoErrorSignerNotFound);
 
                            [ex fulfill];
                        }];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test08_KTC13_updateRecipientsEmptyValue {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSMutableArray<VSMVirgilKeyPair *> *keyPairs = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *halfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *anotherHalfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    
    for (int i = 0; i < self.numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
        
        [keyPairs addObject:keyPair];
        
        if (i < self.numberOfKeys / 2)
            [halfPublicKeys addObject:keyPair.publicKey];
        else
            [anotherHalfPublicKeys addObject:keyPair.publicKey];
    }
    
    VSKKeyknoxManager *keyknoxManager2 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:halfPublicKeys privateKey:keyPairs[0].privateKey retryOnUnauthorized:NO error:nil];
    [keyknoxManager2 updateRecipientsWithNewPublicKeys:anotherHalfPublicKeys newPrivateKey:keyPairs[25].privateKey completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        XCTAssert(decryptedData.value.length == 0 && decryptedData.meta.length == 0 && [decryptedData.version isEqualToString:@"1.0"]);
        
        [ex fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test09_KTC14_resetValue {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    
    [self.keyknoxManager pushValue:someData previousHash:nil completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        
        [self.keyknoxManager resetValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert(decryptedData.value.length == 0 && decryptedData.meta.length == 0);
            XCTAssert([decryptedData.version isEqualToString:@"2.0"]);
        
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test10_KTC15_resetInvalidValue {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    
    VSMVirgilKeyPair *keyPair1 = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
    VSMVirgilKeyPair *keyPair2 = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
    
    VSKKeyknoxManager *keyknoxManager1 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:@[keyPair1.publicKey] privateKey:keyPair1.privateKey retryOnUnauthorized:NO error:nil];
    
    [keyknoxManager1 pushValue:someData previousHash:nil completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        
        VSKKeyknoxManager *keyknoxManager2 = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:self.provider keyknoxClient:self.keyknoxClient publicKeys:@[keyPair2.publicKey] privateKey:keyPair2.privateKey retryOnUnauthorized:NO error:nil];
        
        [keyknoxManager2 resetValueWithCompletion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert(decryptedData.value.length == 0 && decryptedData.meta.length == 0);
            XCTAssert([decryptedData.version isEqualToString:@"2.0"]);
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test11_KTC16_didEncrypt {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    
    [self.keyknoxManager pushValue:someData previousHash:nil completion:^(VSKDecryptedKeyknoxValue *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        
        VSSTokenContext *tokenContext = [[VSSTokenContext alloc] initWithIdentity:nil service:@"" operation:@"" forceReload:NO];
        [self.provider getTokenWith:tokenContext completion:^(id<VSSAccessToken> token, NSError *error) {
            NSError *err;
            VSKEncryptedKeyknoxValue *encryptedValue = [self.keyknoxClient pullValueWithToken:token.stringRepresentation error:&err];
            
            VSCCipher *cipher = [[VSCCipher alloc] init];
            NSData *privateKeyData = [self.crypto exportPrivateKey:self.keyPair.privateKey];
            
            [cipher setContentInfo:encryptedValue.meta error:nil];
            NSData *decryptedData = [cipher decryptData:encryptedValue.value recipientId:self.keyPair.privateKey.identifier privateKey:privateKeyData keyPassword:nil error:&err];
            XCTAssert(err == nil);
            
            XCTAssert([decryptedData isEqualToData:someData]);
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
