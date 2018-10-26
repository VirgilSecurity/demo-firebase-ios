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

@interface VSK003_CloudKeyStorageTests : XCTestCase

@property (nonatomic) TestConfig *config;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VSMVirgilKeyPair *keyPair;
@property (nonatomic) VSKCloudKeyStorage *keyStorage;
@property (nonatomic) VSKKeyknoxManager *keyknoxManager;
@property (nonatomic) NSInteger numberOfKeys;

@end

@implementation VSK003_CloudKeyStorageTests

- (void)setUp {
    [super setUp];
    
    self.config = [TestConfig readFromBundle];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:NO];
    VSKKeyknoxClient *keyknoxClient = [[VSKKeyknoxClient alloc] initWithServiceUrl:[[NSURL alloc] initWithString:self.config.ServiceURL]];
    
    VSMVirgilPrivateKey *apiKey = [self.crypto importPrivateKeyFrom:[[NSData alloc] initWithBase64EncodedString:self.config.ApiPrivateKey options:0] password:nil error:nil];
    VSSJwtGenerator *generator = [[VSSJwtGenerator alloc] initWithApiKey:apiKey apiPublicKeyIdentifier:self.config.ApiPublicKeyId accessTokenSigner:[[VSMVirgilAccessTokenSigner alloc] initWithVirgilCrypto:self.crypto] appId:self.config.AppId ttl:600];
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    
    id<VSSAccessTokenProvider> provider = [[VSSCachingJwtProvider alloc] initWithRenewJwtCallback:^(VSSTokenContext *context, void (^completion)(VSSJwt *jwt, NSError *error)) {
        VSSJwt *jwt = [generator generateTokenWithIdentity:identity additionalData:nil error:nil];
        
        completion(jwt, nil);
    }];

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
    self.keyPair = keyPair;

    NSError *err;
    
    VSKKeyknoxManager *keyknoxManager = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:provider keyknoxClient:keyknoxClient publicKeys:@[keyPair.publicKey] privateKey:keyPair.privateKey retryOnUnauthorized:NO error:&err];
    self.keyknoxManager = keyknoxManager;
    
    XCTAssert(err == nil);
    
    self.keyStorage = [[VSKCloudKeyStorage alloc] initWithKeyknoxManager:keyknoxManager];
}

- (void)tearDown {
    [super tearDown];
}

- (void)test01_KTC19_retrieveCloudEntriesEmptyKeyknox {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        NSError *err;
        XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
        XCTAssert(err == nil);
        
        [ex fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test02_KTC20_storeKey {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
    NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey];
    NSString *name = @"test";
    NSDictionary *meta = @{
                           @"test_key": @"test_value"
                           };
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntryWithName:name data:privateKeyData meta:meta completion:^(NSError *error) {
            XCTAssert(error == nil);
            NSError *err;
            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
            XCTAssert(err == nil);
            
            VSKCloudEntry *entry = [self.keyStorage retrieveEntryWithName:name error:&err];
            XCTAssert(err == nil);
            VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:entry.data password:nil error:nil];
            XCTAssert([privateKey.identifier isEqualToData:keyPair.privateKey.identifier]);
            XCTAssert([entry.name isEqualToString:name]);
            XCTAssert(entry.creationDate.timeIntervalSinceNow < 5);
            XCTAssert([entry.creationDate isEqualToDate:entry.modificationDate]);
            XCTAssert([entry.meta isEqualToDictionary:meta]);
            
            [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
                XCTAssert(err == nil);
                
                VSKCloudEntry *entry = [self.keyStorage retrieveEntryWithName:name error:&err];
                XCTAssert(err == nil);
                VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:entry.data password:nil error:nil];
                XCTAssert([privateKey.identifier isEqualToData:keyPair.privateKey.identifier]);
                XCTAssert([entry.name isEqualToString:name]);
                XCTAssert(entry.creationDate.timeIntervalSinceNow < 5);
                XCTAssert([entry.creationDate isEqualToDate:entry.modificationDate]);
                XCTAssert([entry.meta isEqualToDictionary:meta]);
                
                [ex fulfill];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test03_KTC21_existsKey {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
    NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey];

    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntryWithName:@"test" data:privateKeyData meta:nil completion:^(NSError *error) {
            XCTAssert(error == nil);
            NSError *err;
            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
            XCTAssert(err == nil);

            XCTAssert([self.keyStorage existsEntryNoThrowWithName:@"test"]);
            XCTAssert(![self.keyStorage existsEntryNoThrowWithName:@"test2"]);

            [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
                XCTAssert(err == nil);

                XCTAssert([self.keyStorage existsEntryNoThrowWithName:@"test"]);
                XCTAssert(![self.keyStorage existsEntryNoThrowWithName:@"test2"]);

                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test04_KTC22_storeMultipleKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    int numberOfKeys = 100;

    NSMutableArray<VSMVirgilPrivateKey *> *privateKeys = [[NSMutableArray alloc] init];
    NSMutableArray<VSKKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];

    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];

        [privateKeys addObject:keyPair.privateKey];

        if (i > 0 && i < numberOfKeys - 1) {
            NSString *name = [NSString stringWithFormat:@"%d", i];
            NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey];
            VSKKeyEntry *keyEntry = [[VSKKeyEntry alloc] initWithName:name data:data meta:nil];
            [keyEntries addObject:keyEntry];
        }
    }

    NSData *privateKeyData = [self.crypto exportPrivateKey:privateKeys[0]];
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntryWithName:@"first" data:privateKeyData meta:nil completion:^(NSError *error) {
            [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 1);
                XCTAssert(err == nil);
                VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data password:nil error:nil];
                XCTAssert(err == nil);
                XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                for (int i = 1; i < numberOfKeys - 1; i++) {
                    NSString *name = [NSString stringWithFormat:@"%d", i];
                    VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data password:nil error:nil];
                    XCTAssert(err == nil);
                    XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                }

                [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                    XCTAssert(error == nil);
                    NSError *err;
                    XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 1);
                    XCTAssert(err == nil);
                    VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data password:nil error:nil];
                    XCTAssert(err == nil);
                    XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                    for (int i = 1; i < numberOfKeys - 1; i++) {
                        NSString *name = [NSString stringWithFormat:@"%d", i];
                        VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data password:nil error:nil];
                        XCTAssert(err == nil);
                        XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                    }

                    NSData *privateKeyData = [self.crypto exportPrivateKey:privateKeys[numberOfKeys - 1]];
                    [self.keyStorage storeEntryWithName:@"last" data:privateKeyData meta:nil completion:^(NSError *error) {
                        XCTAssert(error == nil);
                        NSError *err;
                        XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys);
                        XCTAssert(err == nil);
                        VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data password:nil error:nil];
                        XCTAssert(err == nil);
                        XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                        for (int i = 1; i < numberOfKeys - 1; i++) {
                            NSString *name = [NSString stringWithFormat:@"%d", i];
                            VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data password:nil error:nil];
                            XCTAssert(err == nil);
                            XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                        }
                        VSMVirgilPrivateKey *lastPrivateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"last" error:&err].data password:nil error:nil];
                        XCTAssert(err == nil);
                        XCTAssert([lastPrivateKey.identifier isEqualToData:privateKeys[numberOfKeys - 1].identifier]);

                        [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                            XCTAssert(error == nil);
                            NSError *err;
                            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys);
                            XCTAssert(err == nil);
                            VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data password:nil error:nil];
                            XCTAssert(err == nil);
                            XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                            for (int i = 1; i < numberOfKeys - 1; i++) {
                                NSString *name = [NSString stringWithFormat:@"%d", i];
                                VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data password:nil error:nil];
                                XCTAssert(err == nil);
                                XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                            }
                            VSMVirgilPrivateKey *lastPrivateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"last" error:&err].data password:nil error:nil];
                            XCTAssert(err == nil);
                            XCTAssert([lastPrivateKey.identifier isEqualToData:privateKeys[numberOfKeys - 1].identifier]);

                            [ex fulfill];
                        }];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test05_KTC23_deleteAllKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    int numberOfKeys = 100;

    NSMutableArray<VSKKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];

    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
        NSString *name = [NSString stringWithFormat:@"%d", i];
        NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey];
        VSKKeyEntry *keyEntry = [[VSKKeyEntry alloc] initWithName:name data:privateKeyData meta:nil];
        [keyEntries addObject:keyEntry];
    }

    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
            [self.keyStorage deleteAllEntriesWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
                XCTAssert(err == nil);

                [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                    XCTAssert(error == nil);
                    NSError *err;
                    XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
                    XCTAssert(err == nil);

                    [ex fulfill];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test06_KTC24_deleteAllKeysEmpty {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    [self.keyStorage deleteAllEntriesWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        NSError *err;
        XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
        XCTAssert(err == nil);
        
        [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);
            NSError *err;
            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
            XCTAssert(err == nil);
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test07_KTC25_deleteKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    int numberOfKeys = 10;
    
    NSMutableArray<VSKKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];
    
    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
        NSString *name = [NSString stringWithFormat:@"%d", i];
        NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey];
        VSKKeyEntry *keyEntry = [[VSKKeyEntry alloc] initWithName:name data:privateKeyData meta:nil];
        [keyEntries addObject:keyEntry];
    }
    
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
            [self.keyStorage deleteEntryWithName:keyEntries[0].name completion:^(NSError *error) {
                XCTAssert(error == nil);
                
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 1);
                XCTAssert(err == nil);
                
                VSKCloudEntry *keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[0].name error:&err];
                XCTAssert(keyEntry == nil && err != nil);
                
                [self.keyStorage deleteEntriesWithNames:@[keyEntries[1].name, keyEntries[2].name] completion:^(NSError *error) {
                    XCTAssert(error == nil);
                    
                    NSError *err;
                    XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 3);
                    XCTAssert(err == nil);
                    
                    VSKCloudEntry *keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[1].name error:&err];
                    XCTAssert(keyEntry == nil && err != nil);
                    
                    keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[2].name error:&err];
                    XCTAssert(keyEntry == nil && err != nil);
                    
                    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                        XCTAssert(error == nil);
                        
                        NSError *err;
                        
                        XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 3);
                        XCTAssert(err == nil);
                        
                        VSKCloudEntry *keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[0].name error:&err];
                        XCTAssert(keyEntry == nil && err != nil);
                        
                        keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[1].name error:&err];
                        XCTAssert(keyEntry == nil && err != nil);
                        
                        keyEntry = [self.keyStorage retrieveEntryWithName:keyEntries[2].name error:&err];
                        XCTAssert(keyEntry == nil && err != nil);
                        
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test08_KTC26_updateEntry {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    int numberOfKeys = 10;
    
    NSMutableArray<VSKKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];
    
    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
        NSString *name = [NSString stringWithFormat:@"%d", i];
        NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey];
        VSKKeyEntry *keyEntry = [[VSKKeyEntry alloc] initWithName:name data:privateKeyData meta:nil];
        [keyEntries addObject:keyEntry];
    }
    
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
            NSDictionary *meta = @{@"key": @"value"};
            [self.keyStorage updateEntryWithName:keyEntries[0].name data:keyEntries[1].data meta:meta completion:^(VSKCloudEntry *cloudEntry, NSError *error) {
                XCTAssert(cloudEntry != nil && error == nil);
                
                XCTAssert([cloudEntry.name isEqualToString:keyEntries[0].name]);
                XCTAssert([cloudEntry.data isEqualToData:keyEntries[1].data]);
                XCTAssert([cloudEntry.meta isEqualToDictionary:meta]);
                
                NSError *err;
                VSKCloudEntry *cloudEntry2 = [self.keyStorage retrieveEntryWithName:keyEntries[0].name error:&err];
                XCTAssert(cloudEntry2 != nil && err == nil);
                
                XCTAssert([cloudEntry2.name isEqualToString:keyEntries[0].name]);
                XCTAssert([cloudEntry2.data isEqualToData:keyEntries[1].data]);
                XCTAssert([cloudEntry2.meta isEqualToDictionary:meta]);
                
                [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                    NSError *err;
                    VSKCloudEntry *cloudEntry = [self.keyStorage retrieveEntryWithName:keyEntries[0].name error:&err];
                    XCTAssert(cloudEntry != nil && err == nil);

                    XCTAssert([cloudEntry.name isEqualToString:keyEntries[0].name]);
                    XCTAssert([cloudEntry.data isEqualToData:keyEntries[1].data]);
                    XCTAssert([cloudEntry.meta isEqualToDictionary:meta]);

                    [ex fulfill];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test09_KTC27_updateRecipients {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    int numberOfKeys = 10;
    
    NSMutableArray<VSKKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];
    
    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
        NSString *name = [NSString stringWithFormat:@"%d", i];
        NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey];
        VSKKeyEntry *keyEntry = [[VSKKeyEntry alloc] initWithName:name data:privateKeyData meta:nil];
        [keyEntries addObject:keyEntry];
    }
    
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
            VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];

            [self.keyStorage updateRecipientsWithNewPublicKeys:@[keyPair.publicKey] newPrivateKey:keyPair.privateKey completion:^(NSError *error) {
                XCTAssert(error == nil);
                
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys);
                XCTAssert(err == nil);
                
                [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                    XCTAssert(error == nil);
                    
                    NSError *err;
                    XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys);
                    XCTAssert(err == nil);

                    [ex fulfill];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test10_KTC28_outOfSyncError {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    NSError *err;
    NSArray *entries = [self.keyStorage retrieveAllEntriesAndReturnError:&err];
    XCTAssert(entries == nil && [err.domain isEqualToString:VSKCloudKeyStorageErrorDomain] && err.code == VSKCloudKeyStorageErrorCloudStorageOutOfSync);
    err = nil;
    
    VSKCloudEntry *entry = [self.keyStorage retrieveEntryWithName:@"test" error:&err];
    XCTAssert(entry == nil && [err.domain isEqualToString:VSKCloudKeyStorageErrorDomain] && err.code == VSKCloudKeyStorageErrorCloudStorageOutOfSync);
    err = nil;
    
    XCTAssert(![self.keyStorage existsEntryNoThrowWithName:@"test"]);
    
    int numberOfKeys = 10;
    
    NSMutableArray<VSKKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];
    
    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
        NSString *name = [NSString stringWithFormat:@"%d", i];
        NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey];
        VSKKeyEntry *keyEntry = [[VSKKeyEntry alloc] initWithName:name data:privateKeyData meta:nil];
        [keyEntries addObject:keyEntry];
    }
    
    [self.keyStorage storeEntryWithName:keyEntries[0].name data:keyEntries[0].data meta:nil completion:^(NSError *error) {
        XCTAssert([error.domain isEqualToString:VSKCloudKeyStorageErrorDomain] && error.code == VSKCloudKeyStorageErrorCloudStorageOutOfSync);
        
        [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
            XCTAssert([error.domain isEqualToString:VSKCloudKeyStorageErrorDomain] && error.code == VSKCloudKeyStorageErrorCloudStorageOutOfSync);
            
            [self.keyStorage updateEntryWithName:keyEntries[0].name data:keyEntries[0].data meta:nil completion:^(VSKCloudEntry *entry, NSError *error) {
                XCTAssert(entry == nil && [error.domain isEqualToString:VSKCloudKeyStorageErrorDomain] && error.code == VSKCloudKeyStorageErrorCloudStorageOutOfSync);
                
                [self.keyStorage deleteEntryWithName:keyEntries[0].name completion:^(NSError *error) {
                    XCTAssert([error.domain isEqualToString:VSKCloudKeyStorageErrorDomain] && error.code == VSKCloudKeyStorageErrorCloudStorageOutOfSync);
                    
                    [self.keyStorage deleteEntriesWithNames:@[keyEntries[0].name, keyEntries[1].name] completion:^(NSError *error) {
                        XCTAssert([error.domain isEqualToString:VSKCloudKeyStorageErrorDomain] && error.code == VSKCloudKeyStorageErrorCloudStorageOutOfSync);
                        
                        [self.keyStorage updateRecipientsWithNewPublicKeys:@[self.keyPair.publicKey] newPrivateKey:self.keyPair.privateKey completion:^(NSError *error) {
                            XCTAssert([error.domain isEqualToString:VSKCloudKeyStorageErrorDomain] && error.code == VSKCloudKeyStorageErrorCloudStorageOutOfSync);
                            
                            [ex fulfill];
                        }];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test11_KTC41_deleteInvalidValue {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    [self.keyknoxManager pushValue:[[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding] previousHash:nil completion:^(VSKDecryptedKeyknoxValue *value, NSError *error) {
        XCTAssert(value != nil && error == nil);
        
        [self.keyStorage deleteAllEntriesWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);
            
            NSError *err;
            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
            XCTAssert(err == nil);
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
