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
@import VirgilE3Kit;
@import VirgilCrypto;
@import VirgilCryptoApiImpl;

#import "VTETestsConst.h"
#import "VTETestUtils.h"

static const NSTimeInterval timeout = 20.;

@interface VTE001_EncryptionTests : XCTestCase

@property (nonatomic) VTETestsConst *consts;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VTETestUtils *utils;
@property (nonatomic) VSSKeychainStorage *keychainStorage;
@property (nonatomic) VTEEThree *eThree;

@end

@implementation VTE001_EncryptionTests

- (void)setUp {
    [super setUp];

    self.consts = [[VTETestsConst alloc] init];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:false];
    self.utils = [[VTETestUtils alloc] initWithCrypto:self.crypto consts:self.consts];

    VSSKeychainStorageParams *params;
#if TARGET_OS_IOS || TARGET_OS_TV
    params = [VSSKeychainStorageParams makeKeychainStorageParamsWithAccessGroup:nil accessibility:nil error:nil];
#elif TARGET_OS_OSX
    params = [VSSKeychainStorageParams makeKeychainStorageParamsWithTrustedApplications:@[] error:nil];
#endif
    self.keychainStorage = [[VSSKeychainStorage alloc] initWithStorageParams:params];

    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    NSString *identity = [[NSUUID alloc] init].UUIDString;
    [VTEEThree initializeWithTokenCallback:^(void (^completionHandler)(NSString *, NSError *)) {
        NSError *error;
        NSString *token = [self.utils getTokenStringWithIdentity:identity error:&error];

        completionHandler(token, error);
    } completion:^(VTEEThree *eThree, NSError *error) {
        XCTAssert(eThree != nil && error == nil);
        self.eThree = eThree;

        dispatch_semaphore_signal(sema);
    }];

    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
}

- (void)tearDown {
    [super tearDown];
}

- (void)test01 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Look up keys should return published public keys"];

    [self.eThree bootstrapWithPassword:nil completion:^(NSError *error) {
        XCTAssert(error == nil);

        NSMutableArray *identities = [NSMutableArray array];
        NSMutableArray *publicKeys = [NSMutableArray array];

        for (int i = 0; i < 3; i++) {
            VSSCard *card = self.utils.publishRandomCard;
            XCTAssert(card != nil);
            [identities addObject:card.identity];
            [publicKeys addObject:card.publicKey];
        }
        
        [self.eThree lookupPublicKeysOf:identities completion:^(NSArray<VSMVirgilPublicKey *> *foundPublicKeys, NSArray<NSError *> *errors) {
            XCTAssert(error == nil);
            XCTAssert([self.utils isPublicKeysEqualWithPublicKeys1:foundPublicKeys publicKeys2:publicKeys]);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test02 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Look up keys by empty array of identities should throw error"];

    [self.eThree bootstrapWithPassword:nil completion:^(NSError *error) {
        XCTAssert(error == nil);

        [self.eThree lookupPublicKeysOf:@[] completion:^(NSArray<VSMVirgilPublicKey *> *foundPublicKeys, NSArray<NSError *> *errors) {
            XCTAssert(errors.firstObject.code == VTEEThreeErrorMissingIdentities);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test03 {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    [self.eThree bootstrapWithPassword:nil completion:^(NSError *error) {
        XCTAssert(error == nil);
        VTEEThree *eThree1 = self.eThree;

        NSString *identity = [[NSUUID alloc] init].UUIDString;
        [VTEEThree initializeWithTokenCallback:^(void (^completionHandler)(NSString *, NSError *)) {
            NSError *error;
            NSString *token = [self.utils getTokenStringWithIdentity:identity error:&error];

            completionHandler(token, error);
        } completion:^(VTEEThree *eThree2, NSError *error) {
            XCTAssert(eThree2 != nil && error == nil);

            [eThree2 bootstrapWithPassword:nil completion:^(NSError *error) {
                XCTAssert(error == nil);

                [eThree1 lookupPublicKeysOf:@[eThree2.identity] completion:^(NSArray<VSMVirgilPublicKey *> *foundPublicKeys, NSArray<NSError *> *errors) {
                    XCTAssert(errors.count == 0);
                    XCTAssert(foundPublicKeys.firstObject != nil);

                    NSString *plainText = [[NSUUID alloc] init].UUIDString;
                    NSError *err;
                    NSString *encrypted = [eThree1 encryptWithText:plainText for:foundPublicKeys error:&err];
                    XCTAssert(err == nil);

                    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
                    XCTAssert(err == nil);

                    NSString *decrypted = [eThree2 decryptWithText:encrypted from:@[keyPair.publicKey] error:&err];
                    XCTAssert(err != nil && decrypted == nil);

                    [eThree2 lookupPublicKeysOf:@[eThree1.identity] completion:^(NSArray<VSMVirgilPublicKey *> *foundPublicKeys, NSArray<NSError *> *errors) {
                        XCTAssert(errors.count == 0);
                        XCTAssert(foundPublicKeys.firstObject != nil);

                        NSError *err;
                        NSString *decrypted = [eThree2 decryptWithText:encrypted from:foundPublicKeys error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([decrypted isEqualToString:plainText]);

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

- (void)test04 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Encrypt for empty array of keys should throw error"];

    [self.eThree bootstrapWithPassword:nil completion:^(NSError *error) {
        XCTAssert(error == nil);

        NSError *err;
        NSString *encrypted = [self.eThree encryptWithText:@"plaintext" for:@[] error:&err];
        XCTAssert(err.code == VTEEThreeErrorMissingKeys && encrypted == nil);

        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test05 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Decrypt with empty array of keys should throw error"];

    [self.eThree bootstrapWithPassword:nil completion:^(NSError *error) {
        XCTAssert(error == nil);

        NSError *err;
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
        NSString *encrypted = [self.eThree encryptWithText:@"plaintext" for:@[keyPair.publicKey] error:&err];
        XCTAssert(error == nil);

        NSString *decrypted = [self.eThree decryptWithText:encrypted from:@[] error:&err];
        XCTAssert(err.code == VTEEThreeErrorMissingKeys && decrypted == nil);

        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test06 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Should decrypt self encrypted text"];

    [self.eThree bootstrapWithPassword:nil completion:^(NSError *error) {
        XCTAssert(error == nil);

        NSError *err;
        NSString *plainText = [[NSUUID alloc] init].UUIDString;

        NSString *encrypted = [self.eThree encryptWithText:plainText for:nil error:&err];
        XCTAssert(error == nil);

        NSString *decrypted = [self.eThree decryptWithText:encrypted from:nil error:&err];
        XCTAssert(error == nil);
        XCTAssert([decrypted isEqualToString:plainText]);

        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test07 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Should throw error if decrypted text is not verified"];

    [self.eThree bootstrapWithPassword:nil completion:^(NSError *error) {
        XCTAssert(error == nil);

        NSError *err;
        NSString *plainText = [[NSUUID alloc] init].UUIDString;
        NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
        XCTAssert(err == nil);

        [self.eThree lookupPublicKeysOf:@[self.eThree.identity] completion:^(NSArray<VSMVirgilPublicKey *> *foundPublicKeys, NSArray<NSError *> *errors) {
            XCTAssert(errors.count == 0);
            XCTAssert(foundPublicKeys.firstObject != nil);

            NSError *err;
            NSData *encryptedData = [self.crypto encrypt:plainData for:foundPublicKeys error:&err];
            XCTAssert(err == nil);

            NSString *encryptedString = [encryptedData base64EncodedStringWithOptions:0];
            XCTAssert(encryptedString != nil);

            NSString *decrypted = [self.eThree decryptWithText:encryptedString from:@[keyPair.publicKey] error:&err];
            XCTAssert(err != nil && decrypted == nil);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test08 {
    NSError *error;
    [self.keychainStorage deleteEntryWithName:self.eThree.identity error: nil];

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);

    NSString *encrypted = [self.eThree encryptWithText:@"plainText" for:@[keyPair.publicKey] error:&error];
    XCTAssert(error.code == VTEEThreeErrorNotBootstrapped);
    XCTAssert(encrypted == nil);

    error = nil;

    NSString *decrypted = [self.eThree decryptWithText:@"" from:@[keyPair.publicKey] error:&error];
    XCTAssert(error.code == VTEEThreeErrorNotBootstrapped);
    XCTAssert(decrypted == nil);
}

- (void)test09 {
    NSError *error;
    [self.keychainStorage deleteEntryWithName:self.eThree.identity error: nil];

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);

    VSMVirgilPrivateKeyExporter *exporter = [[VSMVirgilPrivateKeyExporter alloc] initWithVirgilCrypto:self.crypto password:nil];
    NSData *exportedKey = [exporter exportPrivateKeyWithPrivateKey:keyPair.privateKey error:&error];
    XCTAssert(error == nil);

    NSDictionary *meta = @{ @"isPublished": @"true"};

    VSSKeychainEntry *entry = [self.keychainStorage storeWithData:exportedKey withName:self.eThree.identity meta:meta error:&error];
    XCTAssert(error == nil && entry != nil);

    NSString *plainText = [[NSUUID alloc] init].UUIDString;
    NSString *encrypted = [self.eThree encryptWithText:plainText for:nil error:&error];
    XCTAssert(error == nil);

    NSString *decrypted = [self.eThree decryptWithText:encrypted from:nil error:&error];
    XCTAssert(error == nil);
    XCTAssert([decrypted isEqualToString:plainText]);
}

@end
