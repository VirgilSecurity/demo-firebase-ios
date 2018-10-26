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

@interface VTE003_KeyBackupTests : XCTestCase

@property (nonatomic) VTETestsConst *consts;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VTETestUtils *utils;
@property (nonatomic) VSSKeychainStorage *keychainStorage;
@property (nonatomic) VTEEThree *eThree;
@property (nonatomic) NSString *password;


@end

@implementation VTE003_KeyBackupTests

- (void)setUp {
    [super setUp];

    self.password = [[NSUUID alloc] init].UUIDString;
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
    XCTestExpectation *ex = [self expectationWithDescription:@"Change password should change brain key to encrypt keys in Keyknox"];

    [self.utils clearAllStoragesWithPassword:self.password identity:self.eThree.identity keychainStorage:self.keychainStorage completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        sleep(2);

        [self.eThree bootstrapWithPassword:self.password completion:^(NSError *error) {
            XCTAssert(error == nil);

            sleep(2);

            NSString *oldPassword = self.password;
            NSString *newPassword = [[NSUUID alloc] init].UUIDString;
            [self.eThree changePrivateKeyPasswordFrom:oldPassword to:newPassword completion:^(NSError *error) {
                XCTAssert(error == nil);

                NSError *err;
                [self.eThree cleanUpAndReturnError:&err];
                XCTAssert(err == nil);

                sleep(2);

                [self.eThree bootstrapWithPassword:oldPassword completion:^(NSError *error) {
                    XCTAssert(error != nil);

                    sleep(2);

                    [self.eThree bootstrapWithPassword:newPassword completion:^(NSError *error) {
                        XCTAssert(error == nil);

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

- (void)test02 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Trying to backup already backuped key should cause error"];

    [self.utils clearAllStoragesWithPassword:self.password identity:self.eThree.identity keychainStorage:self.keychainStorage completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        sleep(2);

        [self.eThree bootstrapWithPassword:self.password completion:^(NSError *error) {
            XCTAssert(error == nil);

            sleep(2);

            [self.eThree backupPrivateKeyWithPassword:self.password completion:^(NSError *error) {
                XCTAssert(error != nil);

                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test03 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Backup Private key should publish key to Keyknox"];

    [self.utils clearAllStoragesWithPassword:self.password identity:self.eThree.identity keychainStorage:self.keychainStorage completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        [self.eThree bootstrapWithPassword:nil completion:^(NSError *error) {
            XCTAssert(error == nil);

            NSError *err;
            VSSKeychainEntry *keychainEntry1 = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
            XCTAssert(err == nil && keychainEntry1 != nil);

            sleep(2);

            [self.eThree backupPrivateKeyWithPassword:self.password completion:^(NSError *error) {
                XCTAssert(error == nil);

                [syncKeyStorage syncWithCompletion:^(NSError *error) {
                    XCTAssert(error == nil);

                    NSError *err;
                    VSSKeychainEntry *syncEntry = [syncKeyStorage retrieveEntryWithName:self.eThree.identity error:&err];
                    XCTAssert(err == nil && syncEntry != nil);
                    XCTAssert([syncEntry.data isEqualToData:keychainEntry1.data]);

                    [self.eThree cleanUpAndReturnError:&err];
                    XCTAssert(err == nil);

                    sleep(2);

                    [self.eThree bootstrapWithPassword:self.password completion:^(NSError *error) {
                        XCTAssert(error == nil);

                        NSError *err;
                        VSSKeychainEntry *keychainEntry2 = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
                        XCTAssert(err == nil && keychainEntry2 != nil);
                        XCTAssert([keychainEntry2.data isEqualToData:keychainEntry1.data]);

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
    XCTestExpectation *ex = [self expectationWithDescription:@"resetBackupedKey should delete Key from Keyknox"];

    [self.utils clearAllStoragesWithPassword:self.password identity:self.eThree.identity keychainStorage:self.keychainStorage completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        sleep(2);

        [self.eThree bootstrapWithPassword:self.password completion:^(NSError *error) {
            XCTAssert(error == nil);

            sleep(2);

            [self.eThree resetPrivateKeyBackupWithPassword:self.password completion:^(NSError *error) {
                XCTAssert(error == nil);

                [syncKeyStorage syncWithCompletion:^(NSError *error) {
                    XCTAssert(error == nil);

                    NSError *err;
                    VSSKeychainEntry *entry = [syncKeyStorage retrieveEntryWithName:self.eThree.identity error:&err];
                    XCTAssert(err != nil && entry == nil);

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

@end
