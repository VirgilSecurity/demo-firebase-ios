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

#import <XCTest/XCTest.h>
@import VirgilSDK;
@import VirgilCryptoAPI;
@import VirgilCryptoApiImpl;
@import VirgilCrypto;

@interface VSS010_PrivateKeyStorageTests : XCTestCase

@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VSSPrivateKeyStorage *privateKeyStorage;

@end

@implementation VSS010_PrivateKeyStorageTests

- (void)setUp {
    [super setUp];
    
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:NO];
    id<VSAPrivateKeyExporter> privateKeyExporter = [[VSMVirgilPrivateKeyExporter alloc] initWithVirgilCrypto:self.crypto password:nil];
    VSSKeyStorage *keyStorage = [[VSSKeyStorage alloc] init];
    self.privateKeyStorage = [[VSSPrivateKeyStorage alloc] initWithPrivateKeyExporter:privateKeyExporter keyStorage:keyStorage];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)test001_storeKey {
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
    NSString *name = [[NSUUID alloc] init].UUIDString;
    NSError *error;
    [self.privateKeyStorage storeWithPrivateKey:keyPair.privateKey name:name meta:nil error:&error];
    XCTAssert(error == nil);
    
    VSSPrivateKeyEntry *privateKeyEntry = [self.privateKeyStorage loadWithName:name error:&error];
    XCTAssert(error == nil && privateKeyEntry != nil);
    XCTAssert(privateKeyEntry.meta == nil);
    
    NSData *privateKeyData1 = [self.crypto exportPrivateKey:(VSMVirgilPrivateKey *)privateKeyEntry.privateKey];
    NSData *privateKeyData2 = [self.crypto exportPrivateKey:keyPair.privateKey];
    
    XCTAssert([privateKeyData1 isEqualToData:privateKeyData2]);
}

- (void)test002_storeKeyWithMeta {
    NSDictionary *dict = @{
                           @"key1": @"value1",
                           @"key2": @"value2"
                           };
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
    NSString *name = [[NSUUID alloc] init].UUIDString;
    NSError *error;
    [self.privateKeyStorage storeWithPrivateKey:keyPair.privateKey name:name meta:dict error:&error];
    XCTAssert(error == nil);
    
    VSSPrivateKeyEntry *privateKeyEntry = [self.privateKeyStorage loadWithName:name error:&error];
    XCTAssert(error == nil && privateKeyEntry != nil);
    
    NSData *privateKeyData1 = [self.crypto exportPrivateKey:(VSMVirgilPrivateKey *)privateKeyEntry.privateKey];
    NSData *privateKeyData2 = [self.crypto exportPrivateKey:keyPair.privateKey];
    
    XCTAssert([privateKeyData1 isEqualToData:privateKeyData2]);
    XCTAssert([dict isEqualToDictionary:privateKeyEntry.meta]);
}


- (void)test003_existsKey {
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
    NSString *name1 = [[NSUUID alloc] init].UUIDString;
    NSString *name2 = [[NSUUID alloc] init].UUIDString;
    [self.privateKeyStorage storeWithPrivateKey:keyPair.privateKey name:name1 meta:nil error:nil];
    
    XCTAssert([self.privateKeyStorage existsWithName:name1]);
    XCTAssert(![self.privateKeyStorage existsWithName:name2]);
}

- (void)test005_deleteKey {
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
    NSString *name = [[NSUUID alloc] init].UUIDString;
    [self.privateKeyStorage storeWithPrivateKey:keyPair.privateKey name:name meta:nil error:nil];
    
    NSError *error;
    [self.privateKeyStorage deleteWithName:name error:&error];
    XCTAssert(error == nil);
    
    VSSPrivateKeyEntry *privateKeyEntry = [self.privateKeyStorage loadWithName:name error:&error];
    XCTAssert(privateKeyEntry == nil);
    XCTAssert(error != nil);
    
    XCTAssert(![self.privateKeyStorage existsWithName:name]);
}

@end
