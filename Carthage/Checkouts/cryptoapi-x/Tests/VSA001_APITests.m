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
@import VirgilCryptoAPI;

@interface DummyPublicKey : NSObject<VSAPublicKey>
@end

@implementation DummyPublicKey
@end

@interface DummyPrivateKey : NSObject<VSAPrivateKey>
@end

@implementation DummyPrivateKey
@end

@interface DummyCardCrypto: NSObject<VSACardCrypto>
@end

@implementation DummyCardCrypto

- (NSData *)generateSignatureOf:(NSData *)data using:(id <VSAPrivateKey>)privateKey error:(NSError **)error {
    return [[NSData alloc] init];
}

- (BOOL)verifySignature:(NSData * _Nonnull)signature of:(NSData * _Nonnull)data with:(id<VSAPublicKey> _Nonnull)publicKey {
    return YES;
}

- (NSData *)generateSHA512For:(NSData *)data error:(NSError *__autoreleasing  _Nullable * _Nullable)error {
    return [[NSData alloc] init];
}

- (id <VSAPublicKey>)importPublicKeyFrom:(NSData *)data error:(NSError **)error {
    return nil;
}

- (NSData * _Nullable)exportPublicKey:(id<VSAPublicKey> _Nonnull)publicKey error:(NSError *__autoreleasing  _Nullable * _Nullable)error {
    return [[NSData alloc] init];
}

@end

@interface DummyAccessTokenSigner: NSObject<VSAAccessTokenSigner>
@end

@implementation DummyAccessTokenSigner

- (NSData *)generateTokenSignatureOf:(NSData *)token using:(id <VSAPrivateKey>)privateKey error:(NSError **)error {
    return [[NSData alloc] init];
}

- (BOOL)verifyTokenSignature:(NSData *)signature of:(NSData *)token with:(id <VSAPublicKey>)publicKey {
    return YES;
}

- (NSString *)getAlgorithm {
    return [[NSString alloc] init];
}

@end

@interface DummyPrivateKeyExporter: NSObject<VSAPrivateKeyExporter>
@end

@implementation DummyPrivateKeyExporter

- (NSData *)exportPrivateKeyWithPrivateKey:(id<VSAPrivateKey>)privateKey error:(NSError **)error {
    return [[NSData alloc] init];
}

- (id<VSAPrivateKey>)importPrivateKeyFrom:(NSData *)data error:(NSError **)error {
    return nil;
}

@end

@interface VSA001_APITests : XCTestCase

@end

@implementation VSA001_APITests

- (void)test001_testAPI {
    id <VSAAccessTokenSigner> accessTokenSigner = [[DummyAccessTokenSigner alloc] init];
    id <VSAPrivateKeyExporter> privateKeyExporter = [[DummyPrivateKeyExporter alloc] init];
    id <VSACardCrypto> cardCrypto = [[DummyCardCrypto alloc] init];
    id <VSAPublicKey> publicKey = [[DummyPublicKey alloc] init];
    id <VSAPrivateKey> privateKey = [[DummyPrivateKey alloc] init];
    
    XCTAssert(accessTokenSigner != nil);
    XCTAssert(privateKeyExporter != nil);
    XCTAssert(cardCrypto != nil);
    XCTAssert(privateKey != nil);
    XCTAssert(publicKey != nil);
}

@end
