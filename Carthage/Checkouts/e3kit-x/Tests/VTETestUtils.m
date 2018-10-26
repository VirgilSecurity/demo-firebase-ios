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
#import "VTETestUtils.h"

@implementation VTETestUtils

- (instancetype __nonnull)initWithCrypto:(VSMVirgilCrypto *)crypto consts:(VTETestsConst *)consts {
    self = [super init];
    if (self) {
        self.consts = consts;
        self.crypto = crypto;
    }
    return self;
}

- (NSString * __nonnull)getTokenStringWithIdentity:(NSString * __nonnull)identity error:(NSError * __nullable * __nullable)errorPtr {
    VSMVirgilPrivateKeyExporter *exporter = [[VSMVirgilPrivateKeyExporter alloc] initWithVirgilCrypto:self.crypto password:nil];
    NSData *privKey = [[NSData alloc] initWithBase64EncodedString:self.consts.apiPrivateKeyBase64 options:0];
    VSMVirgilPrivateKey *privateKey = (VSMVirgilPrivateKey *)[exporter importPrivateKeyFrom:privKey error:errorPtr];

    VSMVirgilAccessTokenSigner *tokenSigner = [[VSMVirgilAccessTokenSigner alloc] initWithVirgilCrypto:self.crypto];
    VSSJwtGenerator *generator = [[VSSJwtGenerator alloc] initWithApiKey:privateKey apiPublicKeyIdentifier:self.consts.apiPublicKeyId accessTokenSigner:tokenSigner appId:self.consts.applicationId ttl:1000];

    VSSJwt *jwtToken = [generator generateTokenWithIdentity:identity additionalData:nil error:errorPtr];

    NSString *strToken = [jwtToken stringRepresentation];

    return strToken;
}

- (id<VSSAccessToken> __nonnull)getTokenWithIdentity:(NSString * __nonnull)identity ttl:(NSTimeInterval)ttl error:(NSError * __nullable * __nullable)errorPtr {
    VSMVirgilPrivateKeyExporter *exporter = [[VSMVirgilPrivateKeyExporter alloc] initWithVirgilCrypto:self.crypto password:nil];
    NSData *privKey = [[NSData alloc] initWithBase64EncodedString:_consts.apiPrivateKeyBase64 options:0];
    VSMVirgilPrivateKey *privateKey = (VSMVirgilPrivateKey *)[exporter importPrivateKeyFrom:privKey error:errorPtr];

    VSMVirgilAccessTokenSigner *tokenSigner = [[VSMVirgilAccessTokenSigner alloc] initWithVirgilCrypto:self.crypto];
    VSSJwtGenerator *generator = [[VSSJwtGenerator alloc] initWithApiKey:privateKey apiPublicKeyIdentifier:self.consts.apiPublicKeyId accessTokenSigner:tokenSigner appId:self.consts.applicationId ttl:ttl];

    VSSJwt *jwtToken = [generator generateTokenWithIdentity:identity additionalData:nil error:errorPtr];
    return jwtToken;
}

- (VSSCard * __nullable)publishRandomCard {
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];
    NSData *exportedPublicKey = [self.crypto exportPublicKey:keyPair.publicKey];
    NSString *identity = [[NSUUID alloc] init].UUIDString;

    VSSRawCardContent *content = [[VSSRawCardContent alloc] initWithIdentity:identity publicKey:exportedPublicKey previousCardId:nil version:@"5.0" createdAt:NSDate.date];
    NSData *snapshot = [content snapshotAndReturnError:nil];

    VSSRawSignedModel *rawCard = [[VSSRawSignedModel alloc] initWithContentSnapshot:snapshot];

    NSString *strToken = [self getTokenStringWithIdentity:identity error:nil];

    VSMVirgilCardCrypto *cardCrypto = [[VSMVirgilCardCrypto alloc] initWithVirgilCrypto:self.crypto];
    VSSCardClient *cardClient = self.consts.serviceURL == nil ? [[VSSCardClient alloc] init] : [[VSSCardClient alloc] initWithServiceUrl:self.consts.serviceURL];

    VSSModelSigner *signer = [[VSSModelSigner alloc] initWithCardCrypto:cardCrypto];
    [signer selfSignWithModel:rawCard privateKey:keyPair.privateKey additionalData:nil error:nil];

    VSSRawSignedModel *responseRawCard = [cardClient publishCardWithModel:rawCard token:strToken error:nil];
    VSSCard *card = [VSSCardManager parseCardFrom:responseRawCard cardCrypto:cardCrypto error:nil];

    return card;
}

- (BOOL)isPublicKeysEqualWithPublicKeys1:(NSArray <VSMVirgilPublicKey *> * __nonnull)publicKeys1 publicKeys2:(NSArray <VSMVirgilPublicKey *> * __nonnull)publicKeys2 {

    for (VSMVirgilPublicKey* key1 in publicKeys1) {
        NSData *data1 = [self.crypto exportPublicKey:key1];
        BOOL found = false;
        for (VSMVirgilPublicKey* key2 in publicKeys2) {
            NSData *data2 = [self.crypto exportPublicKey:key2];
            if ([data1 isEqualToData:data2])
                found = true;
        }
        if (!found)
            return false;
    }

    return true;
}

-(void)setUpSyncKeyStorageWithPassword:(NSString * __nonnull)password identity:(NSString * __nonnull)identity completionHandler:(void(^)(VSKSyncKeyStorage * _Nonnull, NSError * _Nonnull))completionHandler {
    VSSCachingJwtProvider *provider = [[VSSCachingJwtProvider alloc] initWithRenewTokenCallback:^(VSSTokenContext *tokenContext, void(^completionHandler)(NSString *, NSError *)) {
        NSError *error;
        NSString *token = [self getTokenStringWithIdentity:identity error:&error];

        completionHandler(token, error);
    }];
    VSYBrainKeyContext *context = [VSYBrainKeyContext makeContextWithAccessTokenProvider:provider];
    VSYBrainKey *brainKey = [[VSYBrainKey alloc] initWithContext:context];

    [brainKey generateKeyPairWithPassword:password brainKeyId:nil completion:^(VSMVirgilKeyPair *keyPair, NSError *error) {
        VSKSyncKeyStorage *syncKeyStorage = [[VSKSyncKeyStorage alloc] initWithIdentity:identity accessTokenProvider:provider publicKeys:@[keyPair.publicKey] privateKey:keyPair.privateKey error:nil];

        [syncKeyStorage syncWithCompletion:^(NSError *error) {
            completionHandler(syncKeyStorage, error);
        }];
    }];
}

-(void)clearAllStoragesWithPassword:(NSString * __nonnull)password identity:(NSString * __nonnull)identity keychainStorage:(VSSKeychainStorage * __nonnull)keychainStorage completionHandler:(void(^)(VSKSyncKeyStorage * _Nonnull, NSError * _Nonnull))completionHandler {
    [keychainStorage deleteAllEntriesAndReturnError:nil];

    [self setUpSyncKeyStorageWithPassword:password identity:identity completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        [syncKeyStorage deleteAllEntriesWithCompletion:^(NSError *error) {
            completionHandler(syncKeyStorage, error);
        }];
    }];
}

@end
