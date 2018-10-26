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
#import "VSSTestUtils.h"

@implementation VSSTestUtils

- (instancetype __nonnull)initWithCrypto:(VSMVirgilCrypto *)crypto consts:(VSSTestsConst *)consts {
    self = [super init];
    if (self) {
        self.consts = consts;
        self.crypto = crypto;
    }
    return self;
}

- (VSSRawSignedModel *)instantiateRawSignedModelWithKeyPair:(VSMVirgilKeyPair *)keyPair identity:(NSString *)identity error:(NSError * __nullable * __nullable)errorPtr {
    
    VSMVirgilKeyPair *kp = keyPair != nil ? keyPair : [self.crypto generateKeyPairAndReturnError:errorPtr];
    NSString *idty = identity != nil ? identity : [[NSUUID alloc] init].UUIDString;
    
    NSData *exportedPublicKey = [self.crypto exportPublicKey:kp.publicKey];
    
    VSSRawCardContent *content = [[VSSRawCardContent alloc] initWithIdentity:idty publicKey:exportedPublicKey previousCardId:nil version:@"5.0" createdAt:NSDate.date];
    
    NSData *snapshot = [content snapshotAndReturnError:nil];
    
    VSSRawSignedModel *rawCard = [[VSSRawSignedModel alloc] initWithContentSnapshot:snapshot];
    
    VSMVirgilCardCrypto *cardCrypto = [[VSMVirgilCardCrypto alloc] initWithVirgilCrypto:self.crypto];
    VSSModelSigner *signer = [[VSSModelSigner alloc] initWithCardCrypto:cardCrypto];
    [signer selfSignWithModel:rawCard privateKey:keyPair.privateKey additionalData:nil error:errorPtr];

    return rawCard;
}

- (NSString * __nonnull)getTokenStringWithIdentity:(NSString * __nonnull)identity error:(NSError * __nullable * __nullable)errorPtr {
    VSMVirgilPrivateKeyExporter *exporter = [[VSMVirgilPrivateKeyExporter alloc] initWithVirgilCrypto:self.crypto password:nil];
    NSData *privKey = [[NSData alloc] initWithBase64EncodedString:self.consts.apiPrivateKeyBase64 options:0];
    VSMVirgilPrivateKey *privateKey = (VSMVirgilPrivateKey *)[exporter importPrivateKeyFrom:privKey error:errorPtr];
    
    VSMVirgilAccessTokenSigner *tokenSigner = [[VSMVirgilAccessTokenSigner alloc] initWithVirgilCrypto:self.crypto];
    VSSJwtGenerator *generator = [[VSSJwtGenerator alloc] initWithApiKey:privateKey apiPublicKeyIdentifier:self.consts.apiPublicKeyId accessTokenSigner:tokenSigner appId:self.consts.applicationId ttl:1000];
    
    VSSJwt *jwtToken = [generator generateTokenWithIdentity:identity additionalData:nil error:errorPtr];

    NSString *strToken = [jwtToken stringRepresentation];
    
    NSData *pubKey = [[NSData alloc] initWithBase64EncodedString:self.consts.apiPublicKeyBase64 options:0];
    VSMVirgilPublicKey *key = [self.crypto importPublicKeyFrom:pubKey error:errorPtr];
    
    VSSJwtVerifier *verifier = [[VSSJwtVerifier alloc] initWithApiPublicKey:key apiPublicKeyIdentifier:_consts.apiPublicKeyId accessTokenSigner:tokenSigner];
    
    if ([verifier verifyWithToken:jwtToken] == false) {
        return nil;
    }
    
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

- (NSString * __nonnull)getTokenWithWrongPrivateKeyWithIdentity:(NSString * __nonnull)identity error:(NSError * __nullable * __nullable)errorPtr {
    VSMVirgilKeyPair *wrongKeyPair = [self.crypto generateKeyPairAndReturnError:errorPtr];
    VSMVirgilPrivateKey *privateKey = wrongKeyPair.privateKey;
    
    VSMVirgilAccessTokenSigner *tokenSigner = [[VSMVirgilAccessTokenSigner alloc] initWithVirgilCrypto:self.crypto];
    VSSJwtGenerator *generator = [[VSSJwtGenerator alloc] initWithApiKey:privateKey apiPublicKeyIdentifier:self.consts.apiPublicKeyId accessTokenSigner:tokenSigner appId:self.consts.applicationId ttl:1000];
    
    VSSJwt *jwtToken = [generator generateTokenWithIdentity:identity additionalData:nil error:errorPtr];
    
    NSString *strToken = [jwtToken stringRepresentation];
    
    return strToken;
}

- (VSSGeneratorJwtProvider * __nonnull)getGeneratorJwtProviderWithIdentity:(NSString *)identity error:(NSError * __nullable * __nullable)errorPtr {
    VSMVirgilPrivateKeyExporter *exporter = [[VSMVirgilPrivateKeyExporter alloc] initWithVirgilCrypto:self.crypto password:nil];
    NSData *privKey = [[NSData alloc] initWithBase64EncodedString:self.consts.apiPrivateKeyBase64 options:0];
    VSMVirgilPrivateKey *privateKey = (VSMVirgilPrivateKey *)[exporter importPrivateKeyFrom:privKey error:errorPtr];

    VSMVirgilAccessTokenSigner *tokenSigner = [[VSMVirgilAccessTokenSigner alloc] initWithVirgilCrypto:self.crypto];
    VSSJwtGenerator *generator = [[VSSJwtGenerator alloc] initWithApiKey:privateKey apiPublicKeyIdentifier:self.consts.apiPublicKeyId accessTokenSigner:tokenSigner appId:self.consts.applicationId ttl:1000];

    VSSGeneratorJwtProvider *generatorProvider = [[VSSGeneratorJwtProvider alloc] initWithJwtGenerator:generator defaultIdentity:identity additionalData:nil];

    return generatorProvider;
}

- (VSSRawSignature * __nullable)getSelfSignatureFromModel:(VSSRawSignedModel * __nonnull)rawCard {
    for (VSSRawSignature* signature in rawCard.signatures) {
        if ([signature.signer isEqualToString:@"self"]) {
            return signature;
        }
    }
    return nil;
}

- (VSSCardSignature * __nullable)getSelfSignatureFromCard:(VSSCard * __nonnull)card {
    for (VSSCardSignature* signature in card.signatures) {
        if ([signature.signer isEqualToString:@"self"]) {
            return signature;
        }
    }
    return nil;
}

- (NSData * __nonnull)getRandomData {
    int length = 2048;
    NSMutableData *data = [NSMutableData dataWithCapacity:length];
    for (unsigned int i = 0; i < length/4; ++i) {
        u_int32_t randomBits = arc4random();
        [data appendBytes:(void*)&randomBits length:4];
    }
    return data;
}

- (BOOL)isCardsEqualWithCard:(VSSCard * __nonnull)card1 and:(VSSCard * __nonnull)card2 {
    VSSCardSignature *selfSignature1 = [self getSelfSignatureFromCard:card1];
    VSSCardSignature *selfSignature2 = [self getSelfSignatureFromCard:card2];
    
    return ([card1.identifier isEqualToString:card2.identifier] &&
            [card1.identity isEqualToString:card2.identity] &&
            [card1.version isEqualToString:card2.version] &&
            card1.isOutdated == card2.isOutdated &&
            card1.createdAt == card2.createdAt &&
            ([card1.previousCardId isEqualToString:card2.previousCardId] || (card1.previousCardId == nil && card2.previousCardId == nil)) &&
            ([self isCardsEqualWithCard:card1.previousCard and:card2.previousCard] || (card1.previousCard   == nil && card2.previousCard   == nil)) &&
            ([self isCardSignaturesEqualWithSignature:selfSignature1 and:selfSignature2] || (selfSignature1 == nil && selfSignature2 == nil)));
}

- (BOOL)isRawSignaturesEqualWithSignature:(VSSRawSignature * __nonnull)signature1 and:(VSSRawSignature * __nonnull)signature2 {
    return ([signature1.signer isEqualToString:signature2.signer] &&
            [signature1.signature isEqualToData:signature2.signature] &&
            ([signature1.snapshot isEqualToData:signature2.snapshot] || (signature1.snapshot == nil && signature2.snapshot == nil)));
}

- (BOOL)isCardSignaturesEqualWithSignature:(VSSCardSignature * __nonnull)signature1 and:(VSSCardSignature * __nonnull)signature2 {
    return ([signature1.signer isEqualToString:signature2.signer] &&
            [signature1.signature isEqualToData:signature2.signature] &&
            ([signature1.snapshot isEqualToData:signature2.snapshot] || (signature1.snapshot == nil && signature2.snapshot == nil)) &&
            ([signature1.extraFields isEqualToDictionary:signature2.extraFields] || (signature1.extraFields == nil && signature2.extraFields == nil)));
}

- (BOOL)isRawCardContentEqualWithContent:(VSSRawCardContent * __nonnull)content1 and:(VSSRawCardContent * __nonnull)content2 {
    return ([content1.identity isEqualToString:content2.identity] &&
            [content1.publicKey isEqualToData:content2.publicKey] &&
            [content1.version isEqualToString:content2.version] &&
             content1.createdAt == content2.createdAt &&
            ([content1.previousCardId isEqualToString:content2.previousCardId] || (content1.previousCardId == nil && content2.previousCardId == nil)));
}

- (BOOL)isRawSignaturesEqualWithSignatures:(NSArray<VSSRawSignature *> * __nonnull)signatures1 and:(NSArray<VSSRawSignature *> * __nonnull)signatures2 {
    if (signatures1.count != signatures2.count) {
        return false;
    }
    
    for (VSSRawSignature* signature1 in signatures1) {
        for (VSSRawSignature* signature2 in signatures1) {
            if ([signature2.signer isEqualToString:signature1.signer]) {
                if (!([signature1.signature isEqualToData:signature2.signature]
                      && ([signature1.snapshot isEqualToData:signature2.snapshot] || (signature1.snapshot == nil && signature2.snapshot == nil)))) {
                    return NO;
                }
            }
        }
    }
    
    return YES;
}

- (BOOL)isCardSignaturesEqualWithSignatures:(NSArray<VSSCardSignature *> * __nonnull)signatures1 and:(NSArray<VSSCardSignature *> * __nonnull)signatures2 {
    
    if (signatures1.count != signatures2.count) {
        return false;
    }
    BOOL found = false;
    for (VSSCardSignature* signature1 in signatures1) {
        found = false;
        for (VSSCardSignature* signature2 in signatures1) {
            if ([signature2.signer isEqualToString:signature1.signer]) {
                found = ([signature1.signature isEqualToData:signature2.signature] &&
                         ([signature1.snapshot isEqualToData:signature2.snapshot] || (signature1.snapshot == nil && signature2.snapshot == nil)));
            }
        }
        if (found == false) {
            return false;
        }
    }
    
    return true;
}

@end
