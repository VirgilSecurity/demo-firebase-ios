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

#ifndef VSSTestUtils_h
#define VSSTestUtils_h

#import "VSSTestsConst.h"

@import VirgilSDK;
@import VirgilCryptoApiImpl;

@interface VSSTestUtils : NSObject

@property (nonatomic) VSMVirgilCrypto * __nonnull crypto;
@property (nonatomic) VSSTestsConst * __nonnull consts;

- (VSSRawSignedModel * __nonnull)instantiateRawSignedModelWithKeyPair:(VSMVirgilKeyPair * __nullable)keyPair identity:(NSString *_Nullable)identity error:(NSError * __nullable * __nullable)errorPtr;

- (NSString * __nonnull)getTokenStringWithIdentity:(NSString * __nonnull)identity error:(NSError * __nullable * __nullable)errorPtr;
- (id<VSSAccessToken> __nonnull)getTokenWithIdentity:(NSString * __nonnull)identity ttl:(NSTimeInterval)ttl error:(NSError * __nullable * __nullable)errorPtr;
- (NSString * __nonnull)getTokenWithWrongPrivateKeyWithIdentity:(NSString * __nonnull)identity error:(NSError * __nullable * __nullable)errorPtr;

-(VSSGeneratorJwtProvider * __nonnull)getGeneratorJwtProviderWithIdentity:(NSString * __nonnull)identity error:(NSError * __nullable * __nullable)errorPtr;

-(NSData * __nonnull)getRandomData;

-(BOOL)isCardsEqualWithCard:(VSSCard * __nonnull)card1 and:(VSSCard * __nonnull)card2;
-(BOOL)isRawCardContentEqualWithContent:(VSSRawCardContent * __nonnull)content1 and:(VSSRawCardContent * __nonnull)content2;
-(BOOL)isRawSignaturesEqualWithSignature:(VSSRawSignature * __nonnull)signature1 and:(VSSRawSignature * __nonnull)signature2;
-(BOOL)isCardSignaturesEqualWithSignature:(VSSCardSignature * __nonnull)signature1 and:(VSSCardSignature * __nonnull)signature2;
-(BOOL)isRawSignaturesEqualWithSignatures:(NSArray<VSSRawSignature *> * __nonnull)signatures1 and:(NSArray<VSSRawSignature *> * __nonnull)signatures2;
-(BOOL)isCardSignaturesEqualWithSignatures:(NSArray<VSSCardSignature *> * __nonnull)signatures1 and:(NSArray<VSSCardSignature *> * __nonnull)signatures2;

-(VSSRawSignature * __nullable)getSelfSignatureFromModel:(VSSRawSignedModel * __nonnull)rawCard;
-(VSSCardSignature * __nullable)getSelfSignatureFromCard:(VSSCard * __nonnull)card;

- (instancetype __nonnull)initWith NS_UNAVAILABLE;

- (instancetype __nonnull)initWithCrypto:(VSMVirgilCrypto * __nonnull)crypto consts:(VSSTestsConst * __nonnull)consts;

@end

#endif /* VSSTestUtils_h */
