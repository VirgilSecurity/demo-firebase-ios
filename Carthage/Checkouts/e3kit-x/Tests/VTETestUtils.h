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

#ifndef VTETestUtils_h
#define VTETestUtils_h

#import "VTETestsConst.h"

@import VirgilSDK;
@import VirgilCryptoApiImpl;
@import VirgilSDKKeyknox;
@import VirgilSDKPythia;

@interface VTETestUtils : NSObject

@property (nonatomic) VSMVirgilCrypto * __nonnull crypto;
@property (nonatomic) VTETestsConst * __nonnull consts;

- (NSString * __nonnull)getTokenStringWithIdentity:(NSString * __nonnull)identity error:(NSError * __nullable * __nullable)errorPtr;
- (id<VSSAccessToken> __nonnull)getTokenWithIdentity:(NSString * __nonnull)identity ttl:(NSTimeInterval)ttl error:(NSError * __nullable * __nullable)errorPtr;
- (VSSCard * __nullable)publishRandomCard;
- (BOOL)isPublicKeysEqualWithPublicKeys1:(NSArray <VSMVirgilPublicKey *> * __nonnull)publicKeys1 publicKeys2:(NSArray <VSMVirgilPublicKey *> * __nonnull)publicKeys2;

-(void)clearAllStoragesWithPassword:(NSString * __nonnull)password identity:(NSString * __nonnull)identity keychainStorage:(VSSKeychainStorage * __nonnull)keychainStorage completionHandler:(void(^)(VSKSyncKeyStorage * _Nonnull, NSError * _Nonnull))completionHandler;
-(void)setUpSyncKeyStorageWithPassword:(NSString * __nonnull)password identity:(NSString * __nonnull)identity completionHandler:(void(^)(VSKSyncKeyStorage * _Nonnull, NSError * _Nonnull))completionHandler;

- (instancetype __nonnull)initWith NS_UNAVAILABLE;

- (instancetype __nonnull)initWithCrypto:(VSMVirgilCrypto * __nonnull)crypto consts:(VTETestsConst * __nonnull)consts;

@end


#endif /* VTETestUtils_h */
