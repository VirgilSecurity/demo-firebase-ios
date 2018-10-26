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
#import "VSCPfsPublicKey.h"

/**
 Class that represents Responder Public Info: identity, long-term and one-time public keys.
 */
NS_SWIFT_NAME(PfsResponderPublicInfo)
@interface VSCPfsResponderPublicInfo : NSObject
/**
 Designated initializer.

 @param identityPublicKey identity card public key
 @param longTermPublicKey long-term card public key
 @param oneTimePublicKey one-time card public key
 @return initialized instance
 */
- (instancetype __nullable)initWithIdentityPublicKey:(VSCPfsPublicKey * __nonnull)identityPublicKey longTermPublicKey:(VSCPfsPublicKey * __nonnull)longTermPublicKey oneTimePublicKey:(VSCPfsPublicKey * __nullable)oneTimePublicKey NS_DESIGNATED_INITIALIZER;

/**
 Inherited unavailable initializer.

 @return initialized instance
 */
- (instancetype __nonnull)init NS_UNAVAILABLE;

/**
 Identity card public key
 */
@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull identityPublicKey;

/**
 Long-term card public key
 */
@property (nonatomic, readonly) VSCPfsPublicKey * __nonnull longTermPublicKey;

/**
 One-time card public key
 */
@property (nonatomic, readonly) VSCPfsPublicKey * __nullable oneTimePublicKey;

@end
