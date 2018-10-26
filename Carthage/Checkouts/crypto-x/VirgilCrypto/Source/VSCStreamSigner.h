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
#import "VSCFoundationCommons.h"

/// Error domain constant for the `VSCStreamSigner` errors.
NS_SWIFT_NAME(kStreamSignerErrorDomain)
extern NSString * __nonnull const kVSCStreamSignerErrorDomain;

/**
 Wrapper for the functionality for composing/verifying signatures of streams.
 
 This wrapper works with `NSInputStream` instead of `NSData` objects.
 */
NS_SWIFT_NAME(StreamSigner)
@interface VSCStreamSigner : NSObject
/**
 Designated initializer

 @param hash Name of the preferred hash function. In case of `nil` default hash function will be used (SHA384). One of the following names should be used: `kVSCHashNameMD5`, `kVSCHashNameSHA256`, `kVSCHashNameSHA384`, `kVSCHashNameSHA512`.
 @return initialized instance.
 */
- (instancetype __nonnull)initWithHash:(NSString * __nullable)hash NS_DESIGNATED_INITIALIZER;

/**
 Generates signature for data provided by the source with given private key.

 @param source Input stream object containing the data which needs to be signed.
 @param privateKey Data object containing user's private key.
 @param keyPassword Password which was used to create key pair object or `nil`.
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return Signature data object.
 */
- (NSData * __nullable)signStreamData:(NSInputStream * __nonnull)source privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

/**
 Verifies signature.

 @param signature Data object containing a signature.
 @param source Input Stream object containing the data which was used to compose the signature on.
 @param publicKey Data object containing a public key data of a user whose signature needs to be verified.
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `YES` if signature is verified and can be trusted, `NO` - otherwise.
 */
- (BOOL)verifySignature:(NSData * __nonnull)signature fromStream:(NSInputStream * __nonnull)source publicKey:(NSData * __nonnull)publicKey error:(NSError * __nullable * __nullable)error;

@end
