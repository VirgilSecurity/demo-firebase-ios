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

#import "VSCSigner.h"

/// In the MacOSX SDK there is a macro definition which covers signer->verify method.
/// So we need to disable it for this.
#ifdef verify
#undef verify
#endif

#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilSigner;
using virgil::crypto::foundation::VirgilHash;

NSString *const kVSCSignerErrorDomain = @"VSCSignerErrorDomain";

@interface VSCSigner ()

@property (nonatomic, assign) VirgilSigner *signer;

@end

@implementation VSCSigner

@synthesize signer = _signer;

#pragma mark - Lifecycle

- (instancetype)init {
    return [self initWithHash:nil];
}

- (instancetype)initWithHash:(NSString *)hash {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    try {
        if ([hash isEqualToString:kVSCHashNameMD5]) {
            _signer = new VirgilSigner(VirgilHash::Algorithm::MD5);
        }
        else if ([hash isEqualToString:kVSCHashNameSHA256]) {
            _signer = new VirgilSigner(VirgilHash::Algorithm::SHA256);
        }
        else if ([hash isEqualToString:kVSCHashNameSHA384]) {
            _signer = new VirgilSigner(VirgilHash::Algorithm::SHA384);
        }
        else if ([hash isEqualToString:kVSCHashNameSHA512]) {
            _signer = new VirgilSigner(VirgilHash::Algorithm::SHA512);
        }
        else {
            _signer = new VirgilSigner();
        }
    }
    catch(...) {
        _signer = NULL;
    }
    return self;
}

- (void)dealloc {
    if (_signer != NULL) {
        delete _signer;
        _signer = NULL;
    }
}

#pragma mark - Public class logic

- (NSData *)signData:(NSData *)data privateKey:(NSData *)privateKey keyPassword:(NSString *)keyPassword error:(NSError **)error {
    if (privateKey.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCSignerErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to compose the signature: no private key given.", "Sign data error.") }];
        }
        return nil;
    }
    
    NSData *signData = nil;
    try {
        if (self.signer != NULL) {
            // Convert NSData to
            const unsigned char *dataToSign = static_cast<const unsigned char *>(data.bytes);
            VirgilByteArray plainData = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToSign, [data length]);
            // Convert NSData to
            const unsigned char *pKeyData = static_cast<const unsigned char *>(privateKey.bytes);
            VirgilByteArray pKey = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyData, [privateKey length]);
            
            VirgilByteArray sign;
            if (keyPassword.length > 0) {
                std::string pKeyPassS = std::string(keyPassword.UTF8String);
                VirgilByteArray pKeyPassword = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKeyPassS.data(), pKeyPassS.size());
                sign = self.signer->sign(plainData, pKey, pKeyPassword);
            }
            else {
                sign = self.signer->sign(plainData, pKey);
            }
            signData = [NSData dataWithBytes:sign.data() length:sign.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCSignerErrorDomain code:-1013 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to compose signature. Cipher is not initialized properly." }];
            }
            signData = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown error: impossible to get sign exception description.";
            }
            *error = [NSError errorWithDomain:kVSCSignerErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        signData = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCSignerErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown error during composing of signature." }];
        }
        signData = nil;
    }
    
    return signData;
}

- (BOOL)verifySignature:(NSData *)signature data:(NSData *)data publicKey:(NSData *)publicKey error:(NSError **)error {
    if (signature.length == 0 || publicKey.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCSignerErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to verify signature: signature data or/and public key is/are not given.", @"Verify data error.") }];
        }
        return NO;
    }
    
    BOOL verified = NO;
    try {
        if (self.signer != NULL) {
            // Convert NSData data
            const unsigned char *signedDataPtr = static_cast<const unsigned char *>(data.bytes);
            VirgilByteArray signedData = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(signedDataPtr, [data length]);
            // Convert NSData sign
            const unsigned char *signDataPtr = static_cast<const unsigned char *>(signature.bytes);
            VirgilByteArray signData = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(signDataPtr, [signature length]);
            // Convert NSData Key
            const unsigned char *keyDataPtr = static_cast<const unsigned char *>(publicKey.bytes);
            VirgilByteArray pKey = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(keyDataPtr, [publicKey length]);
            
            bool result = self.signer->verify(signedData, signData, pKey);
            verified = result;
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCSignerErrorDomain code:-1014 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to verify signature. Cipher is not initialized properly." }];
            }
            verified = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown error: impossible to get verify exception description.";
            }
            *error = [NSError errorWithDomain:kVSCSignerErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        verified = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCSignerErrorDomain code:-1012 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown error during verification of signature." }];
        }
        verified = NO;
    }
    return verified;
}

@end
