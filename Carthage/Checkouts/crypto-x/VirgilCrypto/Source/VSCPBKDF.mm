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

#import "VSCPBKDF.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilPBKDF;
using virgil::crypto::foundation::VirgilHash;

const size_t kVSCDefaultRandomBytesSize = 64;
NSString *const kVSCPBKDFErrorDomain = @"VSCPBKDFErrorDomain";

@interface VSCPBKDF ()

@property (nonatomic, assign) VirgilPBKDF *pbkdf;

@end

@implementation VSCPBKDF

@dynamic salt;
@dynamic iterations;
@dynamic algorithm;
@dynamic hash;

@synthesize pbkdf = _pbkdf;

#pragma mark - Getters/Setters

- (NSData * __nonnull)salt {
    if (self.pbkdf == NULL) {
        return [NSData data];
    }
    
    NSData *salt = nil;
    try {
        VirgilByteArray vbaSalt = self.pbkdf->getSalt();
        salt = [NSData dataWithBytes:vbaSalt.data() length:vbaSalt.size()];
    }
    catch (...) {
        salt = [NSData data];
    }
    return salt;
}

- (unsigned int)iterations {
    if (self.pbkdf == NULL) {
        return 0;
    }
    
    unsigned int iterations = 0;
    try {
        iterations = self.pbkdf->getIterationCount();
    }
    catch (...) {
        iterations = 0;
    }
    return iterations;
}

- (VSCPBKDFAlgorithm)algorithm {
    if (self.pbkdf == NULL) {
        return VSCPBKDFAlgorithmPBKDF2;
    }
    
    VirgilPBKDF::Algorithm alg = VirgilPBKDF::Algorithm::PBKDF2;
    try {
        alg = self.pbkdf->getAlgorithm();
    } catch (...) {
        alg = VirgilPBKDF::Algorithm::PBKDF2;
    }
    return (VSCPBKDFAlgorithm)alg;
}

- (void)setAlgorithm:(VSCPBKDFAlgorithm)algorithm {
    if (self.pbkdf == NULL) {
        return;
    }
    
    VirgilPBKDF::Algorithm alg = VirgilPBKDF::Algorithm::PBKDF2;
    switch(algorithm) {
        case VSCPBKDFAlgorithmPBKDF2:
            alg = VirgilPBKDF::Algorithm::PBKDF2;
            break;
        default:
            break;
    }
    
    try {
        self.pbkdf->setAlgorithm(alg);
    }
    catch(...) {}
}

- (VSCPBKDFHash)hash {
    if (self.pbkdf == NULL) {
        return (VSCPBKDFHash)0;
    }

    VirgilHash::Algorithm hsh = (VirgilHash::Algorithm)0;
    try {
        hsh = self.pbkdf->getHashAlgorithm();
    }
    catch(...) {
        hsh = (VirgilHash::Algorithm)0;
    }
    return (VSCPBKDFHash)hsh;
}

- (void)setHash:(VSCPBKDFHash)hash {
    if (self.pbkdf == NULL) {
        return;
    }

    VirgilHash::Algorithm hsh = (VirgilHash::Algorithm)0;
    switch(hash) {
        case VSCPBKDFHashSHA1:
            hsh = VirgilHash::Algorithm::SHA1;
            break;
        case VSCPBKDFHashSHA224:
            hsh = VirgilHash::Algorithm::SHA224;
            break;
        case VSCPBKDFHashSHA256:
            hsh = VirgilHash::Algorithm::SHA256;
            break;
        case VSCPBKDFHashSHA384:
            hsh = VirgilHash::Algorithm::SHA384;
            break;
        case VSCPBKDFHashSHA512:
            hsh = VirgilHash::Algorithm::SHA512;
            break;
        default:
            break;
    }
    
    try {
        self.pbkdf->setHashAlgorithm(hsh);
    }
    catch(...) {}
}

#pragma mark - Lifecycle

- (instancetype)initWithSalt:(NSData *)salt iterations:(unsigned int)iterations {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    if (salt.length == 0) {
        salt = [[self class] randomBytesOfSize:0];
    }
    
    if (iterations == 0) {
        iterations = VirgilPBKDF::kIterationCount_Default;
    }
    
    try {
        const unsigned char *saltBytes = static_cast<const unsigned char *>(salt.bytes);
        VirgilByteArray saltArray = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(saltBytes, [salt length]);
        _pbkdf = new VirgilPBKDF(saltArray, iterations);
    }
    catch(...) {
        _pbkdf = NULL;
    }
    
    return self;
}

- (instancetype)init {
    return [self initWithSalt:nil iterations:0];
}

- (void)dealloc {
    if (_pbkdf != NULL) {
        delete _pbkdf;
        _pbkdf = NULL;
    }
}

#pragma mark - Public class logic

- (BOOL)enableRecommendationsCheckWithError:(NSError * __nullable * __nullable)error {
    BOOL success = NO;
    try {
        if (self.pbkdf != NULL) {
            self.pbkdf->enableRecommendationsCheck();
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCPBKDFErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Unable to enable security checks. PBKDF object is not initialized properly.", @"Unable to enable security checks. PBKDF object is not initialized properly.")}];
            }
            success = NO;
        }
    }
    catch (std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = NSLocalizedString(@"Unknown error: impossible to get PBKDF exception description.", @"Unknown error: impossible to get PBKDF exception description.");
            }
            *error = [NSError errorWithDomain:kVSCPBKDFErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch (...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCPBKDFErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Unknown PBKDF error.", @"Unknown PBKDF error.") }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)disableRecommendationsCheckWithError:(NSError * __nullable * __nullable)error {
    BOOL success = NO;
    try {
        if (self.pbkdf != NULL) {
            self.pbkdf->disableRecommendationsCheck();
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCPBKDFErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Unable to disable security checks. PBKDF object is not initialized properly.", @"Unable to disable security checks. PBKDF object is not initialized properly.")  }];
            }
            success = NO;
        }
    }
    catch (std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = NSLocalizedString(@"Unknown error: impossible to get PBKDF exception description.", @"Unknown error: impossible to get PBKDF exception description.");
            }
            *error = [NSError errorWithDomain:kVSCPBKDFErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch (...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCPBKDFErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Unknown PBKDF error.", @"Unknown PBKDF error.") }];
        }
        success = NO;
    }
    return success;
}

- (NSData *)keyFromPassword:(NSString *)password size:(size_t)size error:(NSError **)error {
    if (password.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCPBKDFErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to derive the key: password is missing.", @"Impossible to derive the key: password is missing.") }];
        }
        return nil;
    }
    
    NSData *keyData = nil;
    try {
        if (self.pbkdf != NULL) {
            std::string sPwd = std::string(password.UTF8String);
            VirgilByteArray vbaPwd = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(sPwd.data(), sPwd.size());
            VirgilByteArray vbaKey = self.pbkdf->derive(vbaPwd, size);
            
            keyData = [NSData dataWithBytes:vbaKey.data() length:vbaKey.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCPBKDFErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Unable to derive the key. PBKDF object is not initialized properly.", @"Unable to derive the key. PBKDF object is not initialized properly.")  }];
            }
            keyData = nil;
        }
    }
    catch (std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = NSLocalizedString(@"Unknown error: impossible to get PBKDF exception description.", @"Unknown error: impossible to get PBKDF exception description.");
            }
            *error = [NSError errorWithDomain:kVSCPBKDFErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        keyData = nil;
    }
    catch (...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCPBKDFErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Unknown PBKDF error.", @"Unknown PBKDF error.") }];
        }
        keyData = nil;
    }
    return keyData;
}


+ (NSData*)randomBytesOfSize:(size_t)size {
    if (size == 0) {
        size = kVSCDefaultRandomBytesSize;
    }
    uint8_t randomDataBytes[size];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(randomDataBytes), randomDataBytes) == 0) {
        return [NSData dataWithBytes:randomDataBytes length:sizeof(randomDataBytes)];
    }
    
    return [NSData data];
}

@end
