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
#import "VSCVirgilRandom.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::foundation::VirgilRandom;
using virgil::crypto::VirgilByteArray;

@interface VSCVirgilRandom ()

@property(nonatomic, assign) VirgilRandom *random;

@end

@implementation VSCVirgilRandom

@synthesize random = _random;

- (instancetype __nonnull)initWithPersonalInfo:(NSString * __nonnull)personalInfo {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    try {
        std::string personalInfoString = std::string(personalInfo.UTF8String);
        _random = new VirgilRandom(personalInfoString);
    }
    catch(...) {
        return nil;
    }
    
    return self;
}

- (NSData *)randomizeWithBytesNum:(size_t)bytesNum {
    try {
        const VirgilByteArray &data = self.random->randomize(bytesNum);
        
        return [NSData dataWithBytes:data.data() length:data.size()];
    }
    catch(...) {
        return nil;
    }
}

- (size_t)randomize {
    return self.random->randomize();
}

- (size_t)randomizeBetweenMin:(size_t)min andMax:(size_t)max {
    return self.random->randomize(min, max);
}

- (void)dealloc {
    if (_random != NULL) {
        delete _random;
        _random = NULL;
    }
}

@end
