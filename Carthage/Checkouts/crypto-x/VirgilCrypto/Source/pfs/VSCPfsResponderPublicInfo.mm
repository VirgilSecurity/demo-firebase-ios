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
#import "VSCPfsResponderPublicInfo.h"
#import "VSCPfsResponderPublicInfoPrivate.h"
#import "VSCPfsPublicKeyPrivate.h"

using virgil::crypto::VirgilByteArray;

@implementation VSCPfsResponderPublicInfo

- (instancetype)initWithIdentityPublicKey:(VSCPfsPublicKey *)identityPublicKey longTermPublicKey:(VSCPfsPublicKey *)longTermPublicKey oneTimePublicKey:(VSCPfsPublicKey *)oneTimePublicKey {
    self = [super init];
    if (self) {
        try {
            if (oneTimePublicKey != nil) {
                _cppPfsResponderPublicInfo = new VirgilPFSResponderPublicInfo(*identityPublicKey.cppPfsPublicKey, *longTermPublicKey.cppPfsPublicKey, *oneTimePublicKey.cppPfsPublicKey);
            }
            else {
                _cppPfsResponderPublicInfo = new VirgilPFSResponderPublicInfo(*identityPublicKey.cppPfsPublicKey, *longTermPublicKey.cppPfsPublicKey);
            }
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (VSCPfsPublicKey *)identityPublicKey {
    const VirgilByteArray &keyArr = self.cppPfsResponderPublicInfo->getIdentityPublicKey().getKey();
    NSData *key = [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
    
    return [[VSCPfsPublicKey alloc] initWithKey:key];
}

- (VSCPfsPublicKey *)longTermPublicKey {
    const VirgilByteArray &keyArr = self.cppPfsResponderPublicInfo->getLongTermPublicKey().getKey();
    NSData *key = [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
    
    return [[VSCPfsPublicKey alloc] initWithKey:key];
}

- (VSCPfsPublicKey *)oneTimePublicKey {
    const VirgilByteArray &keyArr = self.cppPfsResponderPublicInfo->getOneTimePublicKey().getKey();
    NSData *key = [NSData dataWithBytes:keyArr.data() length:keyArr.size()];
    
    return [[VSCPfsPublicKey alloc] initWithKey:key];
}

- (void)dealloc {
    delete self.cppPfsResponderPublicInfo;
}

@end
