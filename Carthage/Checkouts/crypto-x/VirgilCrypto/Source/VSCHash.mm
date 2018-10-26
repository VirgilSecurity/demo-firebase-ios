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

#import "VSCHash.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::VirgilByteArray;
using CAlgorithm = virgil::crypto::foundation::VirgilHash::Algorithm;


@interface VSCHash ()

@property(nonatomic, assign) VirgilHash *hash;

@end

@implementation VSCHash

@synthesize hash = _hash;

- (instancetype)initWithAlgorithm:(VSCHashAlgorithm)algorithm {
    self = [super init];
    if (!self) {
        return nil;
    }

    _hash = new VirgilHash([self convertVSCAlgorithmToCAlgorithm:algorithm]);

    return self;
}

- (void)dealloc {
    if (_hash != NULL) {
        delete _hash;
        _hash = NULL;
    }
}

#pragma mark - Private

- (CAlgorithm)convertVSCAlgorithmToCAlgorithm:(VSCHashAlgorithm)keyType {
    CAlgorithm result;
    switch (keyType) {
        case VSCHashAlgorithmMD5:
            result = CAlgorithm::MD5;
            break;
        case VSCHashAlgorithmSHA1:
            result = CAlgorithm::SHA1;
            break;
        case VSCHashAlgorithmSHA224:
            result = CAlgorithm::SHA224;
            break;
        case VSCHashAlgorithmSHA256:
            result = CAlgorithm::SHA256;
            break;
        case VSCHashAlgorithmSHA384:
            result = CAlgorithm::SHA384;
            break;
        case VSCHashAlgorithmSHA512:
            result = CAlgorithm::SHA512;
            break;
    }
    return result;
}

#pragma mark - Public

- (NSData *)hash:(NSData *)data {
    const VirgilByteArray &vData = [VSCByteArrayUtils convertVirgilByteArrayFromData:data];
    const VirgilByteArray &hashData = self.hash->hash(vData);

    return [NSData dataWithBytes:hashData.data() length:hashData.size()];
}

- (void)start {
    self.hash->start();
}

- (void)updateWithData:(NSData *)data {
    const VirgilByteArray &vData = [VSCByteArrayUtils convertVirgilByteArrayFromData:data];
    self.hash->update(vData);
}

- (NSData *)finish {
    const VirgilByteArray &hashData = self.hash->finish();
    
    return [NSData dataWithBytes:hashData.data() length:hashData.size()];
}

@end
