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
#import "VSCPfsSession.h"
#import "VSCPfsSessionPrivate.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilByteArray;

@implementation VSCPfsSession

- (instancetype)initWithSession:(const VirgilPFSSession &)session {
    self = [super init];
    if (self) {
        try {
            _cppPfsSession = new VirgilPFSSession(session);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (instancetype)initWithIdentifier:(NSData *)identifier encryptionSecretKey:(NSData *)encryptionSecretKey decryptionSecretKey:(NSData *)decryptionSecretKey additionalData:(NSData *)additionalData {
    self = [super init];
    if (self) {
        try {
            const VirgilByteArray &identifierArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:identifier];
            const VirgilByteArray &encryptionSecretKeyArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:encryptionSecretKey];
            const VirgilByteArray &decryptionSecretKeyArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:decryptionSecretKey];
            const VirgilByteArray &additionalDataArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:additionalData];
            
            _cppPfsSession = new VirgilPFSSession(identifierArr, encryptionSecretKeyArr, decryptionSecretKeyArr, additionalDataArr);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (NSData *)identifier {
    const VirgilByteArray &identifierArr = self.cppPfsSession->getIdentifier();
    return [NSData dataWithBytes:identifierArr.data() length:identifierArr.size()];
}

- (NSData *)encryptionSecretKey {
    const VirgilByteArray &encryptionSecretKeyArr = self.cppPfsSession->getEncryptionSecretKey();
    return [NSData dataWithBytes:encryptionSecretKeyArr.data() length:encryptionSecretKeyArr.size()];
}

- (NSData *)decryptionSecretKey {
    const VirgilByteArray &decryptionSecretKeyArr = self.cppPfsSession->getDecryptionSecretKey();
    return [NSData dataWithBytes:decryptionSecretKeyArr.data() length:decryptionSecretKeyArr.size()];
}

- (NSData *)additionalData {
    const VirgilByteArray &additionalDataArr = self.cppPfsSession->getAdditionalData();
    return [NSData dataWithBytes:additionalDataArr.data() length:additionalDataArr.size()];
}

- (void)dealloc {
    delete self.cppPfsSession;
}

@end
