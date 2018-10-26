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
#import "VSCPfsEncryptedMessage.h"
#import "VSCPfsEncryptedMessagePrivate.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilByteArray;

@implementation VSCPfsEncryptedMessage

- (instancetype)initWithEncryptedMessage:(const VirgilPFSEncryptedMessage &)encryptedMessage {
    self = [super init];
    if (self) {
        try {
            _cppPfsEncryptedMessage = new VirgilPFSEncryptedMessage(encryptedMessage);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (instancetype)initWithSessionIdentifier:(NSData *)sessionIdentifier salt:(NSData *)salt cipherText:(NSData *)cipherText {
    self = [super init];
    if (self) {
        try {
            const VirgilByteArray &sessionIdentifierArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:sessionIdentifier];
            const VirgilByteArray &saltArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:salt];
            const VirgilByteArray &cipherTextArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:cipherText];
            _cppPfsEncryptedMessage = new VirgilPFSEncryptedMessage(sessionIdentifierArr, saltArr, cipherTextArr);
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (NSData *)sessionIdentifier {
    const VirgilByteArray &sessionIdentifierArr = self.cppPfsEncryptedMessage->getSessionIdentifier();
    return [NSData dataWithBytes:sessionIdentifierArr.data() length:sessionIdentifierArr.size()];
}

- (NSData *)salt {
    const VirgilByteArray &saltArr = self.cppPfsEncryptedMessage->getSalt();
    return [NSData dataWithBytes:saltArr.data() length:saltArr.size()];
}

- (NSData *)cipherText {
    const VirgilByteArray &cipherTextArr = self.cppPfsEncryptedMessage->getCipherText();
    return [NSData dataWithBytes:cipherTextArr.data() length:cipherTextArr.size()];
}

- (void)dealloc {
    delete self.cppPfsEncryptedMessage;
}

@end
