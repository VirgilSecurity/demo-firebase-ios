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
#import "VSCPfs.h"
#import "VSCPfsSessionPrivate.h"
#import "VSCPfsEncryptedMessagePrivate.h"
#import "VSCPfsInitiatorPrivateInfoPrivate.h"
#import "VSCPfsInitiatorPublicInfoPrivate.h"
#import "VSCPfsResponderPublicInfoPrivate.h"
#import "VSCpfsResponderPrivateInfoPrivate.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::pfs::VirgilPFS;
using virgil::crypto::pfs::VirgilPFSSession;
using virgil::crypto::VirgilByteArray;

@interface VSCPfs()

@property (nonatomic, assign, readonly) VirgilPFS * __nonnull cppPfs;

@end

@implementation VSCPfs

- (instancetype)init {
    self = [super init];
    if (self) {
        try {
            _cppPfs = new VirgilPFS();
        }
        catch(...) {
            return nil;
        }
    }
    
    return self;
}

- (VSCPfsSession *)startInitiatorSessionWithInitiatorPrivateInfo:(VSCPfsInitiatorPrivateInfo *)initiatorPrivateInfo respondrerPublicInfo:(VSCPfsResponderPublicInfo *)respondrerPublicInfo additionalData:(NSData *)additionalData {
    try {
        const VirgilByteArray &additionalDataArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:additionalData];
        const VirgilPFSSession &session = self.cppPfs->startInitiatorSession(*initiatorPrivateInfo.cppPfsInitiatorPrivateInfo, *respondrerPublicInfo.cppPfsResponderPublicInfo, additionalDataArr);
        return [[VSCPfsSession alloc] initWithSession:session];
    }
    catch(...) {
        return nil;
    }
}

- (VSCPfsSession *)startResponderSessionWithResponderPrivateInfo:(VSCPfsResponderPrivateInfo *)responderPrivateInfo initiatorPublicInfo:(VSCPfsInitiatorPublicInfo *)initiatorPublicInfo additionalData:(NSData *)additionalData {
    try {
        const VirgilByteArray &additionalDataArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:additionalData];
        const VirgilPFSSession &session = self.cppPfs->startResponderSession(*responderPrivateInfo.cppPfsResponderPrivateInfo, *initiatorPublicInfo.cppPfsInitiatorPublicInfo, additionalDataArr);
        return [[VSCPfsSession alloc] initWithSession:session];
    }
    catch(...) {
        return nil;
    }
}

- (VSCPfsEncryptedMessage *)encryptData:(NSData *)data {
    try {
        const VirgilByteArray &dataArr = [VSCByteArrayUtils convertVirgilByteArrayFromData:data];
        const VirgilPFSEncryptedMessage &encryptedMessage = self.cppPfs->encrypt(dataArr);
        return [[VSCPfsEncryptedMessage alloc] initWithEncryptedMessage:encryptedMessage];
    }
    catch(...) {
        return nil;
    }
}

- (NSData *)decryptMessage:(VSCPfsEncryptedMessage *)message {
    try {
        const VirgilByteArray &dataArr = self.cppPfs->decrypt(*message.cppPfsEncryptedMessage);
        return [NSData dataWithBytes:dataArr.data() length:dataArr.size()];
    }
    catch(...) {
        return nil;
    }
}

- (VSCPfsSession *)session {
    const VirgilPFSSession &session = self.cppPfs->getSession();
    if (!session.isEmpty()) {
        return [[VSCPfsSession alloc] initWithSession:session];
    }
    else {
        return nil;
    }
}

- (void)setSession:(VSCPfsSession *)session {
    if (session != nil) {
        self.cppPfs->setSession(*session.cppPfsSession);
    }
    else {
        self.cppPfs->setSession(VirgilPFSSession());
    }
    
}

- (void)dealloc {
    delete self.cppPfs;
}

@end
