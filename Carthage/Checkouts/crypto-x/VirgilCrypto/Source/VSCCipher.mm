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

#import "VSCCipher.h"
#import "VSCBaseCipherPrivate.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCipher;

NSString *const kVSCCipherErrorDomain = @"VSCCipherErrorDomain";

@interface VSCCipher ()

- (VirgilCipher *)cipher;

@end

@implementation VSCCipher

#pragma mark - Lifecycle

- (void)initializeCipher {
    if (self.llCipher != NULL) {
        // llCipher has been initialized already.
        return;
    }
    
    try {
        self.llCipher = new VirgilCipher();
    }
    catch(...) {
        self.llCipher = NULL;
    }
}

- (void)dealloc {
    if (self.llCipher != NULL) {
        delete (VirgilCipher *)self.llCipher;
        self.llCipher = NULL;
    }
}

- (VirgilCipher *)cipher {
    if (self.llCipher == NULL) {
        return NULL;
    }
    
    return static_cast<VirgilCipher *>(self.llCipher);
}

#pragma mark - Public class logic

- (NSData *)encryptData:(NSData *)plainData embedContentInfo:(BOOL)embedContentInfo error:(NSError **)error {
    if (plainData.length == 0) {
        // Can't encrypt.
        if (error) {
            *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to encrypt: Required parameter is missing.", @"Encrypt data error.") }];
        }
        return nil;
    }
    
    NSData *encData = nil;
    try {
        if ([self cipher] != NULL) {
            VirgilByteArray plainDataArray = [VSCByteArrayUtils convertVirgilByteArrayFromData:plainData];

            // Encrypt data.
            VirgilByteArray encryptedData = [self cipher]->encrypt(plainDataArray, (bool)embedContentInfo);
            encData = [NSData dataWithBytes:encryptedData.data() length:encryptedData.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to encrypt. Cipher is not initialized properly." }];
            }
            encData = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during encryption.";
            }
            *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        encData = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during encryption." }];
        }
        encData = nil;
    }
    
    return encData;
}

- (NSData *)decryptData:(NSData *)encryptedData recipientId:(NSData *)recipientId privateKey:(NSData *)privateKey keyPassword:(NSString *)keyPassword error:(NSError **)error {
    if (encryptedData.length == 0 || recipientId.length == 0 || privateKey.length == 0) {
        // Can't decrypt
        if (error) {
            *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1004 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt with key: At least one of the required parameters is missing.", @"Decrypt data error.") }];
        }
        return nil;
    }
    
    NSData *decData = nil;
    try {
        if ([self cipher] != NULL) {
            const VirgilByteArray &encryptedDataArray = [VSCByteArrayUtils convertVirgilByteArrayFromData:encryptedData];
            const VirgilByteArray &recIdArray = [VSCByteArrayUtils convertVirgilByteArrayFromData:recipientId];
            const VirgilByteArray &pKey = [VSCByteArrayUtils convertVirgilByteArrayFromData:privateKey];
            
            VirgilByteArray decrypted;
            if (keyPassword.length > 0) {
                const VirgilByteArray &pKeyPass = [VSCByteArrayUtils convertVirgilByteArrayFromString:keyPassword];
                decrypted = [self cipher]->decryptWithKey(encryptedDataArray, recIdArray, pKey, pKeyPass);
            }
            else {
                decrypted = [self cipher]->decryptWithKey(encryptedDataArray, recIdArray, pKey);
            }
            decData = [NSData dataWithBytes:decrypted.data() length:decrypted.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1005 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt with key. Cipher is not initialized properly." }];
            }
            decData = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during decryption with key.";
            }
            *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1006 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        decData = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1007 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during decryption with key." }];
        }
        decData = nil;
    }
    return decData;
}

- (NSData *)decryptData:(NSData *)encryptedData password:(NSString *)password error:(NSError **)error {
    if (encryptedData.length == 0 || password.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1008 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt with password: At least one of the required parameters is missing.", @"Decrypt data error.") }];
        }
        return nil;
    }
    
    NSData *decData = nil;
    try {
        if ([self cipher] != NULL) {
            const VirgilByteArray &data = [VSCByteArrayUtils convertVirgilByteArrayFromData:encryptedData];
            const VirgilByteArray &pwd =[VSCByteArrayUtils convertVirgilByteArrayFromString:password];
            
            VirgilByteArray plain = [self cipher]->decryptWithPassword(data, pwd);
            decData = [NSData dataWithBytes:plain.data() length:plain.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1009 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt with password. Cipher is not initialized properly." }];
            }
            decData = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during decryption with password.";
            }
            *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        decData = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCCipherErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during decryption with password." }];
        }
        decData = nil;
    }
    
    return decData;
}

@end
