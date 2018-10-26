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

#import "VSCBaseCipher.h"
#import "VSCBaseCipherPrivate.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCipherBase;

NSString *const kVSCBaseCipherErrorDomain = @"VSCBaseCipherErrorDomain";

@interface VSCBaseCipher ()

- (VirgilCipherBase *)cipher;

@end

@implementation VSCBaseCipher

@synthesize llCipher = _llCipher;

- (instancetype)init {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    [self initializeCipher];
    return self;
}

- (void)initializeCipher {
    if (self.llCipher != NULL) {
        // llCipher has been initialized already.
        return;
    }
    
    try {
        self.llCipher = new VirgilCipherBase();
    }
    catch(...) {
        self.llCipher = NULL;
    }
}

- (VirgilCipherBase *)cipher {
    if (self.llCipher == NULL) {
        return NULL;
    }
    
    return static_cast<VirgilCipherBase *>(self.llCipher);
}

- (BOOL)addKeyRecipient:(NSData * __nonnull)recipientId publicKey:(NSData * __nonnull)publicKey error:(NSError * __nullable * __nullable)error {
    if (recipientId.length == 0 || publicKey.length == 0) {
        // Can't add recipient.
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to add key recipient. Required arguments are missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &recId = [VSCByteArrayUtils convertVirgilByteArrayFromData:recipientId];
            const VirgilByteArray &pKeyBytes = [VSCByteArrayUtils convertVirgilByteArrayFromData:publicKey];
            self.cipher->addKeyRecipient(recId, pKeyBytes);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to add key recipient. Cipher is not initialized properly." }];
            }
            success = NO;
        }
        
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during adding key recipient.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during adding key recipient." }];
        }
        success = NO;
    }
    
    return success;
}

- (BOOL)removeKeyRecipient:(NSData *)recipientId error:(NSError **)error {
    if (recipientId.length == 0) {
        // Can't remove recipient
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove key recipient. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &recId = [VSCByteArrayUtils convertVirgilByteArrayFromData:recipientId];
            self.cipher->removeKeyRecipient(recId);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1004 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove key recipient. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing key recipient.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1005 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1006 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing key recipient." }];
        }
        success = NO;
    }
    
    return success;
}

- (BOOL)isKeyRecipientExists:(NSData *__nonnull)recipientId {
    if (!recipientId || recipientId.length == 0) {
        return NO;
    }

    VirgilByteArray virgilRecipientId = [VSCByteArrayUtils convertVirgilByteArrayFromData:recipientId];
    return self.cipher->keyRecipientExists(virgilRecipientId);
}

- (BOOL)addPasswordRecipient:(NSString *)password error:(NSError **)error {
    if (password.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1007 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to add password recipient. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &vPass = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
            self.cipher->addPasswordRecipient(vPass);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1008 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to add password recipient. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during adding password recipient.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1009 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during adding password recipient." }];
        }
        success = NO;
    }
    
    return success;
}

- (BOOL)removePasswordRecipient:(NSString *)password error:(NSError **)error {
    if (password.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove password recipient. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &vPass = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
            self.cipher->removePasswordRecipient(vPass);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1012 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove password recipient. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing password recipient.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1013 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1014 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing password recipient." }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)removeAllRecipientsWithError:(NSError **)error {
    if (self.cipher == NULL) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1015 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove all recipients. Cipher is not initialized properly." }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        self.cipher->removeAllRecipients();
        if (error) {
            *error = nil;
        }
        success = YES;
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing all recipients.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1016 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1017 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing all recipients." }];
        }
        success = NO;
    }
    return success;
}

- (NSData *)contentInfoWithError:(NSError **)error {
    NSData* contentInfo = nil;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &content = self.cipher->getContentInfo();
            contentInfo = [NSData dataWithBytes:content.data() length:content.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1018 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get content info. Cipher is not initialized properly." }];
            }
            contentInfo = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during getting content info.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1019 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        contentInfo = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1020 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during getting content info." }];
        }
        contentInfo = nil;
    }
    return contentInfo;
}

- (BOOL)setContentInfo:(NSData *)contentInfo error:(NSError **)error {
    if (contentInfo.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1021 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set content info. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &contentInfoBytes = [VSCByteArrayUtils convertVirgilByteArrayFromData:contentInfo];
            self.cipher->setContentInfo(contentInfoBytes);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1022 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set content info. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during setting content info.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1023 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1024 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during setting content info." }];
        }
        success = NO;
    }
    return success;
}

- (size_t)contentInfoSizeInData:(NSData *)data error:(NSError **)error {
    if (data.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1025 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to calculate size of the content info. Required argument is missing." }];
        }
        return 0;
    }
    
    size_t size = 0;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &bytes = [VSCByteArrayUtils convertVirgilByteArrayFromData:data];
            size = self.cipher->defineContentInfoSize(bytes);
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1026 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to calculate size of the content info. Cipher is not initialized properly." }];
            }
            size = 0;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during calculating the size of the content info.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1027 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        size = 0;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1028 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during calculating the size of the content info." }];
        }
        size = 0;
    }
    return size;
}

- (BOOL)setInt:(int)value forKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1029 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom int parameter. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &strKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            self.cipher->customParams().setInteger(strKey, value);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1030 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom int parameter. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during setting custom int parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1031 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1032 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during setting custom int parameter." }];
        }
        success = NO;
    }
    return success;
}

- (int)intForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1033 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom int parameter. Required argument is missing." }];
        }
        return 0;
    }
    
    int value = 0;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            value = self.cipher->customParams().getInteger(vStrKey);
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1034 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom int parameter. Cipher is not initialized properly." }];
            }
            value = 0;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during getting custom int parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1035 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        value = 0;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1036 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during getting custom int parameter." }];
        }
        value = 0;
    }
    return value;
}

- (BOOL)removeIntForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1037 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom int parameter. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            self.cipher->customParams().removeInteger(vStrKey);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1038 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom int parameter. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing custom int parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1039 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1040 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing custom int parameter." }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)setString:(NSString *)value forKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0 || value.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1041 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom string parameter. At least one of the required arguments is missing." }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            const VirgilByteArray &vStrVal = [VSCByteArrayUtils convertVirgilByteArrayFromString:value];

            self.cipher->customParams().setString(vStrKey, vStrVal);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1042 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom string parameter. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during setting custom string parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1043 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1044 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during setting custom string parameter." }];
        }
        success = NO;
    }
    return success;
}

- (NSString *)stringForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1045 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom string parameter. Required argument is missing." }];
        }
        return nil;
    }
    
    NSString *value = nil;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            const VirgilByteArray &vStrVal = self.cipher->customParams().getString(vStrKey);
            std::string str = virgil::crypto::bytes2str(vStrVal);
            value = [[NSString alloc] initWithCString:str.c_str() encoding:NSUTF8StringEncoding];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1046 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom string parameter. Cipher is not initialized properly." }];
            }
            value = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during getting custom string parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1047 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        value = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1048 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during getting custom string parameter." }];
        }
        value = nil;
    }
    return value;
}

- (BOOL)removeStringForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1049 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom string parameter. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            self.cipher->customParams().removeString(vStrKey);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1050 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom string parameter. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing custom string parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1051 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1052 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing custom string parameter." }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)setData:(NSData *)value forKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0 || value.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1053 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom data parameter. At least one of the required arguments is missing." }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            const VirgilByteArray &vBytes = [VSCByteArrayUtils convertVirgilByteArrayFromData:value];
            self.cipher->customParams().setData(vStrKey, vBytes);

            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1054 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to set custom data parameter. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during setting custom data parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1055 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1056 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during setting custom data parameter." }];
        }
        success = NO;
    }
    return success;
}

- (NSData *)dataForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1057 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom data parameter. Required argument is missing." }];
        }
        return nil;
    }
    
    NSData *value = nil;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            const VirgilByteArray &dataVal = self.cipher->customParams().getData(vStrKey);
            value = [[NSData alloc] initWithBytes:dataVal.data() length:dataVal.size()];
            if (error) {
                *error = nil;
            }
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1058 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to get custom data parameter. Cipher is not initialized properly." }];
            }
            value = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during getting custom data parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1059 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        value = nil;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1060 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during getting custom data parameter." }];
        }
        value = nil;
    }
    return value;
}

- (BOOL)removeDataForKey:(NSString *)key error:(NSError **)error {
    if (key.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1061 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom data parameter. Required argument is missing." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        if (self.cipher != NULL) {
            const VirgilByteArray &vStrKey = [VSCByteArrayUtils convertVirgilByteArrayFromString:key];
            self.cipher->customParams().removeData(vStrKey);
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1062 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to remove custom data parameter. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during removing custom data parameter.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1063 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1064 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during removing custom data parameter." }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)isEmptyCustomParametersWithError:(NSError * __nullable * __nullable)error {
    if (self.cipher == NULL) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1065 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to check for emptiness of the custom parameters. Cipher is not initialized properly." }];
        }
        return YES;
    }
    
    BOOL success;
    try {
        bool empty = self.cipher->customParams().isEmpty();
        success = empty;
        if (error) {
            *error = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during checking for emptiness of the custom parameters.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1066 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = YES;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1067 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during checking for emptiness of the custom parameters." }];
        }
        success = YES;
    }
    return success;
}

- (BOOL)clearCustomParametersWithError:(NSError * __nullable * __nullable)error {
    if (self.cipher == NULL) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1068 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to clear the custom parameters. Cipher is not initialized properly." }];
        }
        return NO;
    }
    
    BOOL success;
    try {
        self.cipher->customParams().clear();
        success = YES;
        if (error) {
            *error = nil;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during clearing the custom parameters.";
            }
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1069 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = YES;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCBaseCipherErrorDomain code:-1070 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during clearing the custom parameters." }];
        }
        success = YES;
    }
    return success;
}

@end
