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

#import "VSCStreamCipher.h"
#import "VSCBaseCipherPrivate.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilStreamCipher;
using virgil::crypto::VirgilDataSource;
using virgil::crypto::VirgilDataSink;

NSString *const kVSCStreamCipherErrorDomain = @"VSCStreamCipherErrorDomain";

class VSCStreamCipherDataSource : public ::virgil::crypto::VirgilDataSource {

    NSInputStream *istream;
public:
    VSCStreamCipherDataSource(NSInputStream *is);

    ~VSCStreamCipherDataSource();

    bool hasData();

    VirgilByteArray read();
};

VSCStreamCipherDataSource::VSCStreamCipherDataSource(NSInputStream *is) {
    /// Assign pointer.
    this->istream = is;
    if (this->istream.streamStatus == NSStreamStatusNotOpen) {
        [this->istream open];
    }
}

VSCStreamCipherDataSource::~VSCStreamCipherDataSource() {
    /// Drop pointer.
    [this->istream close];
    this->istream = NULL;
}

bool VSCStreamCipherDataSource::hasData() {
    if (this->istream != NULL) {
        NSStreamStatus st = this->istream.streamStatus;
        if (st == NSStreamStatusNotOpen || st == NSStreamStatusError || st == NSStreamStatusClosed) {
            return false;
        }

        if (this->istream.hasBytesAvailable) {
            return true;
        }
    }

    return false;
}

VirgilByteArray VSCStreamCipherDataSource::read() {
    std::vector<unsigned char> buffer;
    unsigned long desiredSize = 1024;
    long actualSize = 0;

    buffer.resize(desiredSize);
    if (this->istream != NULL) {
        actualSize = [this->istream read:buffer.data() maxLength:desiredSize];
        if (actualSize < 0) {
            actualSize = 0;
        }
    }
    buffer.resize((unsigned long) actualSize);
    buffer.shrink_to_fit();

    return static_cast<VirgilByteArray>(buffer);
}

class VSCStreamCipherDataSink : public virgil::crypto::VirgilDataSink {

    NSOutputStream *ostream;
public:
    VSCStreamCipherDataSink(NSOutputStream *os);

    ~VSCStreamCipherDataSink();
    bool isGood();

    void write(const VirgilByteArray& data);
};

VSCStreamCipherDataSink::VSCStreamCipherDataSink(NSOutputStream *os) {
    /// Assign pointer.
    this->ostream = os;
    if (this->ostream.streamStatus == NSStreamStatusNotOpen) {
        [this->ostream open];
    }
}

VSCStreamCipherDataSink::~VSCStreamCipherDataSink() {
    /// Drop pointer.
    [this->ostream close];
    this->ostream = NULL;
}

bool VSCStreamCipherDataSink::isGood() {
    if (this->ostream != NULL) {
        NSStreamStatus st = this->ostream.streamStatus;
        if (st == NSStreamStatusNotOpen || st == NSStreamStatusError || st == NSStreamStatusClosed) {
            return false;
        }

        if (this->ostream.hasSpaceAvailable) {
            return true;
        }
    }

    return false;
}

void VSCStreamCipherDataSink::write(const VirgilByteArray &data) {
    if (this->ostream != NULL) {
        [this->ostream write:data.data() maxLength:data.size()];
    }
}

@interface VSCStreamCipher ()

@end

@implementation VSCStreamCipher

- (void)initializeCipher {
    if (self.llCipher != NULL) {
        // llCipher has been initialized already.
        return;
    }
    
    try {
        self.llCipher = new VirgilStreamCipher();
    }
    catch(...) {
        self.llCipher = NULL;
    }
}

- (void)dealloc {
    if (self.llCipher != NULL) {
        delete (VirgilStreamCipher *)self.llCipher;
        self.llCipher = NULL;
    }
}

- (VirgilStreamCipher *)Cipher {
    if (self.llCipher == NULL) {
        return NULL;
    }
    
    return static_cast<VirgilStreamCipher *>(self.llCipher);
}

- (BOOL)encryptDataFromStream:(NSInputStream *)source toStream:(NSOutputStream *)destination embedContentInfo:(BOOL)embedContentInfo error:(NSError **)error {
    if (source == nil || destination == nil) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to encrypt stream: At least one of the required parameters is missing.", @"Encrypt stream data error.") }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if ([self Cipher] != NULL) {
            VSCStreamCipherDataSource src = VSCStreamCipherDataSource(source);
            VSCStreamCipherDataSink dest = VSCStreamCipherDataSink(destination);
            bool embed = embedContentInfo;
            [self Cipher]->encrypt(src, dest, embed);

            if (error) {
                *error = nil;
            }

            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to encrypt stream. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during stream encryption.";
            }
            *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream encryption." }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination recipientId:(NSData * __nonnull)recipientId privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error {
    if (source == nil || destination == nil || recipientId.length == 0 || privateKey.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1004 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt stream: At least one of the required parameters is missing.", @"Decrypt stream data error.") }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if ([self Cipher] != NULL) {
            VSCStreamCipherDataSource src = VSCStreamCipherDataSource(source);
            VSCStreamCipherDataSink dest = VSCStreamCipherDataSink(destination);
            const VirgilByteArray &recId = [VSCByteArrayUtils convertVirgilByteArrayFromData:recipientId];
            const VirgilByteArray &pKey = [VSCByteArrayUtils convertVirgilByteArrayFromData:privateKey];

            if (keyPassword.length == 0) {
                [self Cipher]->decryptWithKey(src, dest, recId, pKey);
            }
            else {
                const VirgilByteArray &keyPass = [VSCByteArrayUtils convertVirgilByteArrayFromString:keyPassword];
                [self Cipher]->decryptWithKey(src, dest, recId, pKey, keyPass);
            }
            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1005 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt stream. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during stream decryption.";
            }
            *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1006 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1007 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream decryption." }];
        }
        success = NO;
    }
    return success;
}

- (BOOL)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination password:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error {
    if (source == nil || destination == nil || password.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1008 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt stream: At least one of the required parameters is missing.", @"Decrypt stream data error.") }];
        }
        return NO;
    }
    
    BOOL success = NO;
    try {
        if ([self Cipher] != NULL) {
            VSCStreamCipherDataSource src = VSCStreamCipherDataSource(source);
            VSCStreamCipherDataSink dest = VSCStreamCipherDataSink(destination);
            const VirgilByteArray &pwd = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];

            [self Cipher]->decryptWithPassword(src, dest,pwd);

            if (error) {
                *error = nil;
            }
            success = YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1009 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt stream. Cipher is not initialized properly." }];
            }
            success = NO;
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during stream decryption.";
            }
            *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
        success = NO;
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCStreamCipherErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream decryption." }];
        }
        success = NO;
    }
    return success;
}

@end
