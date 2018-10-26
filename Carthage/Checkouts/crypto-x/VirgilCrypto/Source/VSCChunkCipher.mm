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

#import "VSCChunkCipher.h"
#import "VSCBaseCipherPrivate.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilChunkCipher;
using virgil::crypto::VirgilDataSink;
using virgil::crypto::VirgilDataSource;

NSString *const kVSCChunkCipherErrorDomain = @"VSCChunkCipherErrorDomain";
const unsigned long kVSCChunkCipherPreferredChunkSize = 1024 * 1024;

class VSCChunkCipherDataSource : public VirgilDataSource {

    NSInputStream *istream;
public:
    VSCChunkCipherDataSource(NSInputStream *is);

    ~VSCChunkCipherDataSource();

    bool hasData();

    VirgilByteArray read();
};

VSCChunkCipherDataSource::VSCChunkCipherDataSource(NSInputStream *is) {
    /// Assign pointer.
    this->istream = is;
    if (this->istream.streamStatus == NSStreamStatusNotOpen) {
        [this->istream open];
    }
}

VSCChunkCipherDataSource::~VSCChunkCipherDataSource() {
    /// Drop pointer.
    [this->istream close];
    this->istream = NULL;
}

bool VSCChunkCipherDataSource::hasData() {
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

VirgilByteArray VSCChunkCipherDataSource::read() {
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

class VSCChunkCipherDataSink : public VirgilDataSink {

    NSOutputStream *ostream;
public:
    VSCChunkCipherDataSink(NSOutputStream *os);

    ~VSCChunkCipherDataSink();
    bool isGood();

    void write(const VirgilByteArray& data);
};

VSCChunkCipherDataSink::VSCChunkCipherDataSink(NSOutputStream *os) {
    /// Assign pointer.
    this->ostream = os;
    if (this->ostream.streamStatus == NSStreamStatusNotOpen) {
        [this->ostream open];
    }
}

VSCChunkCipherDataSink::~VSCChunkCipherDataSink() {
    /// Drop pointer.
    [this->ostream close];
    this->ostream = NULL;
}

bool VSCChunkCipherDataSink::isGood() {
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

void VSCChunkCipherDataSink::write(const VirgilByteArray &data) {
    if (this->ostream != NULL) {
        [this->ostream write:data.data() maxLength:data.size()];
    }
}

@implementation VSCChunkCipher

- (void)initializeCipher {
    if (self.llCipher != NULL) {
        // llCipher has been initialized already.
        return;
    }

    try {
        self.llCipher = new VirgilChunkCipher();
    }
    catch(...) {
        self.llCipher = NULL;
    }
}

- (void)dealloc {
    if (self.llCipher != NULL) {
        delete (VirgilChunkCipher *)self.llCipher;
        self.llCipher = NULL;
    }
}

- (VirgilChunkCipher *)cipher {
    if (self.llCipher == NULL) {
        return NULL;
    }

    return static_cast<VirgilChunkCipher *>(self.llCipher);
}

- (BOOL)encryptDataFromStream:(NSInputStream *__nonnull)source toStream:(NSOutputStream *__nonnull)destination error:(NSError * __nullable * __nullable)error {
    return [self encryptDataFromStream:source toStream:destination preferredChunkSize:kVSCChunkCipherPreferredChunkSize embedContentInfo:YES error:error];
}

- (BOOL)encryptDataFromStream:(NSInputStream *)source toStream:(NSOutputStream *)destination preferredChunkSize:(size_t)chunkSize embedContentInfo:(BOOL)embedContentInfo error:(NSError **)error {
    if (source == nil || destination == nil) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to encrypt stream: At least one of the required parameters is missing.", @"Encrypt stream data error.") }];
        }
        return NO;
    }

    try {
        if ([self cipher] != NULL) {
            VSCChunkCipherDataSource src = VSCChunkCipherDataSource(source);
            VSCChunkCipherDataSink dest = VSCChunkCipherDataSink(destination);
            [self cipher]->encrypt(src, dest, embedContentInfo, chunkSize);

            return YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to encrypt stream. Cipher is not initialized properly." }];
            }
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during stream encryption.";
            }
            *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1002 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1003 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream encryption." }];
        }
    }
    
    return NO;
}

- (BOOL)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination recipientId:(NSData * __nonnull)recipientId privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error {
    if (source == nil || destination == nil || recipientId.length == 0 || privateKey.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1004 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt stream: At least one of the required parameters is missing.", @"Decrypt stream data error.") }];
        }
        
        return NO;
    }

    try {
        if ([self cipher] != NULL) {
            VSCChunkCipherDataSource src = VSCChunkCipherDataSource(source);
            VSCChunkCipherDataSink dest = VSCChunkCipherDataSink(destination);
            const VirgilByteArray &recId = [VSCByteArrayUtils convertVirgilByteArrayFromData:recipientId];
            const unsigned char *pKey = static_cast<const unsigned char *>(privateKey.bytes);
            if (keyPassword.length == 0) {
                [self cipher]->decryptWithKey(src, dest, recId, VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKey, [privateKey length]));
            }
            else {
                std::string keyPass = std::string(keyPassword.UTF8String);
                [self cipher]->decryptWithKey(src, dest, recId, VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pKey, [privateKey length]), VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(keyPass.data(), keyPass.size()));
            }
            
            return YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1005 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt stream. Cipher is not initialized properly." }];
            }
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during stream decryption.";
            }
            *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1006 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1007 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream decryption." }];
        }
    }
    
    return NO;
}

- (BOOL)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination password:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error {
    if (source == nil || destination == nil || password.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1008 userInfo:@{ NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to decrypt stream: At least one of the required parameters is missing.", @"Decrypt stream data error.") }];
        }
        
        return NO;
    }

    try {
        if ([self cipher] != NULL) {
            VSCChunkCipherDataSource src = VSCChunkCipherDataSource(source);
            VSCChunkCipherDataSink dest = VSCChunkCipherDataSink(destination);
            std::string pwd = std::string(password.UTF8String);
            [self cipher]->decryptWithPassword(src, dest, VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pwd.data(), pwd.size()));
            
            return YES;
        }
        else {
            if (error) {
                *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1009 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt stream. Cipher is not initialized properly." }];
            }
        }
    }
    catch(std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during stream decryption.";
            }
            *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1010 userInfo:@{ NSLocalizedDescriptionKey: description }];
        }
    }
    catch(...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCChunkCipherErrorDomain code:-1011 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown exception during stream decryption." }];
        }
    }
    
    return NO;
}

@end
