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

#import "VSCByteArrayUtils.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;

@implementation VSCByteArrayUtils

+ (VirgilByteArray)convertVirgilByteArrayFromData:(NSData *)data {
    if (data.length == 0) {
        return VirgilByteArray();
    }
    
    const unsigned char *dataToEncrypt = static_cast<const unsigned char *>(data.bytes);
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(dataToEncrypt, [data length]);
}

+ (VirgilByteArray)convertVirgilByteArrayFromString:(NSString *)string {
    if (string.length == 0) {
        return VirgilByteArray();
    }
    
    std::string pass = std::string(string.UTF8String);
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(pass.data(), pass.size());
}

+ (NSString *)hexStringFromData:(NSData *)data {
    std::string cStr = VirgilByteArrayUtils::bytesToHex([VSCByteArrayUtils convertVirgilByteArrayFromData:data]);
    return [NSString stringWithCString:cStr.c_str() encoding:[NSString defaultCStringEncoding]];;
}

+ (NSData *)dataFromHexString:(NSString *)string {
    std::string cStr = std::string(string.UTF8String);
    VirgilByteArray vData = VirgilByteArrayUtils::hexToBytes(cStr);
    return [[NSData alloc] initWithBytes:vData.data() length:vData.size()];
}

@end
