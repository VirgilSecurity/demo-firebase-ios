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

#import "VSCKeyPair.h"
#import "VSCByteArrayUtilsPrivate.h"
#import <VSCCrypto/VirgilCrypto.h>

#ifdef verify
#undef verify
#endif

using virgil::crypto::VirgilByteArray;
using CType = virgil::crypto::VirgilKeyPair::Type;
using namespace virgil::crypto;
using namespace virgil::crypto::foundation;

NSString *const kVSCKeyPairErrorDomain = @"VSCKeyPairErrorDomain";

@interface VSCKeyPair ()

@property(nonatomic, assign) VirgilKeyPair *keyPair;

+ (CType)convertVSCKeyTypeToCType:(VSCKeyType)keyType;

@end


@implementation VSCKeyPair

@synthesize keyPair = _keyPair;

#pragma mark - Lifecycle

+ (NSArray<VSCKeyPair *> *)generateMultipleKeys:(NSUInteger)numberOfKeys keyPairType:(VSCKeyType)keyPairType {
    NSMutableArray<VSCKeyPair *> *result = [[NSMutableArray alloc] initWithCapacity:numberOfKeys];
    
    CType type = [VSCKeyPair convertVSCKeyTypeToCType:keyPairType];
    
    try {
        VirgilAsymmetricCipher cipher;
        
        for (NSUInteger i = 0; i < numberOfKeys; i++) {
            cipher.genKeyPair(type);
            VSCKeyPair *keyPair = [[VSCKeyPair alloc] initWithKeyPair:VirgilKeyPair(cipher.exportPublicKeyToPEM(), cipher.exportPrivateKeyToPEM())];
            [result addObject:keyPair];
        }
    }
    catch (...) {
    }
    
    return result;
}

- (instancetype)initWithKeyPair:(const VirgilKeyPair &)keyPair {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    _keyPair = new VirgilKeyPair(keyPair);
    
    return self;
}

- (instancetype)initWithKeyPairType:(VSCKeyType)keyPairType password:(NSString *)password {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    try {
        CType type = [VSCKeyPair convertVSCKeyTypeToCType:keyPairType];
        if (!password || password.length == 0) {
            _keyPair = new VirgilKeyPair(VirgilKeyPair::generate(type));
        } else {
            const VirgilByteArray &pwd = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
            _keyPair = new VirgilKeyPair(VirgilKeyPair::generate(type, pwd));
        }
    }
    catch (...) {
        _keyPair = NULL;
    }

    return self;
}

- (instancetype)initWithKeyPairType:(VSCKeyType)keyPairType keyMaterial:(NSData *)keyMaterial password:(NSString *)password {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    try {
        CType type = [VSCKeyPair convertVSCKeyTypeToCType:keyPairType];
        const VirgilByteArray &keyMaterialArray = [VSCByteArrayUtils convertVirgilByteArrayFromData:keyMaterial];
        const VirgilByteArray &pwd = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
        
        _keyPair = new VirgilKeyPair(VirgilKeyPair::generateFromKeyMaterial(type, keyMaterialArray, pwd));
    }
    catch (...) {
        _keyPair = NULL;
        return nil;
    }
    
    return self;
}

- (instancetype)init {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    try {
        _keyPair = new VirgilKeyPair(VirgilKeyPair::generateRecommended());
    }
    catch (...) {
        _keyPair = NULL;
    }

    return self;
}

- (void)dealloc {
    if (_keyPair != NULL) {
        delete _keyPair;
        _keyPair = NULL;
    }
}

#pragma mark - Private

+ (CType)convertVSCKeyTypeToCType:(VSCKeyType)keyType {
    CType result;
    switch (keyType) {
        case VSCKeyTypeRSA_256:
            result = CType::RSA_256;
            break;
        case VSCKeyTypeRSA_512:
            result = CType::RSA_512;
            break;
        case VSCKeyTypeRSA_1024:
            result = CType::RSA_1024;
            break;
        case VSCKeyTypeRSA_2048:
            result = CType::RSA_2048;
            break;
        case VSCKeyTypeRSA_3072:
            result = CType::RSA_3072;
            break;
        case VSCKeyTypeRSA_4096:
            result = CType::RSA_4096;
            break;
        case VSCKeyTypeRSA_8192:
            result = CType::RSA_8192;
            break;
        case VSCKeyTypeEC_SECP192R1:
            result = CType::EC_SECP192R1;
            break;
        case VSCKeyTypeEC_SECP224R1:
            result = CType::EC_SECP224R1;
            break;
        case VSCKeyTypeEC_SECP256R1:
            result = CType::EC_SECP256R1;
            break;
        case VSCKeyTypeEC_SECP384R1:
            result = CType::EC_SECP384R1;
            break;
        case VSCKeyTypeEC_SECP521R1:
            result = CType::EC_SECP521R1;
            break;
        case VSCKeyTypeEC_BP256R1:
            result = CType::EC_BP256R1;
            break;
        case VSCKeyTypeEC_BP384R1:
            result = CType::EC_BP384R1;
            break;
        case VSCKeyTypeEC_BP512R1:
            result = CType::EC_BP512R1;
            break;
        case VSCKeyTypeEC_SECP192K1:
            result = CType::EC_SECP192K1;
            break;
        case VSCKeyTypeEC_SECP224K1:
            result = CType::EC_SECP224K1;
            break;
        case VSCKeyTypeEC_SECP256K1:
            result = CType::EC_SECP256K1;
            break;
        case VSCKeyTypeEC_CURVE25519:
            result = CType::EC_CURVE25519;
            break;
        case VSCKeyTypeFAST_EC_X25519:
            result = CType::FAST_EC_X25519;
            break;
        case VSCKeyTypeFAST_EC_ED25519:
            result = CType::FAST_EC_ED25519;
            break;
    }

    return result;
}

#pragma mark - Public

- (NSData *)publicKey {
    if (self.keyPair == NULL) {
        return [NSData data];
    }
    NSData *publicKey = nil;
    try {
        VirgilByteArray pkey = self.keyPair->publicKey();
        publicKey = [NSData dataWithBytes:pkey.data() length:pkey.size()];
    }
    catch (...) {
        publicKey = [NSData data];
    }
    return publicKey;
}

- (NSData *)privateKey {
    if (self.keyPair == NULL) {
        return [NSData data];
    }

    NSData *privateKey = nil;
    try {
        VirgilByteArray pkey = self.keyPair->privateKey();
        privateKey = [NSData dataWithBytes:pkey.data() length:pkey.size()];
    }
    catch (...) {
        privateKey = [NSData data];
    }
    return privateKey;
}

+ (NSData *__nullable)extractPublicKeyFromPrivateKey:(NSData *__nonnull)privateKey privateKeyPassword:(NSString *__nullable)password {
    if (!privateKey || privateKey.length == 0) {
        return nil;
    }

    NSData *result = nil;
    try {
        const VirgilByteArray &prvtKey = [VSCByteArrayUtils convertVirgilByteArrayFromData:privateKey];
        const VirgilByteArray &pass = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
        VirgilByteArray array = VirgilKeyPair::extractPublicKey(prvtKey, pass);
        result = [NSData dataWithBytes:array.data() length:array.size()];
    }
    catch (std::exception &ex) {
        result = nil;
    }

    return result;
}

+ (NSData *__nullable)encryptPrivateKey:(NSData *)privateKey privateKeyPassword:(NSString *)password {
    if (!privateKey || !password) {
        return nil;
    }

    NSData *encryptedPrivateKey = nil;
    try {
        const VirgilByteArray &prvtKey = [VSCByteArrayUtils convertVirgilByteArrayFromData:privateKey];
        const VirgilByteArray &pass = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
        VirgilByteArray array = VirgilKeyPair::encryptPrivateKey(prvtKey, pass);
        encryptedPrivateKey = [NSData dataWithBytes:array.data() length:array.size()];
    }
    catch (...) {
        encryptedPrivateKey = nil;
    }

    return encryptedPrivateKey;
}

+ (NSData *__nullable)decryptPrivateKey:(NSData *)privateKey privateKeyPassword:(NSString *)password {
    if (!privateKey || !password) {
        return nil;
    }

    NSData *decryptedPrivateKey = nil;
    try {
        const VirgilByteArray &prvtKey = [VSCByteArrayUtils convertVirgilByteArrayFromData:privateKey];
        const VirgilByteArray &pass = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
        VirgilByteArray array = VirgilKeyPair::decryptPrivateKey(prvtKey, pass);
        decryptedPrivateKey = [NSData dataWithBytes:array.data() length:array.size()];
    }
    catch (...) {
        decryptedPrivateKey = nil;
    }

    return decryptedPrivateKey;
}

+ (BOOL)isEncryptedPrivateKey:(NSData *)keyData {
    if (keyData.length == 0) {
        return NO;
    }

    BOOL isEncrypted;
    try {
        const VirgilByteArray &data = [VSCByteArrayUtils convertVirgilByteArrayFromData:keyData];
        isEncrypted = VirgilKeyPair::isPrivateKeyEncrypted(data);
    }
    catch (...) {
        isEncrypted = false;
    }

    return isEncrypted;

}

+ (BOOL)isPrivateKey:(NSData *)keyData matchesPassword:(NSString *)password {
    if (keyData.length == 0 || password.length == 0) {
        return NO;
    }

    BOOL isMatches;
    try {
        const VirgilByteArray &data = [VSCByteArrayUtils convertVirgilByteArrayFromData:keyData];
        const VirgilByteArray &pwd = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
        isMatches = VirgilKeyPair::checkPrivateKeyPassword(data, pwd);
    }
    catch (...) {
        isMatches = false;
    }

    return isMatches;

}

+ (BOOL)isPublicKey:(NSData *)publicKeyData matchesPrivateKey:(NSData *)privateKeyData withPassword:(NSString *)password {
    if (publicKeyData.length == 0 || privateKeyData.length == 0) {
        return NO;
    }

    BOOL isMatches;
    try {
        const VirgilByteArray &pubKeyData = [VSCByteArrayUtils convertVirgilByteArrayFromData:publicKeyData];
        const VirgilByteArray &privKeyData = [VSCByteArrayUtils convertVirgilByteArrayFromData:privateKeyData];
        if (password.length == 0) {
            isMatches = VirgilKeyPair::isKeyPairMatch(pubKeyData, privKeyData);
        } else {
            const VirgilByteArray &pwd = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
            isMatches = VirgilKeyPair::isKeyPairMatch(pubKeyData, privKeyData, pwd);
        }
    }
    catch (...) {
        isMatches = false;
    }

    return isMatches;
}

+ (NSData *__nullable)resetPassword:(NSString *)password toPassword:(NSString *)newPassword forPrivateKey:(NSData *)keyData error:(NSError **)error {
    if (password.length == 0 || newPassword.length == 0 || keyData.length == 0) {
        // Can't reset password.
        if (error) {
            *error = [NSError errorWithDomain:kVSCKeyPairErrorDomain code:-1000 userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString(@"Impossible to reset password: Required parameter is missing.", @"Reset password error.")}];
        }
        return nil;
    }

    NSData *pkeyData = nil;
    try {
        const VirgilByteArray &vbaPwd = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
        const VirgilByteArray &vbaNewPwd = [VSCByteArrayUtils convertVirgilByteArrayFromString:newPassword];
        const VirgilByteArray &pKey = [VSCByteArrayUtils convertVirgilByteArrayFromData:keyData];

        VirgilByteArray pNewKey = VirgilKeyPair::resetPrivateKeyPassword(pKey, vbaPwd, vbaNewPwd);
        pkeyData = [NSData dataWithBytes:pNewKey.data() length:pNewKey.size()];
        if (error) {
            *error = nil;
        }
    }
    catch (std::exception &ex) {
        if (error) {
            NSString *description = [[NSString alloc] initWithCString:ex.what() encoding:NSUTF8StringEncoding];
            if (description.length == 0) {
                description = @"Unknown exception during password reset.";
            }
            *error = [NSError errorWithDomain:kVSCKeyPairErrorDomain code:-1001 userInfo:@{NSLocalizedDescriptionKey: description}];
        }
        pkeyData = nil;
    }
    catch (...) {
        if (error) {
            *error = [NSError errorWithDomain:kVSCKeyPairErrorDomain code:-1002 userInfo:@{NSLocalizedDescriptionKey: @"Unknown exception during password reset."}];
        }
        pkeyData = nil;
    }

    return pkeyData;
}

+ (NSData *)publicKeyToPEM:(NSData *)publicKey {
    if (!publicKey) {
        return [NSData data];
    }

    NSData *pemData = nil;

    try {
        const VirgilByteArray &pubKey = [VSCByteArrayUtils convertVirgilByteArrayFromData:publicKey];
        const VirgilByteArray &array = VirgilKeyPair::publicKeyToPEM(pubKey);
        pemData = [NSData dataWithBytes:array.data() length:array.size()];
    }
    catch (...) {
        pemData = [NSData data];
    }

    return pemData;
}

+ (NSData *)publicKeyToDER:(NSData *)publicKey {
    if (!publicKey) {
        return [NSData data];
    }

    NSData *result = nil;

    try {
        const VirgilByteArray &key = [VSCByteArrayUtils convertVirgilByteArrayFromData:publicKey];
        const VirgilByteArray &der = VirgilKeyPair::publicKeyToDER(key);
        result = [NSData dataWithBytes:der.data() length:der.size()];
    }
    catch (...) {
        result = [NSData data];
    }

    return result;
}

+ (NSData *)privateKeyToPEM:(NSData *)privateKey {
    return [VSCKeyPair privateKeyToPEM:privateKey privateKeyPassword:nil];
}

+ (NSData *)privateKeyToDER:(NSData *)privateKey {
    return [VSCKeyPair privateKeyToDER:privateKey privateKeyPassword:nil];
}

+ (NSData *)privateKeyToPEM:(NSData *)privateKey privateKeyPassword:(NSString *)password {
    if (!privateKey) {
        return [NSData data];
    }

    NSData *result = nil;

    try {
        const VirgilByteArray &pass = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
        const VirgilByteArray &key = [VSCByteArrayUtils convertVirgilByteArrayFromData:privateKey];
        const VirgilByteArray &pem = VirgilKeyPair::privateKeyToPEM(key, pass);

        result = [NSData dataWithBytes:pem.data() length:pem.size()];
    }
    catch (...) {
        result = [NSData data];
    }

    return result;
}

+ (NSData *)privateKeyToDER:(NSData *)privateKey privateKeyPassword:(NSString *)password {
    if (!privateKey) {
        return [NSData data];
    }

    NSData *result = nil;

    try {
        const VirgilByteArray &pass = [VSCByteArrayUtils convertVirgilByteArrayFromString:password];
        const VirgilByteArray &key = [VSCByteArrayUtils convertVirgilByteArrayFromData:privateKey];
        const VirgilByteArray &der = VirgilKeyPair::privateKeyToDER(key, pass);

        result = [NSData dataWithBytes:der.data() length:der.size()];
    }
    catch (...) {
        result = [NSData data];
    }

    return result;
}

@end
