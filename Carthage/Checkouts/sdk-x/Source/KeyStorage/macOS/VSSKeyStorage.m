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
#import <Security/Security.h>
#import "VSSKeyStorage.h"

NSString *const kVSSKeyStorageErrorDomain = @"VSSKeyStorageErrorDomain";

static NSString *privateKeyIdentifierFormat = @".%@.privatekey.%@\0";

SecAccessRef createAccess(NSString *accessLabel, NSArray<NSString *> *trustedApplicationsNames)
{
    OSStatus err;
    
    // Make an exception list of trusted applications; that is,
    // applications that are allowed to access the item without
    // requiring user confirmation:
    SecTrustedApplicationRef myself;
    
    NSMutableArray *trustedApplications = [[NSMutableArray alloc] initWithCapacity:trustedApplicationsNames.count + 1];
    
    //Create trusted application references; see SecTrustedApplications.h:
    err = SecTrustedApplicationCreateFromPath(NULL, &myself);
    
    if (err != noErr) return nil;
    
    [trustedApplications addObject:(__bridge_transfer id)myself];
    
    for (NSString *applicationName in trustedApplicationsNames) {
        SecTrustedApplicationRef someOther;
        err = SecTrustedApplicationCreateFromPath([applicationName UTF8String],
                                                    &someOther);
        
        [trustedApplications addObject:(__bridge_transfer id)someOther];
        
        if (err != noErr) return nil;
    }
    
    //Create an access object:
    SecAccessRef access=nil;
    err = SecAccessCreate((__bridge CFStringRef)accessLabel,
                                 (__bridge CFArrayRef)trustedApplications, &access);
    if (err) return nil;
    
    return access;
}

@implementation VSSKeyStorage

- (instancetype)init {
    VSSKeyStorageConfiguration *configuration = [VSSKeyStorageConfiguration keyStorageConfigurationWithDefaultValues];
    
    return [self initWithConfiguration:configuration];
}

- (instancetype)initWithConfiguration:(VSSKeyStorageConfiguration *)configuration {
    self = [super init];
    if (self) {
        _configuration = [configuration copy];
    }
    
    return self;
}

- (BOOL)storeKeyEntry:(VSSKeyEntry *)keyEntry error:(NSError **)errorPtr {
    NSData *keyEntryData = [NSKeyedArchiver archivedDataWithRootObject:keyEntry];
    
    NSMutableDictionary *query = [self baseExtendedKeychainQueryForName:keyEntry.name];
    
    if (query == nil) {
        if (errorPtr != nil) {
            *errorPtr = [[NSError alloc] initWithDomain:kVSSKeyStorageErrorDomain code:-1000 userInfo:@{ NSLocalizedDescriptionKey: @"Error storing VSSKeyEntry. Error during query dict creation. (Probably trusted applications list issue)" }];
        }
        return NO;
    }

    NSMutableDictionary *keySpecificData = [NSMutableDictionary dictionaryWithDictionary:
                                            @{
                                              (__bridge id)kSecValueData: keyEntryData,
                                              }];
    
    [query addEntriesFromDictionary:keySpecificData];
    
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, nil);
    
    if (status != errSecSuccess) {
        if (errorPtr != nil) {
            *errorPtr = [[NSError alloc] initWithDomain:kVSSKeyStorageErrorDomain code:status userInfo:@{ NSLocalizedDescriptionKey: @"Error while storing key in the keychain. See \"Security Error Codes\" (SecBase.h)." }];
        }
        
        return NO;
    }
    
    return YES;
}

- (BOOL)updateKeyEntry:(VSSKeyEntry *)keyEntry error:(NSError **)errorPtr {
    NSMutableDictionary *query = [self baseKeychainQueryForName:keyEntry.name];
    
    NSData *keyEntryData = [NSKeyedArchiver archivedDataWithRootObject:keyEntry];
    NSMutableDictionary *keySpecificData = [NSMutableDictionary dictionaryWithDictionary:
        @{
          (__bridge id)kSecValueData: keyEntryData,
          }];
    
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)keySpecificData);
    
    if (status != errSecSuccess) {
        if (errorPtr != nil) {
            *errorPtr = [[NSError alloc] initWithDomain:kVSSKeyStorageErrorDomain code:status userInfo:@{ NSLocalizedDescriptionKey: @"Error while updating key in the keychain. See \"Security Error Codes\" (SecBase.h)." }];
        }
        return NO;
    }
    
    return YES;
}

- (VSSKeyEntry *)loadKeyEntryWithName:(NSString *)name error:(NSError **)errorPtr {
    NSMutableDictionary *query = [self baseKeychainQueryForName:name];
    
    NSMutableDictionary *additional = [[NSMutableDictionary alloc] initWithDictionary:
       @{
         (__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue
         }];
    
    [query addEntriesFromDictionary:additional];
    
    CFDataRef outData = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&outData);
    
    if (status != errSecSuccess) {
        if (errorPtr != nil) {
            *errorPtr = [[NSError alloc] initWithDomain:kVSSKeyStorageErrorDomain code:status userInfo:@{ NSLocalizedDescriptionKey: @"Error while obtaining key from the keychain. See \"Security Error Codes\" (SecBase.h)." }];
        }
        return nil;
    }
    
    if (outData == nil) {
        if (errorPtr != nil) {
            *errorPtr = [[NSError alloc] initWithDomain:kVSSKeyStorageErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: @"No data found." }];
        }
        return nil;
    }
    
    NSData *keyData = (__bridge NSData*)outData;
    
    VSSKeyEntry *keyEntry = [NSKeyedUnarchiver unarchiveObjectWithData:keyData];
    
    if (keyEntry == nil) {
        if (errorPtr != nil) {
            *errorPtr = [[NSError alloc] initWithDomain:kVSSKeyStorageErrorDomain code:-1001 userInfo:@{ NSLocalizedDescriptionKey: @"Error while building VSSKeyEntry." }];
        }
        return nil;
    }
    
    return keyEntry;
}

- (BOOL)existsKeyEntryWithName:(NSString *)name {
    NSMutableDictionary *query = [self baseKeychainQueryForName:name];
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, nil);
    
    if (status != errSecSuccess) {
        return NO;
    }
    
    return YES;
}

- (BOOL)deleteKeyEntryWithName:(NSString *)name error:(NSError **)errorPtr {
    NSMutableDictionary *query = [self baseKeychainQueryForName:name];
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    
    if (status != errSecSuccess) {
        if (errorPtr != nil) {
            *errorPtr = [[NSError alloc] initWithDomain:kVSSKeyStorageErrorDomain code:status userInfo:@{ NSLocalizedDescriptionKey: @"Error while obtaining key from the keychain. See \"Security Error Codes\" (SecBase.h)." }];
        }
        return NO;
    }
    
    return YES;
}

- (NSMutableDictionary *)baseExtendedKeychainQueryForName:(NSString *)name {
    NSMutableDictionary *query = [self baseKeychainQueryForName:name];
    
    NSMutableDictionary *additional = [NSMutableDictionary dictionaryWithDictionary:
                                       @{
                                         (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock,
                                         (__bridge id)kSecAttrLabel: name,
                                         (__bridge id)kSecAttrSynchronizable: (__bridge id)kCFBooleanFalse,
                                         (__bridge id)kSecAttrIsInvisible: (__bridge id)kCFBooleanTrue,
                                         }];
    
    if (self.configuration.trustedApplications.count > 0) {
        SecAccessRef access = createAccess(name, self.configuration.trustedApplications);
        if (!access)
            return nil;
        
        [additional setObject:(__bridge id)access forKey:(__bridge id)kSecAttrAccess];
    }
    
    [query addEntriesFromDictionary:additional];
    
    return query;
}

- (NSMutableDictionary *)baseKeychainQueryForName:(NSString *)name {
    NSString *tag = [[NSString alloc] initWithFormat:privateKeyIdentifierFormat, self.configuration.applicationName, name];
    
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithDictionary:
                                  @{
                                    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                    (__bridge id)kSecAttrAccount: name,
                                    (__bridge id)kSecAttrService: tag,
                                    }];
    
    return query;
}

@end
