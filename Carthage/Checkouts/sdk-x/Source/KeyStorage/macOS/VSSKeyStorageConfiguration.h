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

/**
 Class used to initialize default VSSKeyStorage implementation.
 See VSSKeyStorage.
 */
NS_SWIFT_NAME(KeyStorageConfiguration)
@interface VSSKeyStorageConfiguration: NSObject <NSCopying>

/**
 Default VSSKeyStorage values with applicationName = NSBundle.mainBundle.bundleIdentifier, accessibility = kSecAttrAccessibleWhenUnlocked, accessGroup = nil
 
 @return allocated and initialized VSSKeyStorageConfiguration instance
 */
+ (VSSKeyStorageConfiguration * __nonnull)keyStorageConfigurationWithDefaultValues;

/**
 Factory method which allocates and initalizes VSSKeyStorageConfiguration instance.
 
 @param accessibility see https://developer.apple.com/reference/security/keychain_services/keychain_item_accessibility_constants
 @param trustedApplications needed to set up access. No need to add executing application itself. See https://developer.apple.com/reference/security/secaccess
 @return allocated and initialized VSSKeyStorageConfiguration instance
 */
+ (VSSKeyStorageConfiguration * __nonnull)keyStorageConfigurationWithAccessibility:(NSString * __nullable)accessibility trustedApplications:(NSArray<NSString *> * __nullable)trustedApplications;

/**
 Trusted application to set up access. No need to add executing application itself. See https://developer.apple.com/reference/security/secaccess
 */
@property (nonatomic, readonly) NSArray<NSString *> * __nonnull trustedApplications;

/**
 Accessibility. See https://developer.apple.com/reference/security/keychain_services/keychain_item_accessibility_constants
 */
@property (nonatomic, readonly, copy) NSString * __nonnull accessibility;

/**
 ApplicationName.
 */
@property (nonatomic, readonly, copy) NSString * __nonnull applicationName;

@end
