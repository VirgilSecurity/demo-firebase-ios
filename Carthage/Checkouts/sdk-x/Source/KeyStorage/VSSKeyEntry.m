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

#import "VSSKeyEntry.h"

NSString *const kVSSKeyEntryName = @"name";
NSString *const kVSSKeyEntryValue = @"value";
NSString *const kVSSKeyEntryMeta = @"meta";

@interface VSSKeyEntry () <NSCoding>

- (instancetype __nonnull)initWithName:(NSString * __nonnull)name value:(NSData * __nonnull)value meta:(NSDictionary<NSString *, NSString *> * __nullable)meta;

@end

@implementation VSSKeyEntry

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self) {
        _name = [coder decodeObjectOfClass:[NSString class] forKey:kVSSKeyEntryName];
        _value = [coder decodeObjectOfClass:[NSData class] forKey:kVSSKeyEntryValue];
        _meta = [coder decodeObjectOfClass:[NSDictionary class] forKey:kVSSKeyEntryMeta];
    }
    
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:self.name forKey:kVSSKeyEntryName];
    [coder encodeObject:self.value forKey:kVSSKeyEntryValue];
    [coder encodeObject:self.meta forKey:kVSSKeyEntryMeta];
}

- (instancetype)initWithName:(NSString *)name value:(NSData *)value meta:(NSDictionary<NSString *, NSString *> *)meta {
    self = [super init];
    if (self) {
        _name = [name copy];
        _value = [value copy];
        _meta = [meta copy];
    }
    
    return self;
}

+ (VSSKeyEntry *)keyEntryWithName:(NSString *)name value:(NSData *)value meta:(NSDictionary<NSString *, NSString *> *)meta {
    return [[VSSKeyEntry alloc] initWithName:name value:value meta:meta];
}

+ (VSSKeyEntry * __nonnull)keyEntryWithName:(NSString * __nonnull)name value:(NSData * __nonnull)value {
    return [VSSKeyEntry keyEntryWithName:name value:value meta:nil];
}

@end
