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

#define STRINGIZE(x) #x
#define STRINGIZE2(x) STRINGIZE(x)

#import "VTETestsConst.h"

@implementation VTETestsConst

- (instancetype)init
{
    self = [super init];
    if (self) {
        NSBundle *bundle = [NSBundle bundleForClass:self.class];
        NSURL *configFileUrl = [bundle URLForResource:@"TestConfig" withExtension:@"plist"];
        NSDictionary *config = [NSDictionary dictionaryWithContentsOfURL:configFileUrl];
        _config = config;
    }

    return self;
}

- (NSString *)apiPublicKeyId {
    NSString *appToken = self.config[@"ApiPublicKeyId"];

    return appToken;
}

- (NSString *)apiPrivateKeyBase64 {
    NSString *appPrivateKey = self.config[@"ApiPrivateKey"];

    return appPrivateKey;
}

- (NSString *)applicationId {
    NSString *appId = self.config[@"AppId"];

    return appId;
}

- (NSURL *)serviceURL {
    NSString *cardsUrl = self.config[@"ServiceURL"];
    if (cardsUrl != nil)
        return [[NSURL alloc] initWithString:cardsUrl];

    return nil;
}

- (NSString *)servicePublicKey {
    NSString *servicePublicKey = self.config[@"ServicePublicKey"];

    return servicePublicKey;
}

@end
