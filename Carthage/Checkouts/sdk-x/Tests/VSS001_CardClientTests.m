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
#import <XCTest/XCTest.h>
@import VirgilSDK;
@import VirgilCryptoApiImpl;
@import VirgilCrypto;

#import "VSSTestsConst.h"
#import "VSSTestUtils.h"

@interface VSS001_CardClientTests : XCTestCase

@property (nonatomic) VSSTestsConst *consts;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VSMVirgilCardCrypto *cardCrypto;
@property (nonatomic) VSSTestUtils *utils;
@property (nonatomic) VSSCardClient *cardClient;
@property (nonatomic) VSSVirgilCardVerifier *verifier;

@end

@implementation VSS001_CardClientTests

- (void)setUp {
    [super setUp];
    self.continueAfterFailure = NO;
    
    self.consts = [[VSSTestsConst alloc] init];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:true];
    self.cardCrypto = [[VSMVirgilCardCrypto alloc] initWithVirgilCrypto:self.crypto];
    self.utils = [[VSSTestUtils alloc] initWithCrypto:self.crypto consts:self.consts];
    self.cardClient = self.consts.serviceURL == nil ? [[VSSCardClient alloc] init] : [[VSSCardClient alloc] initWithServiceUrl:self.consts.serviceURL];
    
    if (self.consts.servicePublicKey == nil) {
        self.verifier = [[VSSVirgilCardVerifier alloc] initWithCardCrypto:self.cardCrypto whitelists:@[]];
    }
    else {
        NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:self.consts.servicePublicKey options:0];
        VSSVerifierCredentials *creds = [[VSSVerifierCredentials alloc] initWithSigner:@"virgil" publicKey:publicKeyData];
        NSError *error;
        VSSWhitelist *whitelist = [[VSSWhitelist alloc] initWithVerifiersCredentials:@[creds] error:&error];
        XCTAssert(error == nil);
        self.verifier = [[VSSVirgilCardVerifier alloc] initWithCardCrypto:self.cardCrypto whitelists:@[whitelist]];
        self.verifier.verifyVirgilSignature = NO;
    }
}

- (void)tearDown {
    [super tearDown];
}

- (void)test001_CreateCard {
    NSError *error;
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    
    NSData *exportedPublicKey = [self.crypto exportPublicKey:keyPair.publicKey];
    NSString *identity = [[NSUUID alloc] init].UUIDString;

    VSSRawCardContent *content = [[VSSRawCardContent alloc] initWithIdentity:identity publicKey:exportedPublicKey previousCardId:nil version:@"5.0" createdAt:NSDate.date];
    
    NSData *snapshot = [content snapshotAndReturnError:nil];
    
    VSSRawSignedModel *rawCard = [[VSSRawSignedModel alloc] initWithContentSnapshot:snapshot];
    XCTAssert(error == nil && rawCard != nil);

    NSString *strToken = [self.utils getTokenStringWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSModelSigner *signer = [[VSSModelSigner alloc] initWithCardCrypto:self.cardCrypto];
    [signer selfSignWithModel:rawCard privateKey:keyPair.privateKey additionalData:nil error:&error];
    XCTAssert(error == nil);
    
    VSSRawSignedModel *responseRawCard = [self.cardClient publishCardWithModel:rawCard token:strToken error:&error];
    XCTAssert(error == nil && responseRawCard != nil);

    VSSCard *responseCard = [VSSCardManager parseCardFrom:responseRawCard cardCrypto:self.cardCrypto error:&error];
    XCTAssert(error == nil && responseCard != nil);
    VSSCard *card = [VSSCardManager parseCardFrom:rawCard cardCrypto:self.cardCrypto error:&error];
    XCTAssert(error == nil && card != nil && responseCard != nil);
    
    XCTAssert([self.utils isCardsEqualWithCard:responseCard and:card]);
    
    NSData *exportedPublicKeyCard = [self.crypto exportPublicKey:(VSMVirgilPublicKey *)card.publicKey];
    XCTAssert(error == nil);
    
    XCTAssert([exportedPublicKeyCard isEqualToData:exportedPublicKey]);
    
    XCTAssert([self.verifier verifyCard:responseCard]);
}

-(void)test002_GetCard {
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    NSString *strToken = [self.utils getTokenStringWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);

    NSData *exportedPublicKey = [self.crypto exportPublicKey:keyPair.publicKey];

    VSSRawCardContent *content = [[VSSRawCardContent alloc] initWithIdentity:identity publicKey:exportedPublicKey previousCardId:nil version:@"5.0" createdAt:NSDate.date];
    NSData *snapshot = [content snapshotAndReturnError:nil];

    VSSRawSignedModel *rawCard = [[VSSRawSignedModel alloc] initWithContentSnapshot:snapshot];
    
    VSSModelSigner *signer = [[VSSModelSigner alloc] initWithCardCrypto:self.cardCrypto];
    [signer selfSignWithModel:rawCard privateKey:keyPair.privateKey additionalData:nil error:&error];
    XCTAssert(error == nil);
    XCTAssert(rawCard.signatures.count == 1);
    
    VSSRawSignedModel *publishedRawCard = [self.cardClient publishCardWithModel:rawCard token:strToken error:&error];
    XCTAssert(error == nil);
    VSSCard *card = [VSSCardManager parseCardFrom:publishedRawCard cardCrypto:self.cardCrypto error:&error];
    XCTAssert(error == nil && card != nil);
    
    VSSGetCardResponse *getCardResponse = [self.cardClient getCardWithId:card.identifier token:strToken error:&error];
    
    VSSCard *foundCard = [VSSCardManager parseCardFrom:getCardResponse.rawCard cardCrypto:self.cardCrypto error:&error];
    XCTAssert(error == nil && foundCard != nil);

    VSSRawCardContent *responseContent = [[VSSRawCardContent alloc] initWithSnapshot:getCardResponse.rawCard.contentSnapshot error:nil];
    XCTAssert([self.utils isRawCardContentEqualWithContent:content and:responseContent]);

    XCTAssert([self.utils isCardsEqualWithCard:card and:foundCard]);

    XCTAssert([self.verifier verifyCard:foundCard]);
}

-(void)test003_SearchCards {
    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    NSString *strToken = [self.utils getTokenStringWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    
    NSData *exportedPublicKey = [self.crypto exportPublicKey:keyPair.publicKey];
    
    VSSRawCardContent *content = [[VSSRawCardContent alloc] initWithIdentity:identity publicKey:exportedPublicKey previousCardId:nil version:@"5.0" createdAt:NSDate.date];
    NSData *snapshot = [content snapshotAndReturnError:nil];
    VSSRawSignedModel *rawCard = [[VSSRawSignedModel alloc] initWithContentSnapshot:snapshot];
    
    VSSModelSigner *signer = [[VSSModelSigner alloc] initWithCardCrypto:self.cardCrypto];
    [signer selfSignWithModel:rawCard privateKey:keyPair.privateKey additionalData:nil error:&error];
    XCTAssert(error == nil);
    XCTAssert(rawCard.signatures.count == 1);
    
    VSSRawSignedModel *publishedRawCard = [self.cardClient publishCardWithModel:rawCard token:strToken error:&error];
    XCTAssert(error == nil);
    VSSCard *card = [VSSCardManager parseCardFrom:publishedRawCard cardCrypto:self.cardCrypto error:&error];
    XCTAssert(error == nil && card != nil);
    
    NSArray<VSSRawSignedModel *> *foundRawCards = [self.cardClient searchCardsWithIdentity:identity token:strToken error:&error];
    XCTAssert(foundRawCards.count != 0);
    VSSRawSignedModel *foundRawCard = foundRawCards.firstObject;
    
    VSSCard *foundCard = [VSSCardManager parseCardFrom:foundRawCard cardCrypto:self.cardCrypto error:&error];
    XCTAssert(error == nil && foundCard != nil);
    
    VSSRawCardContent *responseContent = [[VSSRawCardContent alloc] initWithSnapshot:foundRawCard.contentSnapshot error:nil];
    XCTAssert([self.utils isRawCardContentEqualWithContent:content and:responseContent]);
    
    XCTAssert([self.utils isCardsEqualWithCard:card and:foundCard]);
    
    XCTAssert([self.verifier verifyCard:foundCard]);
}

-(void)test004_STC_27 {
    NSError *error;
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    
    NSData *exportedPublicKey = [self.crypto exportPublicKey:keyPair.publicKey];
    NSString *identity = @"identity1";
    NSString *wrongIdentity = @"identity2";
    
    VSSRawCardContent *content = [[VSSRawCardContent alloc] initWithIdentity:identity publicKey:exportedPublicKey previousCardId:nil version:@"5.0" createdAt:NSDate.date];
    NSData *snapshot = [content snapshotAndReturnError:nil];
    
    VSSRawSignedModel *rawCard = [[VSSRawSignedModel alloc] initWithContentSnapshot:snapshot];
    XCTAssert(rawCard != nil);
    
    NSString *strToken = [self.utils getTokenStringWithIdentity:wrongIdentity error:&error];
    XCTAssert(error == nil);
    
    VSSModelSigner *signer = [[VSSModelSigner alloc] initWithCardCrypto:self.cardCrypto];
    [signer selfSignWithModel:rawCard privateKey:keyPair.privateKey additionalData:nil error:&error];
    XCTAssert(error == nil);
    
    VSSRawSignedModel *responseRawCard = [self.cardClient publishCardWithModel:rawCard token:strToken error:&error];

    XCTAssert(error != nil);
    XCTAssert(responseRawCard == nil);
}

-(void)test005_STC_25 {
    NSError *error;
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);
    
    NSData *exportedPublicKey = [self.crypto exportPublicKey:keyPair.publicKey];
    NSString *identity = @"identity1";
    
    VSSRawCardContent *content = [[VSSRawCardContent alloc] initWithIdentity:identity publicKey:exportedPublicKey previousCardId:nil version:@"5.0" createdAt:NSDate.date];
    NSData *snapshot = [content snapshotAndReturnError:nil];
    
    VSSRawSignedModel *rawCard = [[VSSRawSignedModel alloc] initWithContentSnapshot:snapshot ];
    XCTAssert(error == nil && rawCard != nil);
    
    NSString *strToken = [self.utils getTokenWithWrongPrivateKeyWithIdentity:identity error:&error];
    XCTAssert(error == nil);
    
    VSSModelSigner *signer = [[VSSModelSigner alloc] initWithCardCrypto:self.cardCrypto];
    [signer selfSignWithModel:rawCard privateKey:keyPair.privateKey additionalData:nil error:&error];
    XCTAssert(error == nil);
    
    VSSRawSignedModel *responseRawCard = [self.cardClient publishCardWithModel:rawCard token:strToken error:&error];
    XCTAssert(error != nil);
    XCTAssert(responseRawCard == nil);
    XCTAssert([[error localizedDescription] isEqualToString:@"JWT is invalid"]);
}

@end
