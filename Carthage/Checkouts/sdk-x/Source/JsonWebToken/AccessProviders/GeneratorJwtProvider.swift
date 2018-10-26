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

import Foundation

/// Implementation of AccessTokenProvider which provides generated JWTs
@objc(VSSGeneratorJwtProvider) open class GeneratorJwtProvider: NSObject, AccessTokenProvider {
    /// JwtGeneretor for generating new tokens
    @objc public let jwtGenerator: JwtGenerator
    /// Identity that will be used for generating token if tokenContext do not have it (e.g. for read operations)
    /// WARNING: Do not create cards with defaultIdentity
    @objc public let defaultIdentity: String
    /// Additional data, that will be present in token
    @objc public let additionalData: [String: String]?

    /// Initializer
    ///
    /// - Parameters:
    ///   - jwtGenerator: `JwtGenerator` instance for generating new tokens
    ///   - defaultIdentity: Identity that will be used for generating token
    ///                      if tokenContext do not have it (e.g. for read operations)
    ///                      WARNING: Do not create cards with defaultIdentity
    ///   - additionalData: Additional data, that will be present in token
    @objc public init(jwtGenerator: JwtGenerator, defaultIdentity: String, additionalData: [String: String]? = nil) {
        self.defaultIdentity = defaultIdentity
        self.additionalData = additionalData
        self.jwtGenerator = jwtGenerator

        super.init()
    }

    /// Provides new generated JWT
    ///
    /// - Parameters:
    ///   - tokenContext: `TokenContext`, provides context explaining why token is needed
    ///   - completion: completion closure, called with access token or corresponding error
    @objc public func getToken(with tokenContext: TokenContext, completion: @escaping (AccessToken?, Error?) -> Void) {
        do {
            let token = try self.jwtGenerator.generateToken(identity: tokenContext.identity ?? self.defaultIdentity,
                                                            additionalData: self.additionalData)
            completion(token, nil)
        } catch {
            completion(nil, error)
        }
    }
}
