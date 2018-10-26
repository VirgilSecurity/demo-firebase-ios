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

/// Declares error types and codes
///
/// - duplicateSigner: tried to add verifier credentials from same signer
@objc(VSSWhitelistError) public enum WhitelistError: Int, Error {
    case duplicateSigner = 1
}

/// Class representing collection of verifiers
/// - Important: Card should contain signature from AT LEAST one verifier from collection of verifiers
@objc(VSSWhitelist) public class Whitelist: NSObject {
    /// Array of verifier credentials
    /// - Note: Card must be signed by AT LEAST one of them
    @objc public let verifiersCredentials: [VerifierCredentials]

    /// Initializer
    ///
    /// - Parameter verifiersCredentials: array of verifier credentials
    /// - Throws: corresponding `WhitelistError`
    @objc public init(verifiersCredentials: [VerifierCredentials]) throws {
        self.verifiersCredentials = verifiersCredentials

        let signers = self.verifiersCredentials.map { $0.signer }

        for signer in signers {
            guard signers.filter({ $0 == signer }).count < 2 else {
                throw WhitelistError.duplicateSigner
            }
        }

        super.init()
    }
}
