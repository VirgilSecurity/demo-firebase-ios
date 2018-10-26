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
import VirgilCryptoApiImpl
import VirgilCrypto

/// Crypto operations needed for Pythia BrainKey
@objc(VSYPythiaCryptoProtocol) public protocol PythiaCryptoProtocol: class {
    /// Blinds password.
    ///
    /// Turns password into a pseudo-random string.
    /// This step is necessary to prevent 3rd-parties from knowledge of end user's password.
    ///
    /// - Parameter password: end user's password.
    /// - Returns: BlindResult with blinded password and blinding secret
    /// - Throws: Depends on implementation
    @objc func blind(password: String) throws -> BlindResult

    /// Deblinds transformed password value using previously returned blinding_secret from blind operation.
    ///
    /// - Parameters:
    ///   - transformedPassword: GT transformed password from transform operation
    ///   - blindingSecret: BN value that was generated during blind operation
    /// - Returns: GT deblinded transformed password
    /// - Throws: Depends on implementation
    @objc func deblind(transformedPassword: Data, blindingSecret: Data) throws -> Data

    /// Generates key pair of given type using random seed
    ///
    /// - Parameters:
    ///   - type: type of key pair
    ///   - seed: random seed
    /// - Returns: generated key pair
    /// - Throws: Depends on implementation
    @objc func generateKeyPair(ofType type: VSCKeyType, fromSeed seed: Data) throws -> VirgilKeyPair
}
