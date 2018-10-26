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

/// Declares client error types and codes
///
/// - constructingUrl: constructing url of endpoint failed
@objc(VSYPythiaCryptoError) public enum PythiaCryptoError: Int, Error {
    case passwordIsNotUTF8 = 1
    case errorWhileGeneratingKeyPair = 2
}

/// Implementation of PythiaCryptoProtocol using Virgil crypto library
@objc(VSYPythiaCrypto) open class PythiaCrypto: NSObject, PythiaCryptoProtocol {
    /// VirgilPythia
    @objc public let virgilPythia = VirgilPythia()
    /// Virgil Crypto
    @objc public let virgilCrypto = VirgilCrypto()

    /// Blinds password.
    ///
    /// Turns password into a pseudo-random string.
    /// This step is necessary to prevent 3rd-parties from knowledge of end user's password.
    ///
    /// - Parameter password: end user's password.
    /// - Returns: BlindResult with blinded password and blinding secret
    /// - Throws: PythiaCryptoError.passwordIsNotUTF8 is password cannot be converted to UTF8
    ///           Rethrows from VirgilPythia.blind
    @objc open func blind(password: String) throws -> BlindResult {
        guard let passwordData = password.data(using: .utf8) else {
            throw PythiaCryptoError.passwordIsNotUTF8
        }

        let blindResult = try self.virgilPythia.blind(password: passwordData)

        return BlindResult(blindedPassword: blindResult.blindedPassword, blindingSecret: blindResult.blindingSecret)
    }

    /// Deblinds transformed password value using previously returned blinding_secret from blind operation.
    ///
    /// - Parameters:
    ///   - transformedPassword: GT transformed password from transform operation
    ///   - blindingSecret: BN value that was generated during blind operation
    /// - Returns: GT deblinded transformed password
    /// - Throws: Rethrows from VirgilPythia.deblind
    @objc open func deblind(transformedPassword: Data, blindingSecret: Data) throws -> Data {
        return try self.virgilPythia.deblind(transformedPassword: transformedPassword, blindingSecret: blindingSecret)
    }

    /// Generates key pair of given type using random seed
    ///
    /// - Parameters:
    ///   - type: type of key pair
    ///   - seed: random seed
    /// - Returns: generated key pair
    /// - Throws: PythiaCryptoError.errorWhileGeneratingKeyPair if key generation failed
    ///           Rethrows from VirgilCrypto.wrapKeyPair
    @objc open func generateKeyPair(ofType type: VSCKeyType, fromSeed seed: Data) throws -> VirgilKeyPair {
        guard let keyPair = KeyPair(keyPairType: type, keyMaterial: seed, password: nil) else {
            throw PythiaCryptoError.errorWhileGeneratingKeyPair
        }

        return try self.virgilCrypto.wrapKeyPair(privateKey: keyPair.privateKey(), publicKey: keyPair.publicKey())
    }
}
