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
import VSCCrypto

// swiftlint:disable force_unwrapping

/// Declares error types and codes
///
/// - underlyingCryptoError: Crypto library returned error
@objc(VSCVirgilPythiaError) public enum VirgilPythiaError: Int, Error {
    case underlyingCryptoError = 0
}

/// Class with Pythia-related crypto operations
@objc(VSCVirgilPythia) public class VirgilPythia: NSObject {
    private static func bindBufForRead(buf: UnsafeMutablePointer<pythia_buf_t>, data: Data) {
        data.withUnsafeBytes { (pointer: UnsafePointer<UInt8>) -> Void in
            let mutablePointer = UnsafeMutablePointer(mutating: pointer)
            pythia_buf_setup(buf, mutablePointer, 0, data.count)
        }
    }

    private static func bindBufForWrite(buf: UnsafeMutablePointer<pythia_buf_t>, size: Int) -> Data {
        var data = Data(count: size)

        data.withUnsafeMutableBytes { (mutablePointer: UnsafeMutablePointer<UInt8>) -> Void in
            pythia_buf_setup(buf, mutablePointer, size, 0)
        }

        return data
    }

    private static func trim(data: inout Data, from buf: UnsafeMutablePointer<pythia_buf_t>) {
        data.removeLast(data.count - buf.pointee.len)
    }

    /// Blinds password.
    ///
    /// Turns password into a pseudo-random string.
    /// This step is necessary to prevent 3rd-parties from knowledge of end user's password.
    ///
    /// - Parameter password: end user's password.
    /// - Returns: BlindResult with blinded password and blinding secret
    /// - Throws: VirgilPythiaError.underlyingCryptoError
    @objc public func blind(password: Data) throws -> BlindResult {
        let passwordBuf = pythia_buf_new()!
        let blindedPasswordBuf = pythia_buf_new()!
        let blindingSecretBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(passwordBuf)
            pythia_buf_free(blindedPasswordBuf)
            pythia_buf_free(blindingSecretBuf)
        }

        VirgilPythia.bindBufForRead(buf: passwordBuf, data: password)

        var blindedPassword = VirgilPythia.bindBufForWrite(buf: blindedPasswordBuf, size: PYTHIA_G1_BUF_SIZE)
        var blindingSecret = VirgilPythia.bindBufForWrite(buf: blindingSecretBuf, size: PYTHIA_BN_BUF_SIZE)

        if (virgil_pythia_blind(passwordBuf, blindedPasswordBuf, blindingSecretBuf) != 0) {
            throw VirgilPythiaError.underlyingCryptoError
        }

        VirgilPythia.trim(data: &blindedPassword, from: blindedPasswordBuf)
        VirgilPythia.trim(data: &blindingSecret, from: blindingSecretBuf)

        return BlindResult(blindedPassword: blindedPassword, blindingSecret: blindingSecret)
    }

    /// Deblinds transformed password value using previously returned blinding_secret from blind operation.
    ///
    /// - Parameters:
    ///   - transformedPassword: GT transformed password from transform operation
    ///   - blindingSecret: BN value that was generated during blind operation
    /// - Returns: GT deblinded transformed password
    /// - Throws: VirgilPythiaError.underlyingCryptoError
    @objc public func deblind(transformedPassword: Data, blindingSecret: Data) throws -> Data {
        let transformedPasswordBuf = pythia_buf_new()!
        let blindingSecretBuf = pythia_buf_new()!
        let deblindedPasswordBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(transformedPasswordBuf)
            pythia_buf_free(blindingSecretBuf)
            pythia_buf_free(deblindedPasswordBuf)
        }

        VirgilPythia.bindBufForRead(buf: transformedPasswordBuf, data: transformedPassword)
        VirgilPythia.bindBufForRead(buf: blindingSecretBuf, data: blindingSecret)

        var deblindedPassword = VirgilPythia.bindBufForWrite(buf: deblindedPasswordBuf, size: PYTHIA_GT_BUF_SIZE)

        if (virgil_pythia_deblind(transformedPasswordBuf, blindingSecretBuf, deblindedPasswordBuf) != 0) {
            throw VirgilPythiaError.underlyingCryptoError
        }

        VirgilPythia.trim(data: &deblindedPassword, from: deblindedPasswordBuf)

        return deblindedPassword
    }

    internal func computeTransformationKey(transformationKeyId: Data,
                                           pythiaSecret: Data,
                                           pythiaScopeSecret: Data) throws -> (Data, Data) {
        let transformationKeyIdBuf = pythia_buf_new()!
        let pythiaSecretBuf = pythia_buf_new()!
        let pythiaScopeSecretBuf = pythia_buf_new()!
        let transformationPrivateKeyBuf = pythia_buf_new()!
        let transformationPublicKeyBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(transformationKeyIdBuf)
            pythia_buf_free(pythiaSecretBuf)
            pythia_buf_free(pythiaScopeSecretBuf)
            pythia_buf_free(transformationPrivateKeyBuf)
            pythia_buf_free(transformationPublicKeyBuf)
        }

        VirgilPythia.bindBufForRead(buf: transformationKeyIdBuf, data: transformationKeyId)
        VirgilPythia.bindBufForRead(buf: pythiaSecretBuf, data: pythiaSecret)
        VirgilPythia.bindBufForRead(buf: pythiaScopeSecretBuf, data: pythiaScopeSecret)

        var transformationPrivateKey = VirgilPythia.bindBufForWrite(buf: transformationPrivateKeyBuf,
                                                                    size: PYTHIA_BN_BUF_SIZE)
        var transformationPublicKey = VirgilPythia.bindBufForWrite(buf: transformationPublicKeyBuf,
                                                                   size: PYTHIA_G1_BUF_SIZE)

        if (virgil_pythia_compute_transformation_key_pair(transformationKeyIdBuf,
                                                          pythiaSecretBuf,
                                                          pythiaScopeSecretBuf,
                                                          transformationPrivateKeyBuf,
                                                          transformationPublicKeyBuf) != 0) {
            throw VirgilPythiaError.underlyingCryptoError
        }

        VirgilPythia.trim(data: &transformationPrivateKey, from: transformationPrivateKeyBuf)
        VirgilPythia.trim(data: &transformationPublicKey, from: transformationPublicKeyBuf)

        return (transformationPrivateKey, transformationPublicKey)
    }

    internal func transform(blindedPassword: Data, tweak: Data, transformationPrivateKey: Data) throws -> (Data, Data) {
        let blindedPasswordBuf = pythia_buf_new()!
        let tweakBuf = pythia_buf_new()!
        let transformationPrivateKeyBuf = pythia_buf_new()!
        let transformedPasswordBuf = pythia_buf_new()!
        let transformedTweakBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(blindedPasswordBuf)
            pythia_buf_free(tweakBuf)
            pythia_buf_free(transformationPrivateKeyBuf)
            pythia_buf_free(transformedPasswordBuf)
            pythia_buf_free(transformedTweakBuf)
        }

        VirgilPythia.bindBufForRead(buf: blindedPasswordBuf, data: blindedPassword)
        VirgilPythia.bindBufForRead(buf: tweakBuf, data: tweak)
        VirgilPythia.bindBufForRead(buf: transformationPrivateKeyBuf, data: transformationPrivateKey)

        var transformedPassword = VirgilPythia.bindBufForWrite(buf: transformedPasswordBuf,
                                                               size: PYTHIA_GT_BUF_SIZE)
        var transformedTweak = VirgilPythia.bindBufForWrite(buf: transformedTweakBuf,
                                                            size: PYTHIA_G2_BUF_SIZE)

        if (virgil_pythia_transform(blindedPasswordBuf, tweakBuf,
                                    transformationPrivateKeyBuf,
                                    transformedPasswordBuf,
                                    transformedTweakBuf) != 0) {
            throw VirgilPythiaError.underlyingCryptoError
        }

        VirgilPythia.trim(data: &transformedPassword, from: transformedPasswordBuf)
        VirgilPythia.trim(data: &transformedTweak, from: transformedTweakBuf)

        return (transformedPassword, transformedTweak)
    }

    internal func prove(transformedPassword: Data, blindedPassword: Data,
                        transformedTweak: Data, transformationPrivateKey: Data,
                        transformationPublicKey: Data) throws -> (Data, Data) {
        let transformedPasswordBuf = pythia_buf_new()!
        let blindedPasswordBuf = pythia_buf_new()!
        let transformedTweakBuf = pythia_buf_new()!
        let transformationPrivateKeyBuf = pythia_buf_new()!
        let transformationPublicKeyBuf = pythia_buf_new()!
        let proofValueCBuf = pythia_buf_new()!
        let proofValueUBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(transformedPasswordBuf)
            pythia_buf_free(blindedPasswordBuf)
            pythia_buf_free(transformedTweakBuf)
            pythia_buf_free(transformationPrivateKeyBuf)
            pythia_buf_free(transformationPublicKeyBuf)
            pythia_buf_free(proofValueCBuf)
            pythia_buf_free(proofValueUBuf)
        }

        VirgilPythia.bindBufForRead(buf: transformedPasswordBuf, data: transformedPassword)
        VirgilPythia.bindBufForRead(buf: blindedPasswordBuf, data: blindedPassword)
        VirgilPythia.bindBufForRead(buf: transformedTweakBuf, data: transformedTweak)
        VirgilPythia.bindBufForRead(buf: transformationPrivateKeyBuf, data: transformationPrivateKey)
        VirgilPythia.bindBufForRead(buf: transformationPublicKeyBuf, data: transformationPublicKey)

        var proofValueC = VirgilPythia.bindBufForWrite(buf: proofValueCBuf, size: PYTHIA_BN_BUF_SIZE)
        var proofValueU = VirgilPythia.bindBufForWrite(buf: proofValueUBuf, size: PYTHIA_BN_BUF_SIZE)

        if (virgil_pythia_prove(transformedPasswordBuf, blindedPasswordBuf,
                                transformedTweakBuf, transformationPrivateKeyBuf,
                                transformationPublicKeyBuf,
                                proofValueCBuf, proofValueUBuf) != 0) {
            throw VirgilPythiaError.underlyingCryptoError
        }

        VirgilPythia.trim(data: &proofValueC, from: proofValueCBuf)
        VirgilPythia.trim(data: &proofValueU, from: proofValueUBuf)

        return (proofValueC, proofValueU)
    }

    internal func verify(transformedPassword: Data, blindedPassword: Data, tweak: Data,
                         transformationPublicKey: Data,
                         proofValueC: Data, proofValueU: Data) -> Bool {
        let transformedPasswordBuf = pythia_buf_new()!
        let blindedPasswordBuf = pythia_buf_new()!
        let tweakBuf = pythia_buf_new()!
        let transformationPublicKeyBuf = pythia_buf_new()!
        let proofValueCBuf = pythia_buf_new()!
        let proofValueUBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(transformedPasswordBuf)
            pythia_buf_free(blindedPasswordBuf)
            pythia_buf_free(tweakBuf)
            pythia_buf_free(transformationPublicKeyBuf)
            pythia_buf_free(proofValueCBuf)
            pythia_buf_free(proofValueUBuf)
        }

        VirgilPythia.bindBufForRead(buf: transformedPasswordBuf, data: transformedPassword)
        VirgilPythia.bindBufForRead(buf: blindedPasswordBuf, data: blindedPassword)
        VirgilPythia.bindBufForRead(buf: tweakBuf, data: tweak)
        VirgilPythia.bindBufForRead(buf: transformationPublicKeyBuf, data: transformationPublicKey)
        VirgilPythia.bindBufForRead(buf: proofValueCBuf, data: proofValueC)
        VirgilPythia.bindBufForRead(buf: proofValueUBuf, data: proofValueU)

        var verified = Int32()

        if (virgil_pythia_verify(transformedPasswordBuf, blindedPasswordBuf,
                                 tweakBuf, transformationPublicKeyBuf,
                                 proofValueCBuf, proofValueUBuf,
                                 &verified) != 0) {
            return false
        }

        return verified != 0
    }
}
