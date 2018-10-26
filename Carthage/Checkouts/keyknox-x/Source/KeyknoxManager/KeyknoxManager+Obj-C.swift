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
import VirgilCryptoAPI

// MARK: - Obj-C extension
extension KeyknoxManager {
    /// Signs then encrypts and pushed value to Keyknox service
    ///
    /// - Parameters:
    ///   - value: value to push
    ///   - previousHash: previous value hash
    ///   - completion: Completion handler
    @objc open func pushValue(_ value: Data, previousHash: Data?,
                              completion: @escaping (DecryptedKeyknoxValue?, Error?) -> Void) {
        self.pushValue(value, previousHash: previousHash).start(completion: completion)
    }

    /// Pull value, decrypt then verify signature
    ///
    /// - Parameter completion: Completion handler
    @objc open func pullValue(completion: @escaping (DecryptedKeyknoxValue?, Error?) -> Void) {
        self.pullValue().start(completion: completion)
    }

    /// Resets Keyknox value (makes it empty). Also increments version
    ///
    /// - Returns: Completion handler
    @objc open func resetValue(completion: @escaping(DecryptedKeyknoxValue?, Error?) -> Void) {
        self.resetValue().start(completion: completion)
    }

    /// Updates public keys for ecnryption and signature verification
    /// and private key for decryption and signature generation
    ///
    /// - Parameters:
    ///   - newPublicKeys: New public keys that will be used for encryption and signature verification
    ///   - newPrivateKey: New private key that will be used for decryption and signature generation
    ///   - completion: Completion handler
    @objc open func updateRecipients(newPublicKeys: [PublicKey]? = nil,
                                     newPrivateKey: PrivateKey? = nil,
                                     completion: @escaping (DecryptedKeyknoxValue?, Error?) -> Void) {
        self.updateRecipients(newPublicKeys: newPublicKeys, newPrivateKey: newPrivateKey).start(completion: completion)
    }

    /// Updates public keys for ecnryption and signature verification
    /// and private key for decryption and signature generation
    ///
    /// - Parameters:
    ///   - value: Current Keyknox value
    ///   - previousHash: Previous Keyknox value hash
    ///   - newPublicKeys: New public keys that will be used for encryption and signature verification
    ///   - newPrivateKey: New private key that will be used for decryption and signature generation
    ///   - completion: Completion handler
    @objc open func updateRecipients(value: Data, previousHash: Data,
                                     newPublicKeys: [PublicKey]? = nil,
                                     newPrivateKey: PrivateKey? = nil,
                                     completion: @escaping (DecryptedKeyknoxValue?, Error?) -> Void) {
        self.updateRecipients(value: value, previousHash: previousHash,
                              newPublicKeys: newPublicKeys,
                              newPrivateKey: newPrivateKey).start(completion: completion)
    }
}
