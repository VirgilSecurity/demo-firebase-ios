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

// MARK: - Extension with key back-up operations
extension EThree {
    /// Encrypts the user's private key using the user's password and backs up the encrypted
    /// private key to Virgil's cloud. This enables users to log in from other devices and have
    /// access to their private key to decrypt data.
    ///
    /// - Parameters:
    ///   - password: String with password
    ///   - completion: completion handler called with corresponding error
    /// - Important: Requires a bootstrapped user
    @objc public func backupPrivateKey(password: String, completion: @escaping (Error?) -> ()) {
        guard let identityKeyPair = self.localKeyManager.retrieveKeyPair(), identityKeyPair.isPublished else {
            completion(EThreeError.notBootstrapped)
            return
        }

        self.cloudKeyManager.store(key: identityKeyPair.privateKey, usingPassword: password) { completion($1) }
    }

    /// Changes the password on a backed-up private key.
    ///
    /// - Parameters:
    ///   - oldOne: old password
    ///   - newOne: new password
    ///   - completion: completion handler with corresponding error
    @objc public func changePrivateKeyPassword(from oldOne: String, to newOne: String,
                                               completion: @escaping (Error?) -> ()) {
        self.cloudKeyManager.changePassword(from: oldOne, to: newOne, completion: completion)
    }

    /// Deletes PrivateKey stored on Virgil's cloud. This will disable user to log in from other devices.
    ///
    /// - Parameters:
    ///   - password: String with password
    ///   - completion: completion handler called with corresponding error
    @objc public func resetPrivateKeyBackup(password: String, completion: @escaping (Error?) -> ()) {
        self.cloudKeyManager.delete(password: password, completion: completion)
    }
}
