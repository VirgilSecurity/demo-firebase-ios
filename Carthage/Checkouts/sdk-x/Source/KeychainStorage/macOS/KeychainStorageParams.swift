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
import Security

/// Class responsible for KeychainStorage setup
@objc(VSSKeychainStorageParams) public final class KeychainStorageParams: NSObject {
    /// Application name
    @objc public let appName: String

    /// Trusted applications
    @objc public let trustedApplications: [String]

    /// Init
    ///
    /// - Parameters:
    ///   - appName: Application name
    ///   - trustedApplications: List of trusted applications
    @objc public init(appName: String, trustedApplications: [String]) {
        self.appName = appName
        self.trustedApplications = trustedApplications

        super.init()
    }

    /// Fabric method
    ///
    /// - Parameters:
    ///   - trustedApplications: List of trusted applications
    /// - Returns: Initialized KeychainStorageParams
    /// - Throws: KeychainStorageError
    @objc static public func makeKeychainStorageParams(trustedApplications: [String] = [])
        throws -> KeychainStorageParams {
        guard let appName = Bundle.main.bundleIdentifier else {
            throw KeychainStorageError(errCode: .invalidAppBundle)
        }

        return KeychainStorageParams(appName: appName, trustedApplications: [])
    }
}
