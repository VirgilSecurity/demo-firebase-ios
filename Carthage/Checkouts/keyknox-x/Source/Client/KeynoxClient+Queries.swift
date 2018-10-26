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
import VirgilSDK

// MARK: - Queries
extension KeyknoxClient: KeyknoxClientProtocol {
    /// Header key for blob hash
    @objc public static let virgilKeyknoxHashKey = "Virgil-Keyknox-Hash"

    /// Header key for previous blob hash
    @objc public static let virgilKeyknoxPreviousHashKey = "Virgil-Keyknox-Previous-Hash"

    /// Push value to Keyknox service
    ///
    /// - Parameters:
    ///   - meta: meta data
    ///   - value: encrypted blob
    ///   - previousHash: hash of previous blob
    ///   - token: auth token
    /// - Returns: EncryptedKeyknoxValue
    /// - Throws: KeyknoxClientError.constructingUrl if URL init failed
    ///           KeyknoxClientError.invalidPreviousHashHeader if extracting previousHash from response header failed
    ///           Rethrows from ServiceRequest, Connection, BaseClient
    public func pushValue(meta: Data, value: Data, previousHash: Data? = nil,
                          token: String) throws -> EncryptedKeyknoxValue {
        guard let url = URL(string: "keyknox/v1", relativeTo: self.serviceUrl) else {
            throw KeyknoxClientError.constructingUrl
        }

        let params = [
            "meta": meta.base64EncodedString(),
            "value": value.base64EncodedString()
        ]

        let headers: [String: String]
        if let previousHash = previousHash {
            headers = [KeyknoxClient.virgilKeyknoxPreviousHashKey: previousHash.base64EncodedString()]
        }
        else {
            headers = [:]
        }

        let request = try ServiceRequest(url: url, method: .put, accessToken: token, params: params, headers: headers)

        let response = try self.connection.send(request)

        let keyknoxData: KeyknoxData = try self.processResponse(response)

        let keyknoxHash = try self.extractKeyknoxHash(response: response)

        return EncryptedKeyknoxValue(keyknoxData: keyknoxData, keyknoxHash: keyknoxHash)
    }

    /// Pulls values from Keyknox service
    ///
    /// - Parameter token: auth token
    /// - Returns: EncryptedKeyknoxValue
    /// - Throws: KeyknoxClientError.constructingUrl if URL init failed
    ///           KeyknoxClientError.invalidPreviousHashHeader if extracting previousHash from response header failed
    ///           Rethrows from ServiceRequest, Connection, BaseClient
    public func pullValue(token: String) throws -> EncryptedKeyknoxValue {
        guard let url = URL(string: "keyknox/v1", relativeTo: self.serviceUrl) else {
            throw KeyknoxClientError.constructingUrl
        }

        let request = try ServiceRequest(url: url, method: .get, accessToken: token)

        let response = try self.connection.send(request)

        let keyknoxData: KeyknoxData = try self.processResponse(response)

        let keyknoxHash = try self.extractKeyknoxHash(response: response)

        return EncryptedKeyknoxValue(keyknoxData: keyknoxData, keyknoxHash: keyknoxHash)
    }

    /// Resets Keyknox value (makes it empty). Also increments version
    ///
    /// - Parameter token: auth token
    /// - Returns: DecryptedKeyknoxValue
    /// - Throws: KeyknoxClientError.constructingUrl if URL init failed
    ///           KeyknoxClientError.invalidPreviousHashHeader if extracting previousHash from response header failed
    ///           Rethrows from ServiceRequest, Connection, BaseClient
    @objc open func resetValue(token: String) throws -> DecryptedKeyknoxValue {
        guard let url = URL(string: "keyknox/v1/reset", relativeTo: self.serviceUrl) else {
            throw KeyknoxClientError.constructingUrl
        }

        let request = try ServiceRequest(url: url, method: .post, accessToken: token)

        let response = try self.connection.send(request)

        let keyknoxData: KeyknoxData = try self.processResponse(response)

        let keyknoxHash = try self.extractKeyknoxHash(response: response)

        return DecryptedKeyknoxValue(keyknoxData: keyknoxData, keyknoxHash: keyknoxHash)
    }

    private func extractKeyknoxHash(response: Response) throws -> Data {
        let responseHeaders = response.response.allHeaderFields as NSDictionary

        guard let keyknoxHashStr = responseHeaders[KeyknoxClient.virgilKeyknoxHashKey] as? String,
            let keyknoxHash = Data(base64Encoded: keyknoxHashStr) else {
                throw KeyknoxClientError.invalidPreviousHashHeader
        }

        return keyknoxHash
    }
}
