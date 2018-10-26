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

// MARK: - PythiaClientProtocol implementation
extension PythiaClient: PythiaClientProtocol {
    /// Generates seed using given blinded password and brainkey id
    ///
    /// - Parameters:
    ///   - blindedPassword: blinded password
    ///   - brainKeyId: brainkey id
    ///   - token: authorization token
    /// - Returns: Generated seed
    /// - Throws: PythiaClientError.constructingUrl if url is not valid
    ///           Rethrows from HttpConnectionProtocol.send, PythiaClient.proccessResponse
    ///           See PythiaClient.handleError
    @objc public func generateSeed(blindedPassword: Data, brainKeyId: String?, token: String) throws -> Data {
        guard let url = URL(string: "pythia/v1/brainkey", relativeTo: self.serviceUrl) else {
            throw PythiaClientError.constructingUrl
        }

        var params = [
            "blinded_password": blindedPassword.base64EncodedString()
        ]

        if let brainKeyId = brainKeyId {
            params["brainkey_id"] = brainKeyId
        }

        let request = try ServiceRequest(url: url, method: .post, accessToken: token, params: params)

        let response = try self.connection.send(request)

        class SeedResponse: Codable {
            let seed: Data
        }

        let seedResponse: SeedResponse = try self.processResponse(response)

        return seedResponse.seed
    }
}
