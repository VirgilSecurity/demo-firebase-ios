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

// MARK: - Queries
extension CardClient: CardClientProtocol {
    /// HTTP header key for getCard response that marks outdated cards
    @objc public static let xVirgilIsSuperseededKey = "x-virgil-is-superseeded"
    /// HTTP header value for xVirgilIsSuperseededKey key for getCard response that marks outdated cards
    @objc public static let xVirgilIsSuperseededTrue = "true"

    /// Returns `GetCardResponse` with `RawSignedModel` of card from the Virgil Cards Service with given ID, if exists
    ///
    /// - Parameters:
    ///   - cardId: String with unique Virgil Card identifier
    ///   - token: String with `Access Token`
    /// - Returns: `GetCardResponse` if card found
    /// - Throws: CardClientError.constructingUrl, if url initialization failed
    ///           CardServiceError, if service returned correctly-formed error json
    ///           NSError with CardClient.serviceErrorDomain error domain,
    ///               http status code as error code, and description string if present in http body
    ///           Rethrows from ServiceRequest, HttpConnectionProtocol, JsonDecoder, BaseClient
    @objc open func getCard(withId cardId: String, token: String) throws -> GetCardResponse {
        guard let url = URL(string: "card/v5/\(cardId)", relativeTo: self.serviceUrl) else {
            throw CardClientError.constructingUrl
        }

        let request = try ServiceRequest(url: url, method: .get, accessToken: token)

        let response = try self.connection.send(request)

        let isOutdated: Bool
        // Swift dictionaries doesn't support case-insensitive keys, NSDictionary does
        let allHeaders = (response.response.allHeaderFields as NSDictionary)
        if let xVirgilIsSuperseeded = allHeaders[CardClient.xVirgilIsSuperseededKey] as? String,
            xVirgilIsSuperseeded == CardClient.xVirgilIsSuperseededTrue {
                isOutdated = true
        }
        else {
            isOutdated = false
        }

        return GetCardResponse(rawCard: try self.processResponse(response), isOutdated: isOutdated)
    }

    /// Creates Virgil Card instance on the Virgil Cards Service
    /// Also makes the Card accessible for search/get queries from other users
    /// `RawSignedModel` should contain appropriate signatures
    ///
    /// - Parameters:
    ///   - model: Signed `RawSignedModel`
    ///   - token: String with `Access Token`
    /// - Returns: `RawSignedModel` of created card
    /// - Throws: CardClientError.constructingUrl, if url initialization failed
    ///           CardServiceError, if service returned correctly-formed error json
    ///           NSError with CardClient.serviceErrorDomain error domain,
    ///               http status code as error code, and description string if present in http body
    ///           Rethrows from ServiceRequest, HttpConnectionProtocol, JsonDecoder, BaseClient
    @objc open func publishCard(model: RawSignedModel, token: String) throws -> RawSignedModel {
        guard let url = URL(string: "card/v5", relativeTo: self.serviceUrl) else {
            throw CardClientError.constructingUrl
        }

        let request = try ServiceRequest(url: url, method: .post, accessToken: token, params: model)

        let response = try self.connection.send(request)

        return try self.processResponse(response)
    }

    /// Performs search of Virgil Cards using given identity on the Virgil Cards Service
    ///
    /// - Parameters:
    ///   - identity: Identity of cards to search
    ///   - token: String with `Access Token`
    /// - Returns: Array with `RawSignedModel`s of matched Virgil Cards
    /// - Throws: CardClientError.constructingUrl, if url initialization failed
    ///           CardServiceError, if service returned correctly-formed error json
    ///           NSError with CardClient.serviceErrorDomain error domain,
    ///               http status code as error code, and description string if present in http body
    ///           Rethrows from ServiceRequest, HttpConnectionProtocol, JsonDecoder, BaseClient
    @objc open func searchCards(identity: String, token: String) throws -> [RawSignedModel] {
        guard let url = URL(string: "card/v5/actions/search", relativeTo: self.serviceUrl) else {
            throw CardClientError.constructingUrl
        }

        let request = try ServiceRequest(url: url, method: .post, accessToken: token, params: ["identity": identity])

        let response = try self.connection.send(request)

        return try self.processResponse(response)
    }
}
