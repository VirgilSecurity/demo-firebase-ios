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

/// Declares client error types and codes
///
/// - constructingUrl: constructing url of endpoint failed
@objc(VSSCardClientError) public enum CardClientError: Int, Error {
    case constructingUrl = 1
}

/// Class representing operations with Virgil Cards service
@objc(VSSCardClient) open class CardClient: BaseClient {
    // swiftlint:disable force_unwrapping
    /// Default URL for service
    @objc public static let defaultURL = URL(string: "https://api.virgilsecurity.com")!
    // swiftlint:enable force_unwrapping

    /// Initializes a new `CardClient` instance
    ///
    /// - Parameters:
    ///   - serviceUrl: URL of service client will use
    ///   - connection: custom HTTPConnection
    public override init(serviceUrl: URL = CardClient.defaultURL, connection: HttpConnectionProtocol) {
        super.init(serviceUrl: serviceUrl, connection: connection)
    }

    /// Initializes a new `CardClient` instance
    @objc convenience public init() {
        self.init(serviceUrl: CardClient.defaultURL)
    }

    /// Initializes a new `CardClient` instance
    ///
    /// - Parameter serviceUrl: URL of service client will use
    @objc convenience public init(serviceUrl: URL) {
        self.init(serviceUrl: serviceUrl, connection: HttpConnection())
    }

    /// Handles error from Card Service
    ///
    /// - Parameters:
    ///   - statusCode: http status code
    ///   - body: response body
    /// - Returns: Corresponding error
    override open func handleError(statusCode: Int, body: Data?) -> Error {
        if let body = body, let rawServiceError = try? JSONDecoder().decode(RawServiceError.self, from: body) {
            return ServiceError(httpStatusCode: statusCode, rawServiceError: rawServiceError)
        }

        return super.handleError(statusCode: statusCode, body: body)
    }
}
