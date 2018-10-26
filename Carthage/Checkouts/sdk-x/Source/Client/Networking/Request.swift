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

/// Declares error types and codes
///
/// - urlRequestIsIncompleteOrInvalid: Provided URLRequest is incomplete or invalid
@objc(VSSRequestError) public enum RequestError: Int, Error {
    case urlRequestIsIncompleteOrInvalid = 1
}

/// Represents Http request
open class Request {
    /// Url of request
    public let url: URL
    /// Http method
    public let method: Method
    /// Request headers
    public let headers: [String: String]?
    /// Request body
    public let body: Data?

    /// Default request timeout
    public static let defaultTimeout: TimeInterval = 45

    /// Http methods
    ///
    /// - get
    /// - post
    /// - put
    /// - delete
    public enum Method: String {
        case get    = "GET"
        case post   = "POST"
        case put    = "PUT"
        case delete = "DELETE"
    }

    /// Initializer
    ///
    /// - Parameters:
    ///   - url: Request url
    ///   - method: Request method
    ///   - headers: Request headers
    ///   - body: Request body
    public init(url: URL, method: Method, headers: [String: String]? = nil, body: Data? = nil) {
        self.url = url
        self.method = method
        self.headers = headers
        self.body = body
    }

    /// Initializer from URLRequest
    ///
    /// - Parameter urlRequest: URLRequest
    /// - Throws: RequestError.urlRequestIsIncompleteOrInvalid if URLRequest is incomplete or invalid
    public init(urlRequest: URLRequest) throws {
        guard let url = urlRequest.url,
            let methodStr = urlRequest.httpMethod,
            let method = Method(rawValue: methodStr) else {
                throw RequestError.urlRequestIsIncompleteOrInvalid
        }

        self.url = url
        self.method = method
        self.headers = urlRequest.allHTTPHeaderFields
        self.body = urlRequest.httpBody
    }

    /// Returns URLRequest created from this Request
    ///
    /// - Returns: URLRequest
    public func getNativeRequest() -> URLRequest {
        var request = URLRequest(url: self.url)

        request.timeoutInterval = Request.defaultTimeout
        request.httpMethod = self.method.rawValue
        request.allHTTPHeaderFields = self.headers
        request.httpBody = self.body

        return request
    }
}
