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
/// - invalidGetRequestParameters: GET request parameters are not [String: String] and cannot be encoded
/// - urlComponentsConvertingFailed: Error building url from components during GET request
/// - getQueryWithDecodableIsNotSupported: GET query with Encodable body is not supported
/// - duplicateHeadersKey: Passed headers dictionary contains forbidden http header keys
@objc(VSSServiceRequestError) public enum ServiceRequestError: Int, Error {
    case invalidGetRequestParameters = 1
    case urlComponentsConvertingFailed = 2
    case getQueryWithDecodableIsNotSupported = 3
    case duplicateHeadersKey = 4
}

/// Class represents HTTP Request to Virgil Service
open class ServiceRequest: Request {
    /// HTTP header key for Authorization
    public static let accessTokenHeader = "Authorization"
    /// HTTP header prefix for Virgil JWT
    public static let accessTokenPrefix = "Virgil"

    /// Initializer
    ///
    /// - Parameters:
    ///   - url: Request url
    ///   - method: Request method
    ///   - accessToken: Access token
    ///   - params: Encodable request body
    ///   - headers: Http headers
    /// - Throws: ServiceRequestError.getQueryWithDecodableIsNotSupported, if GET query with params
    ///           Rethrows from JSONEncoder
    public init<T: Encodable>(url: URL, method: Method, accessToken: String, params: T? = nil,
                              headers: [String: String] = [:]) throws {
        let bodyData: Data?
        let newUrl: URL

        switch method {
        case .get:
            guard params == nil else {
                throw ServiceRequestError.getQueryWithDecodableIsNotSupported
            }

            bodyData = nil
            newUrl = url

        case .post, .put, .delete:
            if let bodyEncodable = params {
                bodyData = try JSONEncoder().encode(bodyEncodable)
            }
            else {
                bodyData = nil
            }

            newUrl = url
        }

        var requestHeaders = [ServiceRequest.accessTokenHeader: "\(ServiceRequest.accessTokenPrefix) \(accessToken)"]

        try requestHeaders.merge(headers) { _, _ in throw ServiceRequestError.duplicateHeadersKey }

        super.init(url: newUrl, method: method, headers: requestHeaders, body: bodyData)
    }

    /// Initializer
    ///
    /// - Parameters:
    ///   - url: Request url
    ///   - method: Request method
    ///   - accessToken: Access token
    ///   - params: JSON-encodable object
    ///   - headers: Http headers
    /// - Throws: ServiceRequestError.invalidGetRequestParameters,
    ///               if GET request is initialized and params are not [String: String]
    ///           ServiceRequestError.urlComponentsConvertingFailed,
    ///               if error occured while building url from components during GET request
    ///           Rethrows from JSONSerialization
    public init(url: URL, method: Method, accessToken: String, params: Any? = nil,
                headers: [String: String] = [:]) throws {
        let bodyData: Data?
        let newUrl: URL

        switch method {
        case .get:
            if let params = params {
                guard let params = params as? [String: String] else {
                    throw ServiceRequestError.invalidGetRequestParameters
                }

                var components = URLComponents(string: url.absoluteString)

                components?.queryItems = params.map { URLQueryItem(name: $0.key, value: $0.value) }

                guard let url = components?.url else {
                    throw ServiceRequestError.urlComponentsConvertingFailed
                }
                newUrl = url
            }
            else {
                newUrl = url
            }
            bodyData = nil

        case .post, .put, .delete:
            if let bodyJson = params {
                bodyData = try JSONSerialization.data(withJSONObject: bodyJson, options: [])
            }
            else {
                bodyData = nil
            }

            newUrl = url
        }

        var requestHeaders = [ServiceRequest.accessTokenHeader: "\(ServiceRequest.accessTokenPrefix) \(accessToken)"]

        try requestHeaders.merge(headers) { _, _ in throw ServiceRequestError.duplicateHeadersKey }

        super.init(url: newUrl, method: method, headers: requestHeaders, body: bodyData)
    }
}
