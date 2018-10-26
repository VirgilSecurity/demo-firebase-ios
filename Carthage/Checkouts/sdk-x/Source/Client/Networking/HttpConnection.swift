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
/// - noUrlInRequest: Provided URLRequest doesn't have url
/// - wrongResponseType: Response is not of HTTPURLResponse type
@objc(VSSServiceConnectionError) public enum ServiceConnectionError: Int, Error {
    case noUrlInRequest = 1
    case wrongResponseType = 2
}

/// Simple HttpConnection implementation
open class HttpConnection: HttpConnectionProtocol {
    /// Default number of maximum concurrent operations
    public static let defaulMaxConcurrentOperationCount = 10
    /// Queue for URLSession
    private let queue: OperationQueue
    /// Url session used to create network tasks
    private let session: URLSession

    /// Creates HttpConnection with maximum number of concurrent operations
    /// = HttpConnection.defaulMaxConcurrentOperationCount
    public init(maxConcurrentOperationCount: Int = HttpConnection.defaulMaxConcurrentOperationCount) {
        self.queue = OperationQueue()
        self.queue.maxConcurrentOperationCount = maxConcurrentOperationCount

        let config = URLSessionConfiguration.ephemeral
        self.session = URLSession(configuration: config, delegate: nil, delegateQueue: self.queue)
    }

    /// Sends Request and returns Response over http
    ///
    /// - Parameter request: Request to send
    /// - Returns: Obtained response
    /// - Throws: ServiceConnectionError.noUrlInRequest if provided URLRequest doesn't have url
    ///           ServiceConnectionError.wrongResponseType if response is not of HTTPURLResponse type
    public func send(_ request: Request) throws -> Response {
        let nativeRequest = request.getNativeRequest()

        guard let url = nativeRequest.url else {
            throw ServiceConnectionError.noUrlInRequest
        }

        let className = String(describing: type(of: self))

        Log.debug("\(className): request method: \(nativeRequest.httpMethod ?? "")")
        Log.debug("\(className): request url: \(url.absoluteString)")
        if let data = nativeRequest.httpBody, !data.isEmpty, let str = String(data: data, encoding: .utf8) {
            Log.debug("\(className): request body: \(str)")
        }
        Log.debug("\(className): request headers: \(nativeRequest.allHTTPHeaderFields ?? [:])")
        if let cookies = HTTPCookieStorage.shared.cookies(for: url) {
            for cookie in cookies {
                Log.debug("*******COOKIE: \(cookie.name): \(cookie.value)")
            }
        }

        let semaphore = DispatchSemaphore(value: 0)

        var dataT: Data?
        var responseT: URLResponse?
        var errorT: Error?
        let task = self.session.dataTask(with: nativeRequest) { dataR, responseR, errorR in
            dataT = dataR
            responseT = responseR
            errorT = errorR

            semaphore.signal()
        }
        task.resume()

        semaphore.wait()

        if let error = errorT {
            throw error
        }

        guard let response = responseT as? HTTPURLResponse else {
            throw ServiceConnectionError.wrongResponseType
        }

        Log.debug("\(className): response URL: \(response.url?.absoluteString ?? "")")
        Log.debug("\(className): response HTTP status code: \(response.statusCode)")
        Log.debug("\(className): response headers: \(response.allHeaderFields as AnyObject)")

        if let data = dataT, !data.isEmpty, let str = String(data: data, encoding: .utf8) {
            Log.debug("\(className): response body: \(str)")
        }

        return Response(statusCode: response.statusCode, response: response, body: dataT)
    }

    deinit {
        self.session.invalidateAndCancel()
        self.queue.cancelAllOperations()
    }
}
