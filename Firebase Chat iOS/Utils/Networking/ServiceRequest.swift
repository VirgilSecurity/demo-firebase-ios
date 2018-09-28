//
//  ServiceRequest.swift
//  VirgilSDK
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

public class ServiceRequest: NSObject, HTTPRequest {
    let url: URL
    let method: Method
    let params: Any?
    let headers: [String: String]?

    @objc public static let DefaultTimeout: TimeInterval = 45

    enum RequestErrors: Int, Error {
        case selfParamsFailed
        case urlComponentsFailed
    }

    public enum Method: String {
        case get    = "GET"
        case post   = "POST"
        case put    = "PUT"
        case delete = "DELETE"
    }

    public init(url: URL, method: Method, headers: [String: String]? = nil, params: Any? = nil) throws {
        self.url = url
        self.method = method
        self.params = params
        self.headers = headers

        super.init()
    }

    public func getNativeRequest() throws -> URLRequest {
        var request: URLRequest
        switch self.method {
        case .get:
            let url: URL
            if let p = self.params {
                guard let p = p as? [String: String] else {
                    throw RequestErrors.selfParamsFailed
                }

                var components = URLComponents(string: self.url.absoluteString)
                components?.queryItems = p.map({
                    URLQueryItem(name: $0.key, value: $0.value)
                })

                guard let u = components?.url else {
                    throw RequestErrors.urlComponentsFailed
                }

                url = u
            } else {
                url = self.url
            }

            request = URLRequest(url: url)
            request.allHTTPHeaderFields = self.headers == nil ? [:] : self.headers

        case .post, .put, .delete:
            request = URLRequest(url: self.url)

            request.allHTTPHeaderFields = self.headers == nil ? [:] : self.headers

            let httpBody: Data?
            if let params = self.params {
                httpBody = try JSONSerialization.data(withJSONObject: params, options: [])
            } else {
                httpBody = nil
            }

            request.httpBody = httpBody
        }

        request.timeoutInterval = ServiceRequest.DefaultTimeout
        request.httpMethod = self.method.rawValue

        return request
    }
}

extension NSURLRequest: HTTPRequest {
    public func getNativeRequest() -> URLRequest {
        return self as URLRequest
    }
}
