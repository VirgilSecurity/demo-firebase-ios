//
//  Connection.swift
//  VirgilSDK
//
//  Created by Oleksandr Deundiak on 9/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

public protocol HTTPResponse {
    var statusCode: Int { get }
    var response: HTTPURLResponse { get }
    var body: Data? { get }
}

public protocol HTTPRequest {
    func getNativeRequest() throws -> URLRequest
}

public protocol HTTPConnection: class {
    func send(_ request: HTTPRequest) throws -> HTTPResponse
}
