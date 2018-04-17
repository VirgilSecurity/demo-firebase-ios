//
//  ServiceResponse.swift
//  VirgilSDK
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

public class ServiceResponse: NSObject {
    public let statusCode: Int
    public let response: HTTPURLResponse
    public let body: Data?

    @objc public init(statusCode: Int, response: HTTPURLResponse, body: Data?) {
        self.statusCode = statusCode
        self.response = response
        self.body = body
    }
}

extension ServiceResponse: HTTPResponse { }
