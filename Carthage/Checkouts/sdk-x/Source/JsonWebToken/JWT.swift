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
/// - incorrectNumberOfJwtComponents: Number of JWT components doesn't equal 3
/// - utf8StrIsInvalid: Invalid UTF8 string to sign
@objc(VSSJwtError) public enum JwtError: Int, Error {
    case incorrectNumberOfJwtComponents = 1
    case utf8StrIsInvalid = 2
}

/// Class implementing `AccessToken` in terms of Virgil JWT
@objc(VSSJwt) public final class Jwt: NSObject, AccessToken {
    /// Represents JWT Header content
    @objc public let headerContent: JwtHeaderContent
    /// Represents JWT Body content
    @objc public let bodyContent: JwtBodyContent
    /// Represents JWT Signature content
    @objc public let signatureContent: JwtSignatureContent

    /// Initializes `Jwt` with provided header, body and signature content
    ///
    /// - Parameters:
    ///   - headerContent: header of `Jwt`
    ///   - bodyContent: body of `Jwt`
    ///   - signatureContent: signature of `Jwt`
    @objc public init(headerContent: JwtHeaderContent, bodyContent: JwtBodyContent,
                      signatureContent: JwtSignatureContent) throws {
        self.headerContent = headerContent
        self.bodyContent = bodyContent
        self.signatureContent = signatureContent

        super.init()
    }

    /// Initializes `Jwt` from its string representation
    ///
    /// - Parameter stringRepresentation: must be equal to
    ///                                   base64UrlEncode(JWT Header) + "." + base64UrlEncode(JWT Body)
    ///                                   + "." + base64UrlEncode(Jwt Signature)
    @objc public init(stringRepresentation: String) throws {
        let array = stringRepresentation.components(separatedBy: ".")

        guard array.count == 3 else {
            throw JwtError.incorrectNumberOfJwtComponents
        }

        let headerBase64Url = array[0]
        let bodyBase64Url = array[1]
        let signatureBase64Url = array[2]

        self.headerContent = try JwtHeaderContent(base64UrlEncoded: headerBase64Url)
        self.bodyContent = try JwtBodyContent(base64UrlEncoded: bodyBase64Url)
        self.signatureContent = try JwtSignatureContent(base64UrlEncoded: signatureBase64Url)

        super.init()
    }

    /// Returns JWT data that should be signed
    ///
    /// - Returns: JWT data that should be signed
    /// - Throws: JwtError.utf8StrIsInvalid if utf8 string is invalid
    @objc public func dataToSign() throws -> Data {
        return try Jwt.dataToSign(headerContent: self.headerContent, bodyContent: self.bodyContent)
    }

    /// Returns JWT data that should be signed
    ///
    /// - Parameters:
    ///   - headerContent: JWT header
    ///   - bodyContent: JWT body
    /// - Returns: JWT data that should be signed
    /// - Throws: JwtError.utf8StrIsInvalid if utf8 string is invalid
    @objc public static func dataToSign(headerContent: JwtHeaderContent, bodyContent: JwtBodyContent) throws -> Data {
        let dataStr = "\(headerContent.stringRepresentation).\(bodyContent.stringRepresentation)"
        guard let data = dataStr.data(using: .utf8) else {
            throw JwtError.utf8StrIsInvalid
        }

        return data
    }

    /// Provides string representation of token
    ///
    /// - Returns: string representation of token
    @objc public func stringRepresentation() -> String {
        let headerStr = self.headerContent.stringRepresentation
        let bodyStr = self.bodyContent.stringRepresentation
        let signatureStr = self.signatureContent.stringRepresentation

        return "\(headerStr).\(bodyStr).\(signatureStr)"
    }

    /// Extracts identity
    ///
    /// - Returns: identity
    @objc public func identity() -> String {
        return self.bodyContent.identity
    }

    /// Returns whether or not token is expired
    ///
    /// - Parameter date: current date
    /// - Returns: true if token is expired, false otherwise
    @objc public func isExpired(date: Date = Date()) -> Bool {
        return date >= self.bodyContent.expiresAt
    }
}
