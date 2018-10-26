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

/// Class representing entry in cloud
@objc(VSKCloudEntry) public final class CloudEntry: NSObject, Codable {
    /// Entry name
    @objc public let name: String

    /// Entry data
    @objc public let data: Data

    /// Entry creation date
    @objc public let creationDate: Date

    /// Entry modification date
    @objc public let modificationDate: Date

    /// Entry meta
    @objc public let meta: [String: String]?

    /// Init
    ///
    /// - Parameters:
    ///   - name: name
    ///   - data: data
    ///   - creationDate: creationDate
    ///   - modificationDate: modificationDate
    ///   - meta: meta
    @objc public init(name: String, data: Data, creationDate: Date, modificationDate: Date, meta: [String: String]?) {
        self.name = name
        self.data = data
        self.creationDate = creationDate
        self.modificationDate = modificationDate
        self.meta = meta

        super.init()
    }

    /// CodingKeys
    ///
    /// - name: name
    /// - data: data
    /// - creationDate: creationDate
    /// - modificationDate: modificationDate
    /// - meta: meta
    public enum CodingKeys: String, CodingKey {
        case name
        case data
        case creationDate = "creation_date"
        case modificationDate = "modification_date"
        case meta
    }
}

// MARK: - Equatable implementation
public extension CloudEntry {
    static func == (lhs: CloudEntry, rhs: CloudEntry) -> Bool {
        return lhs.name == rhs.name
            && lhs.data == rhs.data
            && lhs.creationDate == rhs.creationDate
            && lhs.modificationDate == rhs.modificationDate
            && lhs.meta == rhs.meta
    }
}
