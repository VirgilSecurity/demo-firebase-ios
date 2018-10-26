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

/// Aggregates common functions to use with JSONEncoder
public final class DateUtils {
    /// Converts date to timestamp
    ///
    /// - Parameter date: date
    /// - Returns: timestamp
    public static func dateToTimestamp(date: Date) -> Int64 {
        return Int64(date.timeIntervalSince1970)
    }

    /// Converts date to timestamp in milliseconds
    ///
    /// - Parameter date: date
    /// - Returns: timestamp in milliseconds
    public static func dateToMilliTimestamp(date: Date) -> Int64 {
        return Int64(date.timeIntervalSince1970 * 1000)
    }

    /// Creates date from tiemstamp
    ///
    /// - Parameter timestamp: timestamp
    /// - Returns: date
    public static func dateFromTimestamp(_ timestamp: Int64) -> Date {
        return Date(timeIntervalSince1970: TimeInterval(timestamp))
    }

    /// Creates date from timestamp in milliseconds
    ///
    /// - Parameter timestamp: timestamp in milliseconds
    /// - Returns: date
    public static func dateFromMilliTimestamp(_ timestamp: Int64) -> Date {
        return Date(timeIntervalSince1970: TimeInterval(timestamp) / 1000)
    }

    /// Decodes Date using Int timestamp
    ///
    /// - Parameter decoder: Decoder
    /// - Returns: Decoded Date
    /// - Throws: Rethrows from Decoder
    public static func timestampDateDecodingStrategy(decoder: Decoder) throws -> Date {
        let timestamp = try decoder.singleValueContainer().decode(Int64.self)

        return self.dateFromTimestamp(timestamp)
    }

    /// Encodes Date to Int timestamp
    ///
    /// - Parameters:
    ///   - date: Date to encode
    ///   - encoder: Encoder
    /// - Throws: Rethrows from Encoder
    public static func timestampDateEncodingStrategy(date: Date, encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.dateToTimestamp(date: date))
    }

    /// Decodes Date using Int64 timestamp in milliseconds
    ///
    /// - Parameter decoder: Decoder
    /// - Returns: Decoded Date
    /// - Throws: Rethrows from Decoder
    public static func timestampMilliDateDecodingStrategy(decoder: Decoder) throws -> Date {
        let timestamp = try decoder.singleValueContainer().decode(Int64.self)

        return self.dateFromMilliTimestamp(timestamp)
    }

    /// Encodes Date to Int64 timestamp in milliseconds
    ///
    /// - Parameters:
    ///   - date: Date to encode
    ///   - encoder: Encoder
    /// - Throws: Rethrows from Encoder
    public static func timestampMilliDateEncodingStrategy(date: Date, encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.dateToMilliTimestamp(date: date))
    }
}
