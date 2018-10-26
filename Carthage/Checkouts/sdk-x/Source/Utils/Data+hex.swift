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

// MARK: - Data extension for hex encoding and decoding
public extension Data {
    /// Encodes data in hex format
    ///
    /// - Returns: Hex-encoded string
    func hexEncodedString() -> String {
        return self
            .map({ String(format: "%02hhx", $0) })
            .joined()
    }

    /// Initializer
    ///
    /// - Parameter hex: Hex-encoded string
    init?(hexEncodedString hex: String) {
        let length = hex.lengthOfBytes(using: .ascii)

        guard length % 2 == 0 else {
            return nil
        }

        var data = Data()
        data.reserveCapacity(length / 2)

        var lowerBound = hex.startIndex

        while true {
            guard let upperBound = hex.index(lowerBound, offsetBy: 2, limitedBy: hex.endIndex) else {
                break
            }

            let substr = String(hex[Range(uncheckedBounds: (lowerBound, upperBound))])
            let res = strtol(substr, nil, 16)
            data.append(contentsOf: [UInt8(res)])

            lowerBound = upperBound
        }

        self = data
    }
}
