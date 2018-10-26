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

// MARK: - Import export cards
extension CardManager {
    /// Imports and verifies Card from base64 encoded string
    ///
    /// - Parameter base64EncodedString: base64 encoded string with Card
    /// - Returns: imported and verified Card
    /// - Throws: CardManagerError.cardIsNotVerified, if Card verificaction has failed
    ///           Rethrows from RawSignedModel, JSONDecoder, CardCrypto
    @objc open func importCard(fromBase64Encoded base64EncodedString: String) throws -> Card {
        return try CardManager.importCard(fromBase64Encoded: base64EncodedString,
                                          cardCrypto: self.cardCrypto, cardVerifier: self.cardVerifier)
    }

    /// Imports and verifies Card from json Dictionary
    ///
    /// - Parameter json: json Dictionary
    /// - Returns: imported and verified Card
    /// - Throws: CardManagerError.cardIsNotVerified, if Card verificaction has failed
    ///           Rethrows from RawSignedModel, JSONDecoder, CardCrypto, JSONSerialization
    @objc open func importCard(fromJson json: Any) throws -> Card {
        return try CardManager.importCard(fromJson: json,
                                          cardCrypto: self.cardCrypto, cardVerifier: self.cardVerifier)
    }

    /// Imports and verifies Card from RawSignedModel
    ///
    /// - Parameter rawCard: RawSignedModel
    /// - Returns: imported and verified Card
    /// - Throws: CardManagerError.cardIsNotVerified, if Card verificaction has failed
    ///           Rethrows from RawSignedModel, JSONDecoder, CardCrypto, JSONSerialization
    @objc open func importCard(fromRawCard rawCard: RawSignedModel) throws -> Card {
        return try CardManager.importCard(fromRawCard: rawCard,
                                          cardCrypto: self.cardCrypto, cardVerifier: self.cardVerifier)
    }

    /// Exports Card as base64 encoded string
    ///
    /// - Parameter card: Card to be exported
    /// - Returns: base64 encoded string with Card
    /// - Throws: CardManagerError.cardIsNotVerified, if Card verificaction has failed
    ///           Rethrows from RawSignedModel, JSOEncoder, CardCrypto
    @objc open func exportCardAsBase64EncodedString(_ card: Card) throws -> String {
        return try CardManager.exportCardAsBase64EncodedString(card)
    }

    /// Exports Card as json Dictionary
    ///
    /// - Parameter card: Card to be exported
    /// - Returns: json Dictionary with Card
    /// - Throws: CardManagerError.cardIsNotVerified, if Card verificaction has failed
    ///           Rethrows from RawSignedModel, JSOEncoder, CardCrypto, JSONSerialization
    @objc open func exportCardAsJson(_ card: Card) throws -> Any {
        return try CardManager.exportCardAsJson(card)
    }
    /// Exports Card as RawSignedModel
    ///
    /// - Parameter card: Card to be exported
    /// - Returns: RawSignedModel representing Card
    /// - Throws: CardManagerError.cardIsNotVerified, if Card verificaction has failed
    ///           Rethrows from RawSignedModel, JSOEncoder, CardCrypto
    @objc open func exportCardAsRawCard(_ card: Card) throws -> RawSignedModel {
        return try CardManager.exportCardAsRawCard(card)
    }
}
