//
//  VirgilHelper.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/13/18.
//  Copyright © 2018 Eugen Pivovarov. All rights reserved.
//


import Foundation
import VirgilSDK
import VirgilCryptoApiImpl

class VirgilHelper {
    static let sharedInstance = VirgilHelper()
    let crypto: VirgilCrypto
    let keyStorage: PrivateKeyStorage
    let queue: DispatchQueue
    let connection: ServiceConnection

    private var publicKey: VirgilPublicKey?
    private var privateKey: VirgilPrivateKey?
    private var channelCard: Card?

    private init() {
        self.crypto = VirgilCrypto()
        self.keyStorage = PrivateKeyStorage(privateKeyExporter: VirgilPrivateKeyExporter())
        self.queue = DispatchQueue(label: "virgil-help-queue")
        self.connection = ServiceConnection()
    }

    func makeHash(from string: String) -> String? {
        guard let data = string.data(using: .utf8) else {
            Log.error("string to data failed")
            return nil
        }
        return self.crypto.computeHash(for: data, using: .SHA256).hexEncodedString()
    }
}
