//
//  NotificationService.swift
//  Notification Extention
//
//  Created by Yevhen Pyvovarov on 11/5/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import UserNotifications
import VirgilCryptoApiImpl
import VirgilSDK

class NotificationService: UNNotificationServiceExtension {

    var contentHandler: ((UNNotificationContent) -> Void)?
    var bestAttemptContent: UNMutableNotificationContent?

    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        self.contentHandler = contentHandler
        bestAttemptContent = (request.content.mutableCopy() as? UNMutableNotificationContent)

        guard let keychainStorageParams = try? KeychainStorageParams.makeKeychainStorageParams() else {
            return
        }
        let keychainStorage = KeychainStorage(storageParams: keychainStorageParams)
        let crypto = VirgilCrypto()

        if let bestAttemptContent = bestAttemptContent,
            let keyEntry = try? keychainStorage.retrieveEntry(withName: "FIXME"),
            let privateKey = try? crypto.importPrivateKey(from: keyEntry.data),
            let data = Data(base64Encoded: bestAttemptContent.body),
            let decryptedData = try? crypto.decrypt(data, with: privateKey),
            let decryptedString = String(data: decryptedData, encoding: .utf8) {
                bestAttemptContent.body = decryptedString
                contentHandler(bestAttemptContent)
        }
    }
    
    override func serviceExtensionTimeWillExpire() {
        // Called just before the extension will be terminated by the system.
        // Use this as an opportunity to deliver your "best attempt" at modified content, otherwise the original push payload will be used.
        if let contentHandler = contentHandler, let bestAttemptContent =  bestAttemptContent {
            contentHandler(bestAttemptContent)
        }
    }

}
