//
//  NotificationService.swift
//  Notification Extension
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

    let appName = "com.virgil.Virgil-Firebase-Sample"

    // We need Crypto instance for importing Private Key and decrypting
    let crypto = VirgilCrypto()

    enum NotificationKeys: String {
        case uid = "uid"
        case aps = "aps"
        case alert = "alert"
        case body = "body"
    }

    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        self.contentHandler = contentHandler
        bestAttemptContent = (request.content.mutableCopy() as? UNMutableNotificationContent)

        // Initializing KeyStorage with root application name. We need it to fetch shared key from root app
        guard let keychainStorageParams = try? KeychainStorageParams.makeKeychainStorageParams(appName: appName) else {
            return
        }
        let keychainStorage = KeychainStorage(storageParams: keychainStorageParams)

        // Make sure we got mutable content
        guard let bestAttemptContent = bestAttemptContent else {
            return
        }

        // Parsing userInfo of content for retreiving body and uid of recipient
        guard let aps = bestAttemptContent.userInfo[NotificationKeys.aps.rawValue] as? [String: Any],
            let alert = aps[NotificationKeys.alert.rawValue] as? [String: String],
            let body = alert[NotificationKeys.body.rawValue],
            let uid = bestAttemptContent.userInfo[NotificationKeys.uid.rawValue] as? String else {
                return
        }

        // Retrieve private key of recipient
        guard let keyEntry = try? keychainStorage.retrieveEntry(withName: uid),
            let privateKey = try? crypto.importPrivateKey(from: keyEntry.data) else {
                return
        }

        // Decrypting notification body
        guard let data = Data(base64Encoded: body),
            let decryptedData = try? crypto.decrypt(data, with: privateKey),
            let decryptedString = String(data: decryptedData, encoding: .utf8) else {
                return
        }

        // Changing body of notification from ciphertext to decrypted message
        bestAttemptContent.body = decryptedString
        contentHandler(bestAttemptContent)

        // Note: We got body from userInfo, not from bestAttemptContent.body directly in a reason of 1000 symbol restriction
    }
    
    override func serviceExtensionTimeWillExpire() {
        // Called just before the extension will be terminated by the system.
        // Use this as an opportunity to deliver your "best attempt" at modified content, otherwise the original push payload will be used.
        if let contentHandler = contentHandler, let bestAttemptContent =  bestAttemptContent {
            contentHandler(bestAttemptContent)
        }
    }

}
