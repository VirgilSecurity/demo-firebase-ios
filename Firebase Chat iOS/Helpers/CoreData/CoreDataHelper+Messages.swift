//
//  CoreDataHelper+Messages.swift
//  VirgilMessenger
//
//  Created by Eugen Pivovarov on 2/20/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation
import UIKit
import CoreData

extension CoreDataHelper {
    func createTextMessage(withBody body: String, isIncoming: Bool, date: Date) {
        guard let channel = self.currentChannel else {
            Log.error("Core Data: nil selected channel")
            return
        }

        self.createTextMessage(forChannel: channel, withBody: body, isIncoming: isIncoming, date: date)
    }

    func createTextMessage(forChannel channel: Channel, withBody body: String, isIncoming: Bool, date: Date) {
        self.queue.async {
            guard let entity = NSEntityDescription.entity(forEntityName: Entities.message.rawValue, in: self.managedContext) else {
                Log.error("Core Data: entity not found: " + Entities.message.rawValue)
                return
            }

            let message = Message(entity: entity, insertInto: self.managedContext)

            let encryptedBody = body    //= try? VirgilHelper.sharedInstance.encrypt(text: body)
            message.body = encryptedBody //?? "Error encrypting message"
            message.isIncoming = isIncoming
            message.date = date

            let messages = channel.mutableOrderedSetValue(forKey: Keys.messages.rawValue)
            messages.add(message)

            Log.debug("Core Data: new message added. Count: \(messages.count)")
            self.appDelegate.saveContext()
        }
    }
}
