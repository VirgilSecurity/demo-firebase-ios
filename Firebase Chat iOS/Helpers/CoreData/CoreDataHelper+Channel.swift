//
//  CoreDataHelper+Channel.swift
//  VirgilMessenger
//
//  Created by Eugen Pivovarov on 2/20/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation
import CoreData

extension CoreDataHelper {
    func createChannel(withName name: String, globalName: String) -> Channel? {
        guard let account = self.currentAccount else {
            Log.error("Core Data: nil account")
            return nil
        }

        guard let entity = NSEntityDescription.entity(forEntityName: Entities.channel.rawValue, in: self.managedContext) else {
            Log.error("Core Data: entity not found: " + Entities.channel.rawValue)
            return nil
        }

        let channel = Channel(entity: entity, insertInto: self.managedContext)

        channel.name = name
        channel.globalName = globalName

        let channels = account.mutableOrderedSetValue(forKey: Keys.channels.rawValue)
        channels.add(channel)

        Log.debug("Core Data: new channel added. Count: \(channels.count)")
        self.appDelegate.saveContext()

        return channel
    }

    func loadChannel(withName username: String) -> Bool {
        if let channel = self.getChannel(withName: username) {
            self.setCurrent(channel: channel)
            return true
        }
        return false
    }

    func getChannel(withName username: String) -> Channel? {
        guard let account = self.currentAccount, let channels = account.channels else {
            Log.error("Core Data: nil account core data")
            return nil
        }

        for channel in channels {
            guard let channel = channel as? Channel, let name = channel.name  else {
                Log.error("Core Data: can't get account channel")
                return nil
            }
            Log.debug("Core Data name: " + name)
            if name == username {
                Log.debug("Core Data: found channel in core data: " + name)
                return channel
            }
        }
        Log.error("Core Data: channel not found")
        return nil
    }

    func deleteChannel(withName username: String) {
        self.queue.async {
            guard let account = self.currentAccount, let channels = account.channels else {
                Log.error("Core Data: nil account")
                return
            }

            for channel in channels {
                guard let channel = channel as? Channel, let name = channel.name else {
                    Log.error("Core Data: can't get account channels")
                    return
                }

                Log.debug("Core Data name: " + name)
                if name == username {
                    Log.debug("Core Data: found channel in core data: " + name)
                    self.managedContext.delete(channel)
                    Log.debug("Core Data: channel deleted")
                    return
                }
            }
            Log.error("Core Data: channel not found")
            self.appDelegate.saveContext()
        }
    }

    func doesChannelExist(withName username: String) -> Bool {
        guard let account = self.currentAccount else {
            Log.error("Core Data: missing current user")
            return false
        }

        guard let channels = account.channels else {
            Log.error("Core Data failed")
            return false
        }

        for item in channels {
            guard let channel = item as? Channel else {
                Log.error("Core Data failed")
                return false
            }
            if channel.name == username {
                return true
            }
        }

        return false
    }

    func doesChannelExist(withGlobalName username: String) -> Bool {
        guard let account = self.currentAccount else {
            Log.error("Core Data: missing current user")
            return false
        }

        guard let channels = account.channels else {
            Log.error("Core Data failed")
            return false
        }

        for item in channels {
            guard let channel = item as? Channel else {
                Log.error("Core Data failed")
                return false
            }
            if channel.globalName == username {
                return true
            }
        }

        return false
    }
}
