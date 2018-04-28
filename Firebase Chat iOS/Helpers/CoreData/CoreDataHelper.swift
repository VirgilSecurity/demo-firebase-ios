//
//  CoreDataHelper.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 11/9/17.
//  Copyright © 2017 Virgil Security. All rights reserved.
//

import UIKit
import Foundation
import CoreData

class CoreDataHelper {
    let queue: DispatchQueue
    let appDelegate = UIApplication.shared.delegate as! AppDelegate
    let managedContext: NSManagedObjectContext

    static private(set) var sharedInstance: CoreDataHelper!
    private(set) var accounts: [Account] = []
    private(set) var currentChannel: Channel?
    private(set) var currentAccount: Account?

    enum Entities: String {
        case account = "Account"
        case channel = "Channel"
        case message = "Message"
    }

    enum Keys: String {
        case account = "account"
        case channels = "channels"
        case messages = "messages"
        case identity = "identity"
        case name = "name"
        case body = "body"
        case isIncoming = "isIncoming"
    }

    static func initialize() {
        sharedInstance = CoreDataHelper()
    }

    private init() {
        managedContext = self.appDelegate.persistentContainer.viewContext
        self.queue = DispatchQueue(label: "core-data-help-queue")
        guard let accounts = self.fetch() else {
            Log.error("Core Data: fetch error")
            return
        }
        self.accounts = accounts
        Log.debug("Core Data: accounts fetched. Count: \(self.accounts.count)")
        for account in self.accounts {
            let identity = account.identity ?? "not found"
            Log.debug(identity)
        }
    }

    func reloadData() {
        guard let accounts = self.fetch() else {
            Log.error("Core Data: fetch error")
            return
        }
        self.accounts = accounts
    }

    private func fetch() -> [Account]? {
        let fetchRequest = NSFetchRequest<NSManagedObject>(entityName: Entities.account.rawValue)

        do {
            let accounts = try managedContext.fetch(fetchRequest) as? [Account]
            return accounts
        } catch let error as NSError {
            Log.error("Could not fetch. \(error), \(error.userInfo)")
            return nil
        }
    }

    func setCurrent(account: Account?) {
        self.currentAccount = account
    }

    func setCurrent(channel: Channel?) {
        self.currentChannel = channel
    }

    func append(account: Account) {
        self.accounts.append(account)
    }
}
