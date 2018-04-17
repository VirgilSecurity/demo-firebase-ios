//
//  CoreDataHelper+Account.swift
//  VirgilMessenger
//
//  Created by Eugen Pivovarov on 2/20/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation
import CoreData

extension CoreDataHelper {
    func createAccount(withIdentity identity: String, exportedCard: String, completion: @escaping () -> ()) {
        self.queue.async {
            guard let entity = NSEntityDescription.entity(forEntityName: Entities.account.rawValue, in: self.managedContext) else {
                Log.error("Core Data: entity not found: " + Entities.account.rawValue)
                return
            }

            let account = Account(entity: entity, insertInto: self.managedContext)
            account.identity = identity
            account.card = exportedCard

            self.append(account: account)
            self.setCurrent(account: account)

            Log.debug("Core Data: account created")

            self.appDelegate.saveContext()

            completion()
        }
    }

    func loadAccount(withIdentity username: String) -> Bool {
        Log.debug("Core Data: Search for " + username)
        for account in CoreDataHelper.sharedInstance.accounts {
            if let identity = account.identity, identity == username {
                self.setCurrent(account: account)
                Log.debug("Core Data: found account: " + identity)
                let channels = account.channels
                Log.debug("Core Data: it has " + String(describing: channels?.count) + " channels")
                return true
            }
        }
        Log.debug("Core Data: Searching for account ended")
        return false
    }

    func getAccount(withIdentity username: String) -> Account? {
        for account in CoreDataHelper.sharedInstance.accounts {
            if let identity = account.identity, identity == username {
                return account
            }
        }
        return nil
    }

    func getAccountCard() -> String? {
        if let account = currentAccount, let card = account.card {
            return card
        } else {
            Log.error("Core Data: nil account found")
            return nil
        }
    }

    func deleteAccount() {
        guard let account = self.currentAccount else {
            Log.error("Core Data: nil account")
            return
        }

        self.managedContext.delete(account)
        Log.debug("Core Data: account deleted")

        self.appDelegate.saveContext()

        self.reloadData()
    }
}
