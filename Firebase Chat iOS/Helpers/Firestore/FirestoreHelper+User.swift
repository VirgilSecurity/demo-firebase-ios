//
//  FirestoreHelper+User.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/27/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import Firebase

extension FirestoreHelper {
    func setUpUser(identity: String, completion: @escaping (Error?) -> ()) {
        self.doesUserExist(withUsername: identity) { exist in
            if !exist {
                self.createUser(identity: identity) { error in
                    guard error == nil else {
                        Log.error("Firebase: creating user failed with error: \(error!.localizedDescription)")
                        completion(error)
                        return
                    }

                    completion(nil)
                }
            }
        }
    }

    func createUser(identity: String, completion: @escaping (Error?) -> ()) {
        let userReference = self.userCollection.document(identity)
        userReference.setData([
            Keys.createdAt.rawValue: Date(),
            Keys.channels.rawValue: []
        ]) { error in
            guard error == nil else {
                completion(error)
                return
            }
            Log.debug("Firebase: user created")

            completion(nil)
        }
    }

    func doesUserExist(withUsername username: String, completion: @escaping (Bool) -> ()) {
        let userReference = self.userCollection.document(username)
        userReference.getDocument { snapshot, error in
            if error != nil || snapshot == nil || !(snapshot?.exists)! {
                completion(false)
                Log.debug("Firebase: user do not exist")
                return
            }
            completion(true)
            Log.debug("Firebase: user exist")
        }
    }
}
