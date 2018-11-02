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
    func setUpUser(identity: String, uid: String, completion: @escaping (Error?) -> ()) {
        self.doesUserExist(withUsername: identity) { exist in
            if !exist {
                self.createUser(identity: identity, uid: uid) { error in
                    if let error = error {
                        Log.error("Firebase: creating user failed with error: \(error.localizedDescription)")
                    }

                    completion(error)
                }
            }
        }
    }

    func createUser(identity: String, uid: String, completion: @escaping (Error?) -> ()) {
        let userReference = self.userCollection.document(identity)

        let userData: [String: Any] = [Keys.uid.rawValue: uid,
                                       Keys.createdAt.rawValue: Date(),
                                       Keys.channels.rawValue: []]

        userReference.setData(userData) { error in
            if let error = error {
                Log.error("Firebase: creating user failed with error: \(error.localizedDescription)")
            }

            completion(error)
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
