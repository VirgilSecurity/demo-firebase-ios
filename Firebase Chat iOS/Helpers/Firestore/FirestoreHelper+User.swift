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
    func setUpUser(username: String, uid: String, completion: @escaping (Error?) -> ()) {
        self.doesUserExist(withUsername: username) { exist in
            if !exist {
                self.createUser(username: username, uid: uid) { error in
                    if let error = error {
                        Log.error("Firebase: creating user failed with error: \(error.localizedDescription)")
                    }

                    completion(error)
                }
            }
        }
    }

    func createUser(username: String, uid: String, completion: @escaping (Error?) -> ()) {
        InstanceID.instanceID().instanceID { (result, error) in
            guard let token = result?.token, error == nil else {
                completion(error)
                return
            }
            let userReference = self.userCollection.document(username)

            let userData: [String: Any] = [Keys.uid.rawValue: uid,
                                           Keys.registrationToken.rawValue: token,
                                           Keys.createdAt.rawValue: Date(),
                                           Keys.channels.rawValue: []]

            userReference.setData(userData) { error in
                if let error = error {
                    Log.error("Firebase: creating user failed with error: \(error.localizedDescription)")
                }

                completion(error)
            }
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
