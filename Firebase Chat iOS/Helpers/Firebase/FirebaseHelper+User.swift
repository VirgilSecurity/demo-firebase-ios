//
//  FirebaseHelper+User.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/27/18.
//  Copyright © 2018 Eugen Pivovarov. All rights reserved.
//

import Foundation
import Firebase

extension FirebaseHelper {
    func createUser(email: String, completion: @escaping (Error?) -> ()) {
        let userReference = self.userCollection.document(email)
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

    func doesUserExist(withUsername username: String, completion: @escaping (Bool)->()) {
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
