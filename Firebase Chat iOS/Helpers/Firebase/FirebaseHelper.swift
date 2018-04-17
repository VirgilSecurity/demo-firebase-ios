//
//  FirebaseHelper.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/13/18.
//  Copyright © 2018 Eugen Pivovarov. All rights reserved.
//

import Foundation
import Firebase

class FirebaseHelper {
    static let sharedInstance = FirebaseHelper()
    let userCollection: CollectionReference
    let channelCollection: CollectionReference
    var listener: ListenerRegistration?

    enum Collections: String {
        case users = "Users"
        case channels = "Channels"
    }

    enum Keys: String {
        case members = "members"
        case channels = "channels"
        case createdAt = "createdAt"
    }

    enum Notifications: String {
        case ChannelAdded = "FirebaseHelper.Notifications.ChannelAdded"
    }

    private init() {
        self.userCollection = Firestore.firestore().collection(Collections.users.rawValue)
        self.channelCollection = Firestore.firestore().collection(Collections.channels.rawValue)
        self.listener = nil
    }

    func setUpListener(email: String) {
        listener = self.userCollection.document(email).addSnapshotListener { documentSnapshot, error in
            guard let channels = documentSnapshot?.get("channels") as? [String] else {
                print("Error fetching document: \(error?.localizedDescription ?? "unknown error")")
                return
            }
            NotificationCenter.default.post(
                name: Notification.Name(rawValue: FirebaseHelper.Notifications.ChannelAdded.rawValue),
                object: self,
                userInfo: [
                    Keys.channels.rawValue: channels
                ])
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
        }
    }

    func createChannel(currentUser: String, user: String, completion: @escaping (Error?) -> ()) {
        guard let name = FirebaseHelper.makeChannelName(currentUser, user) else {
            Log.error("Firestore: creating Channel failed")
            completion(NSError())
            return
        }

        self.channelCollection.document(name).setData([
            Keys.members.rawValue: [currentUser, user]
        ]) { error in
            guard error == nil else {
                Log.error("Firestore: Adding channel failed with error: \(error?.localizedDescription ?? "unknown error")")
                completion(error)
                return
            }

            self.userCollection.document(currentUser).getDocument { snapshot, error in
                guard let snapshot = snapshot, error == nil, var channels = snapshot.data()?[Keys.channels.rawValue] as? [String] else {
                    Log.error("Firestore: get user document failed with error: (\(error?.localizedDescription ?? "unknown error")")
                    completion(error)
                    return
                }
                channels.append(name)
                self.userCollection.document(currentUser).updateData([
                    Keys.channels.rawValue: channels
                ]) { error in
                    guard error == nil else {
                        completion(error) 
                        return
                    }
                    self.userCollection.document(user).getDocument { snapshot, error in
                        guard let snapshot = snapshot, error == nil, var channels = snapshot.data()?[Keys.channels.rawValue] as? [String] else {
                            Log.error("Firestore: get user document failed with error: (\(error?.localizedDescription ?? "unknown error")")
                            completion(error)
                            return
                        }
                        channels.append(name)
                        self.userCollection.document(user).updateData([
                            Keys.channels.rawValue: channels
                        ]) { error in
                            completion(error)
                        }
                    }
                }
            }
        }
    }

    func getChannels(of user: String, completion: @escaping ([String], Error?) -> ()) {
        let userReference = self.userCollection.document(user)
        userReference.getDocument { snapshot, error in
            guard error == nil, let snapshot = snapshot, let channels = snapshot.get(Keys.channels.rawValue) as? [String] else {
                Log.debug("Firebase: get channels failed")
                completion([], error)
                return
            }
            completion(channels, nil)
        }
    }


    func getChannelMembers(channel: String, completion: @escaping ([String], Error?) -> ()) {
        let channelReference = self.channelCollection.document(channel)
        channelReference.getDocument { snapshot, error in
            guard error == nil, let snapshot = snapshot, let members = snapshot.get(Keys.members.rawValue) as? [String] else {
                Log.debug("Firebase: get channel members failed")
                completion([], error)
                return
            }
            completion(members, nil)
        }
    }

    static func makeChannelName(_ user1: String, _ user2: String) -> String? {
        if user1 > user2 {
            return VirgilHelper.sharedInstance.makeHash(from: user1 + user2)
        } else {
            return VirgilHelper.sharedInstance.makeHash(from: user2 + user1)
        }
    }
}
