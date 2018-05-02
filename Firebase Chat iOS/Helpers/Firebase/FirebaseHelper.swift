//
//  FirebaseHelper.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/13/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import Firebase

class FirebaseHelper {
    static private(set) var sharedInstance: FirebaseHelper!
    static var tokenChangeListener: IDTokenDidChangeListenerHandle? = nil
    let userCollection: CollectionReference
    let channelCollection: CollectionReference

    var channelListListener: ListenerRegistration?
    var channelListener: ListenerRegistration?

    enum Collections: String {
        case users = "Users"
        case channels = "Channels"
        case messages = "Messages"
    }

    enum Keys: String {
        case members
        case channels
        case createdAt
        case count
        case body
        case sender
        case receiver
    }

    enum Notifications: String {
        case ChannelAdded = "FirebaseHelper.Notifications.ChannelAdded"
        case MessageAdded = "FirebaseHelper.Notifications.MessageAdded"
    }

    enum NotificationKeys: String {
        case channels
        case messages
    }

    static func initialize() {
        sharedInstance = FirebaseHelper()
    }

    private init() {
        self.userCollection = Firestore.firestore().collection(Collections.users.rawValue)
        self.channelCollection = Firestore.firestore().collection(Collections.channels.rawValue)
        self.channelListListener = nil
        self.channelListener = nil

        FirebaseHelper.tokenChangeListener = Auth.auth().addIDTokenDidChangeListener { auth, user in
            guard let user = user, let email = user.email else {
                Log.error("Refresh token failed")
                return
            }
            user.getIDToken { token, error in
                guard error == nil, let token = token else {
                    Log.error("get ID Token with error: \(error?.localizedDescription ?? "unknown error")")
                    return
                }
                VirgilHelper.sharedInstance.update(email: email, authToken: token)
            }
        }
    }

    func setUpChannelListListener(email: String) {
        self.channelListListener = self.userCollection.document(email).addSnapshotListener { documentSnapshot, error in
            guard let channels = documentSnapshot?.get("channels") as? [String] else {
                print("Error fetching document: \(error?.localizedDescription ?? "unknown error")")
                return
            }
            NotificationCenter.default.post(
                name: Notification.Name(rawValue: FirebaseHelper.Notifications.ChannelAdded.rawValue),
                object: self,
                userInfo: [
                    NotificationKeys.channels.rawValue: channels
                ])
        }
    }

    func setUpChannelListener(channel: String) {
        let messageCollection = self.channelCollection.document(channel).collection(Collections.messages.rawValue)
        self.channelListener = messageCollection.addSnapshotListener { snapshot, error in
            guard let messages = snapshot?.documents else {
                print("Error fetching messages: \(error?.localizedDescription ?? "unknown error")")
                return
            }
            NotificationCenter.default.post(
                name: Notification.Name(rawValue: FirebaseHelper.Notifications.MessageAdded.rawValue),
                object: self,
                userInfo: [
                    NotificationKeys.messages.rawValue: messages
                ])
        }
    }

    func send(message: String, to receiver: String, from currentUser: String, completion: @escaping (Error?) -> ()) {
        guard let channel = FirebaseHelper.makeChannelName(currentUser, receiver) else {
            return
        }
        let channelReference = self.channelCollection.document(channel)
        let messagesCollection = channelReference.collection(Collections.messages.rawValue)

        channelReference.getDocument { snapshot, error in
            guard let snapshot = snapshot, error == nil else {
                Log.error("Firestore: get user document failed with error: (\(error?.localizedDescription ?? "unknown error")")
                completion(error)
                return
            }
            let count = (snapshot.data()?[Keys.count.rawValue] as? Int) ?? 0

            messagesCollection.document("\(count)").setData([
                Keys.body.rawValue: message,
                Keys.sender.rawValue: currentUser,
                Keys.receiver.rawValue: receiver,
                Keys.createdAt.rawValue: Date()
            ]) { error in
                guard error == nil else {
                    completion(error)
                    return
                }
                channelReference.updateData([
                    Keys.count.rawValue: count + 1
                ]) { error in
                     completion(error)
                }
            }
        }
    }
}
