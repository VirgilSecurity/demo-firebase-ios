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
            guard let user = user, let id = CoreDataHelper.sharedInstance.currentAccount?.identity else {
                Log.error("Refresh token failed")
                return
            }
            user.getIDToken { token, error in
                guard error == nil, let token = token else {
                    Log.error("get ID Token with error: \(error?.localizedDescription ?? "unknown error")")
                    return
                }
                VirgilHelper.sharedInstance.setCardManager(identity: id, authToken: token)
            }
        }
    }

    func setUpChannelListListener(for id: String) {
        self.channelListListener = self.userCollection.document(id).addSnapshotListener { documentSnapshot, error in
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
                Log.error("Error fetching messages: \(error?.localizedDescription ?? "unknown error")")
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
}
