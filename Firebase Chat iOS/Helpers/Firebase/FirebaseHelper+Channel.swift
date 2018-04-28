//
//  FirebaseHelper+Channel.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/27/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import Firebase

extension FirebaseHelper {
    func createChannel(currentUser: String, user: String, completion: @escaping (Error?) -> ()) {
        guard let name = FirebaseHelper.makeChannelName(currentUser, user) else {
            Log.error("Firestore: creating Channel failed")
            completion(NSError())
            return
        }

        let group = DispatchGroup()
        var err: Error?

        group.enter()
        self.channelCollection.document(name).setData([
            Keys.members.rawValue: [currentUser, user],
            Keys.count.rawValue: 0
        ]) { error in
            err = error
            group.leave()
        }

        self.userCollection.document(currentUser).getDocument { snapshot, error in
            guard let snapshot = snapshot, error == nil, var channels = snapshot.data()?[Keys.channels.rawValue] as? [String] else {
                err = error ?? NSError()
                group.leave()
                return
            }
            channels.append(name)
            self.userCollection.document(currentUser).updateData([
                Keys.channels.rawValue: channels
            ]) { error in
                err = error
                group.leave()
            }
        }

        group.enter()
        self.userCollection.document(user).getDocument { snapshot, error in
            guard let snapshot = snapshot, error == nil, var channels = snapshot.data()?[Keys.channels.rawValue] as? [String] else {
                err = error ?? NSError()
                group.leave()
                return
            }
            channels.append(name)
            self.userCollection.document(user).updateData([
                Keys.channels.rawValue: channels
            ]) { error in
                err = error
                group.leave()
            }
        }

        group.notify(queue: .main) {
            if let error = err {
                Log.error("Firebase channel creation failed with error: \(error.localizedDescription)")
            }
            completion(err)
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
