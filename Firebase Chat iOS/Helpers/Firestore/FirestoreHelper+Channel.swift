//
//  FirestoreHelper+Channel.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/27/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import Firebase

extension FirestoreHelper {
    func createChannel(user1: String, user2: String, completion: @escaping (Error?) -> ()) {
        guard let name = FirestoreHelper.makeChannelName(user1, user2) else {
            Log.error("Firestore: creating Channel failed")
            // FIXME
            completion(NSError())
            return
        }

        Firestore.firestore().runTransaction({ transaction, errorPointer in
            let user1DocRef = self.userCollection.document(user1)
            let user2DocRef = self.userCollection.document(user2)
            let channelDocRef = self.channelCollection.document(name)

            do {
                let user1Doc = try transaction.getDocument(user1DocRef)
                let user2Doc = try transaction.getDocument(user2DocRef)

                guard let user1ID = user1Doc.data()?[Keys.uid.rawValue],
                    let user2ID = user2Doc.data()?[Keys.uid.rawValue],
                    var user1Channels = user1Doc.data()?[Keys.channels.rawValue] as? [String],
                    var user2Channels = user2Doc.data()?[Keys.channels.rawValue] as? [String] else {
                        // FIXME
                        throw NSError()
                }
                user1Channels.append(name)
                user2Channels.append(name)

                let user1Decription = [Keys.username.rawValue: user1, Keys.uid.rawValue: user1ID]
                let user2Decription = [Keys.username.rawValue: user2, Keys.uid.rawValue: user2ID]

                let channelDocData: [String: Any] = [Keys.members.rawValue: [user1Decription, user2Decription],
                                                     Keys.count.rawValue: 0] as [String : Any]

                transaction.updateData([Keys.channels.rawValue: user1Channels], forDocument: user1DocRef)
                transaction.updateData([Keys.channels.rawValue: user2Channels], forDocument: user2DocRef)
                transaction.setData(channelDocData, forDocument: channelDocRef)

                return nil
            } catch {
                errorPointer?.pointee = error as NSError

                return nil
            }
        }, completion: { object, error in
            if let error = error {
                Log.error("Firebase channel creation failed with error: \(error.localizedDescription)")
            }
            
            completion(error)
        })
    }

    func getChannels(of user: String, completion: @escaping ([String], Error?) -> ()) {
        let userReference = self.userCollection.document(user)
        userReference.getDocument { snapshot, error in
            guard error == nil, let snapshot = snapshot,
                let channels = snapshot.get(Keys.channels.rawValue) as? [String] else {
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
            guard error == nil, let snapshot = snapshot,
                let members = snapshot.get(Keys.members.rawValue) as? [String] else {
                    Log.debug("Firebase: get channel members failed")
                    completion([], error)
                    return
            }
            completion(members, nil)
        }
    }

    static func makeChannelName(_ user1: String, _ user2: String) -> String? {
        if user1 > user2 {
            return E3KitHelper.makeHash(from: user1 + user2)
        } else {
            return E3KitHelper.makeHash(from: user2 + user1)
        }
    }
}
