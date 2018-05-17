//
//  Firebase+Messages.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 5/4/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import Firebase

extension FirebaseHelper {
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

    func updateMessages(of channel: String, completion: @escaping (Error?) -> ()) {
        let channelReference = self.channelCollection.document(channel)
        let messagesCollection = channelReference.collection(Collections.messages.rawValue)

        guard var count = CoreDataHelper.sharedInstance.currentChannel?.messages?.count else {
            Log.error("Getting messeges count Core Data failed")
            completion(NSError())
            return
        }

        guard let currentUser = CoreDataHelper.sharedInstance.currentAccount?.identity else {
            Log.error("Getting Core Data current user failed")
            completion(NSError())
            return
        }

        messagesCollection.getDocuments { snapshot, error in
            guard let messages = snapshot?.documents else {
                Log.error("Error fetching messages: \(error?.localizedDescription ?? "unknown error")")
                completion(NSError())
                return
            }
            if (count < messages.count) {
                for i in count..<messages.count {
                    let messageDocuments = messages.filter({ $0.documentID == "\(i)" })
                    guard let messageDocument = messageDocuments.first,
                        let receiver = messageDocument.data()[FirebaseHelper.Keys.receiver.rawValue] as? String,
                        let body = messageDocument.data()[FirebaseHelper.Keys.body.rawValue] as? String,
                        let timestamp = messageDocument.data()[FirebaseHelper.Keys.createdAt.rawValue] as? Timestamp else {
                            break
                    }
                    let messageDate = timestamp.dateValue()
                    let isIncoming = receiver == currentUser ? true : false

                    var decryptedBody: String?
                    do {
                        decryptedBody = try VirgilHelper.sharedInstance.decrypt(body)
                    } catch {
                        Log.error("Decrypting failed with error: \(error.localizedDescription)")
                    }
                    CoreDataHelper.sharedInstance.createTextMessage(withBody: decryptedBody ?? "Message encrypted",
                                                                    isIncoming: isIncoming, date: messageDate)
                    count += 1
                }
            }
            completion(nil)
        }
    }
}
