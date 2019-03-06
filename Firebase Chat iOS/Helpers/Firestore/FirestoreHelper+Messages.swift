//
//  FirestoreHelper+Messages.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 5/4/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import Firebase
import VirgilE3Kit

extension FirestoreHelper {
    func send(message: String, to receiver: String, from currentUser: String, completion: @escaping (Error?) -> ()) {
        guard let channel = FirestoreHelper.makeChannelName(currentUser, receiver) else {
            completion(nil)
            return
        }

        let channelDocRef = self.channelCollection.document(channel)
        let messagesCollection = channelDocRef.collection(Collections.messages.rawValue)

        Firestore.firestore().runTransaction({ transaction, errorPointer in
            do {
                let channelDoc = try transaction.getDocument(channelDocRef)

                let messagesNumber = (channelDoc.data()?[Keys.count.rawValue] as? Int) ?? 0
                let messageDoc = messagesCollection.document("\(messagesNumber)")
                let messageData: [String: Any] = [Keys.body.rawValue: message,
                                                  Keys.sender.rawValue: currentUser,
                                                  Keys.receiver.rawValue: receiver,
                                                  Keys.createdAt.rawValue: Date()]
                transaction.setData(messageData, forDocument: messageDoc)

                let updatedCountData = [Keys.count.rawValue: messagesNumber + 1]
                transaction.updateData(updatedCountData, forDocument: channelDocRef)

                return nil
            } catch {
                errorPointer?.pointee = error as NSError
                return nil
            }
        }, completion: { object, error in
            if let error = error {
                Log.error("Firebase: writing message transaction failed with error: \(error.localizedDescription)")
            }

            completion(error)
        })
    }

    func blindMessageBody(messageNumber: String, channel: String, completion: @escaping (Error?) -> ()) {
        let channelReference = self.channelCollection.document(channel)
        let messagesCollection = channelReference.collection(Collections.messages.rawValue)

        let updatedBodyData = [Keys.body.rawValue: ""]

        messagesCollection.document("\(messageNumber)").updateData(updatedBodyData) { error in
            if let error = error {
                Log.debug("Blinding message failed with error: \(error.localizedDescription)")
            }

            completion(error)
        }
    }

    func updateMessages(of channel: String, publicKeys: EThree.LookupResult, completion: @escaping (Error?) -> ()) {
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
                        let receiver = messageDocument.data()[FirestoreHelper.Keys.receiver.rawValue] as? String,
                        let body = messageDocument.data()[FirestoreHelper.Keys.body.rawValue] as? String,
                        let timestamp = messageDocument.data()[FirestoreHelper.Keys.createdAt.rawValue] as? Timestamp else {
                            break
                    }
                    var decryptedBody: String?
                    if body == "" {
                        decryptedBody = "Message deleted"
                    } else {
                        do {
                            decryptedBody = try E3KitHelper.sharedInstance.decrypt(text: body, from: publicKeys.first?.value)
                        } catch {
                            Log.error("Decrypting failed with error: \(error.localizedDescription)")
                        }
                    }
                    let messageDate = timestamp.dateValue()
                    let isIncoming = receiver == currentUser ? true : false

                    CoreDataHelper.sharedInstance.createTextMessage(withBody: decryptedBody ?? "Message encrypted",
                                                                    isIncoming: isIncoming, date: messageDate)
                    count += 1
                }
            }
            completion(nil)
        }
    }
}
