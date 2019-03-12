/*
 The MIT License (MIT)

 Copyright (c) 2015-present Badoo Trading Limited.

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
*/

import Foundation
import Chatto
import ChattoAdditions
import Firebase
import VirgilE3Kit

class DataSource: ChatDataSourceProtocol {
    var nextMessageId: Int = 0
    let preferredMaxWindowSize = 500
    private let pageSize: Int
    private var countCore: Int = 0
    var slidingWindow: SlidingDataSource<ChatItemProtocol>!
    private let publicKeys: EThree.LookupResult

    init(pageSize: Int, publicKeys: EThree.LookupResult) {
        self.slidingWindow = SlidingDataSource(pageSize: pageSize)
        self.pageSize = pageSize
        self.publicKeys = publicKeys

        guard let currentChannel = CoreDataHelper.sharedInstance.currentChannel,
            let globalName = currentChannel.globalName else {
                Log.error("Get current channel failed")
                return
        }
        guard let count = CoreDataHelper.sharedInstance.currentChannel?.messages?.count else {
            Log.error("Getting messeges count Core Data failed")
            return
        }
        self.countCore = count
        self.showMessages()
        self.delegate?.chatDataSourceDidUpdate(self, updateType: .reload)
        NotificationCenter.default.addObserver(self,
                                               selector: #selector(DataSource.processMessage(notification:)),
                                               name: Notification.Name(rawValue: FirestoreHelper.Notifications.MessageAdded.rawValue),
                                               object: nil)

        FirestoreHelper.sharedInstance.setUpChannelListener(channel: globalName)
    }

    @objc private func processMessage(notification: Notification) {
        Log.debug("processing message")
        guard  let userInfo = notification.userInfo,
            let messages = userInfo[FirestoreHelper.NotificationKeys.messages.rawValue] as? [QueryDocumentSnapshot],
            let currentUser = CoreDataHelper.sharedInstance.currentAccount?.identity else {
                return
        }

        if (self.countCore < messages.count) {
            for i in self.countCore..<messages.count {
                let messageDocuments = messages.filter({ $0.documentID == "\(i)" })
                guard let messageDocument = messageDocuments.first,
                    let receiver = messageDocument.data()[FirestoreHelper.Keys.receiver.rawValue] as? String,
                    let body = messageDocument.data()[FirestoreHelper.Keys.body.rawValue] as? String,
                    let timestamp = messageDocument.data()[FirestoreHelper.Keys.createdAt.rawValue] as? Timestamp else {
                        return
                }
                let messageDate = timestamp.dateValue()
                let isIncoming = receiver == currentUser ? true : false

                var decryptedBody: String?
                do {
                    // For group chats here should be getting sender id and decrypting from publicKeys[senderId]
                    let publicKey = isIncoming ? self.publicKeys.first?.value : nil
                    decryptedBody = try E3KitHelper.sharedInstance.decrypt(text: body, from: publicKey)
                } catch {
                    Log.error("Decrypting failed with error: \(error.localizedDescription)")
                }

                let decryptedMessage = MessageFactory.createTextMessageModel("\(self.nextMessageId)",
                                                                             text: decryptedBody ?? "Message encrypted",
                                                                             isIncoming: isIncoming, status: .success,
                                                                             date: messageDate)
                CoreDataHelper.sharedInstance.createTextMessage(withBody: decryptedBody ?? "Message encrypted",
                                                                isIncoming: isIncoming, date: messageDate)

                self.countCore += 1
                self.slidingWindow.insertItem(decryptedMessage, position: .bottom)
                self.nextMessageId += 1

                self.delegate?.chatDataSourceDidUpdate(self)
            }
        }
    }

    lazy var messageSender: MessageSender = {
        let sender = MessageSender(publicKeys: self.publicKeys)
        sender.onMessageChanged = { [weak self] message in
            guard let sSelf = self else { return }
            sSelf.delegate?.chatDataSourceDidUpdate(sSelf)
        }
        return sender
    }()

    var hasMoreNext: Bool {
        return self.slidingWindow.hasMore()
    }

    var hasMorePrevious: Bool {
        return self.slidingWindow.hasPrevious()
    }

    var chatItems: [ChatItemProtocol] {
        return self.slidingWindow.itemsInWindow
    }

    weak var delegate: ChatDataSourceDelegateProtocol?

    func loadNext() {
        self.slidingWindow.loadNext()
        self.slidingWindow.adjustWindow(focusPosition: 1, maxWindowSize: self.preferredMaxWindowSize)
        self.delegate?.chatDataSourceDidUpdate(self, updateType: .pagination)
    }

    func loadPrevious() {
        self.slidingWindow.loadPrevious()
        self.slidingWindow.adjustWindow(focusPosition: 0, maxWindowSize: self.preferredMaxWindowSize)
        self.delegate?.chatDataSourceDidUpdate(self, updateType: .pagination)
    }

    func addTextMessage(_ text: String) {
        let uid = "\(self.nextMessageId)"
        self.nextMessageId += 1
        let message = MessageFactory.createTextMessageModel(uid, text: text, isIncoming: false, status: .sending, date: Date())
        self.messageSender.sendMessage(message)
        self.delegate?.chatDataSourceDidUpdate(self)
    }

    func adjustNumberOfMessages(preferredMaxCount: Int?, focusPosition: Double, completion:(_ didAdjust: Bool) -> ()) {
        let didAdjust = self.slidingWindow.adjustWindow(focusPosition: focusPosition,
                                                        maxWindowSize: preferredMaxCount ?? self.preferredMaxWindowSize)
        completion(didAdjust)
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
}

extension DataSource {
    private func showMessages() {
        guard let channel = CoreDataHelper.sharedInstance.currentChannel,
            let messages = channel.messages else {
                Log.error("Can't get last messages: channel not found in Core Data")
                return
        }

        for message in messages {
            guard let message = message as? Message,
                let messageDate = message.date else {
                    Log.error("Retriving message from Core Data failed")
                    return
            }
            let resultMessage = MessageFactory.createTextMessageModel("\(self.nextMessageId)",
                                                                      text: message.body ?? "Corrupted Message",
                                                                      isIncoming: message.isIncoming,
                                                                      status: .success, date: messageDate)
            self.slidingWindow.insertItem(resultMessage, position: .bottom)
            self.nextMessageId += 1
        }
    }
}
