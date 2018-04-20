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

class DataSource: ChatDataSourceProtocol {
    var nextMessageId: Int = 0
    let preferredMaxWindowSize = 500
    private let pageSize: Int
    private var countCore: Int = 0
    var slidingWindow: SlidingDataSource<ChatItemProtocol>!

    init(pageSize: Int) {
        self.slidingWindow = SlidingDataSource(pageSize: pageSize)
        self.pageSize = pageSize
        self.countCore = self.getCoreDataLastMessages().count

        guard let currentChannel = CoreDataHelper.sharedInstance.currentChannel,
            let globalName = currentChannel.globalName else {
                Log.error("Get current channel failed")
                return
        }
        NotificationCenter.default.addObserver(self,
                                               selector: #selector(DataSource.processMessage(notification:)),
                                               name: Notification.Name(rawValue: FirebaseHelper.Notifications.MessageAdded.rawValue),
                                               object: nil)

        FirebaseHelper.sharedInstance.setUpChannelListener(channel: globalName)
    }

    @objc private func processMessage(notification: Notification) {
        Log.debug("processing message")
        guard  let userInfo = notification.userInfo,
            let messages = userInfo[FirebaseHelper.NotificationKeys.messages.rawValue] as? [QueryDocumentSnapshot],
            let currentUser = CoreDataHelper.sharedInstance.currentAccount?.identity else {
            return
        }

        for i in self.countCore..<messages.count {
            let messageDocuments = messages.filter({ $0.documentID == "\(i)" })
            guard let messageDocument = messageDocuments.first,
                let receiver = messageDocument.data()[FirebaseHelper.Keys.receiver.rawValue] as? String,
                let body = messageDocument.data()[FirebaseHelper.Keys.body.rawValue] as? String,
                let messageDate = messageDocument.data()[FirebaseHelper.Keys.createdAt.rawValue] as? Date else {
                    return
            }
            if receiver != currentUser {
                let textMessageModel = MessageFactory.createTextMessageModel("\(self.nextMessageId)", text: body,
                                                                             isIncoming: false, status: .success, date: messageDate)
                CoreDataHelper.sharedInstance.createTextMessage(withBody: body, isIncoming: false, date: messageDate)
                self.countCore += 1

                self.slidingWindow.insertItem(textMessageModel, position: .bottom)
                self.nextMessageId += 1
            } else {
                Log.debug("Receiving " + body)

                let textMessageModel = MessageFactory.createTextMessageModel("\(self.nextMessageId)", text: body,
                                                                             isIncoming: true, status: .success, date: messageDate)

                CoreDataHelper.sharedInstance.createTextMessage(withBody: body, isIncoming: true, date: messageDate)
                self.countCore += 1

                self.slidingWindow.insertItem(textMessageModel, position: .bottom)
                self.nextMessageId += 1
            }
            self.delegate?.chatDataSourceDidUpdate(self)
        }
    }

    lazy var messageSender: MessageSender = {
        let sender = MessageSender()
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
        //self.slidingWindow.insertItem(message, position: .bottom)
        self.delegate?.chatDataSourceDidUpdate(self)
    }

    func adjustNumberOfMessages(preferredMaxCount: Int?, focusPosition: Double, completion:(_ didAdjust: Bool) -> ()) {
        let didAdjust = self.slidingWindow.adjustWindow(focusPosition: focusPosition, maxWindowSize: preferredMaxCount ?? self.preferredMaxWindowSize)
        completion(didAdjust)
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
}

extension DataSource {
    private func getCoreDataLastMessages() -> [DemoMessageModelProtocol] {
        var result: [DemoMessageModelProtocol] = []

        guard let channel = CoreDataHelper.sharedInstance.currentChannel,
            let messages = channel.messages else {
                Log.error("Can't get last messages: channel not found in Core Data")
                return result
        }

        for message in messages {
            guard let message = message as? Message,
                let messageDate = message.date
                else {
                    Log.error("retriving message from Core Data failed")
                    return result
            }

            let decryptedMessage: DemoMessageModelProtocol
            if let messageBody = message.body {
                //let decryptedBody = try? VirgilHelper.sharedInstance.decrypt(text: messageBody) //FIXME

                let model = MessageFactory.createMessageModel("\(self.nextMessageId)", isIncoming: message.isIncoming,
                                                              type: TextMessageModel<MessageModel>.chatItemType,
                                                              status: .success, date: messageDate)
                decryptedMessage = DemoTextMessageModel(messageModel: model, text: messageBody)
            } else {
                let model = MessageFactory.createMessageModel("\(self.nextMessageId)", isIncoming: message.isIncoming,
                                                              type: TextMessageModel<MessageModel>.chatItemType,
                                                              status: .failed, date: messageDate)
                decryptedMessage =  DemoTextMessageModel(messageModel: model, text: "Corrupted Message")
            }
            self.slidingWindow.insertItem(decryptedMessage, position: .bottom)
            self.nextMessageId += 1

            result.append(decryptedMessage)
        }

        return result
    }
}
