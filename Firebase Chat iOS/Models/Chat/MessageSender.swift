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
import VirgilCryptoApiImpl

public protocol DemoMessageModelProtocol: MessageModelProtocol {
    var status: MessageStatus { get set }
}

public class MessageSender {
    public let publicKeys: [VirgilPublicKey]
    public var onMessageChanged: ((_ message: DemoMessageModelProtocol) -> ())?

    public init(publicKeys: [VirgilPublicKey]) {
        self.publicKeys = publicKeys
    }

    public func sendMessages(_ messages: [DemoMessageModelProtocol]) {
        for message in messages {
            self.sendMessage(message)
        }
    }

    public func sendMessage(_ message: DemoMessageModelProtocol) {
        Log.debug("Sending message: \(message)")
        if let textMessage = message as? DemoTextMessageModel {
            do {
                let encrypted = try VirgilHelper.sharedInstance.encrypt(text: textMessage.body, for: self.publicKeys)

                self.messageStatus(ciphertext: encrypted, message: textMessage)
            } catch {
                Log.error("Sending message failed with error: \(error.localizedDescription)")
            }
        } else {
            Log.error("Unknown message model")
            return
        }
    }

    // MARK: - Private API

    private func messageStatus(ciphertext: String, message: DemoTextMessageModel) {
        switch message.status {
        case .success:
            break
        case .failed:
            self.updateMessage(message, status: .sending)
            self.messageStatus(ciphertext: ciphertext, message: message)
        case .sending:
            guard let currentUser = CoreDataHelper.sharedInstance.currentAccount?.identity,
                let receiver = CoreDataHelper.sharedInstance.currentChannel?.name else {
                    return
            }
            FirestoreHelper.sharedInstance.send(message: ciphertext, to: receiver, from: currentUser) { error in
                guard error == nil else {
                    Log.error("Sending message \"\(ciphertext)\" failed: \(error!.localizedDescription)")
                    self.updateMessage(message, status: .failed)
                    return
                }
                self.updateMessage(message, status: .success)
            }
        }
    }

    private func updateMessage(_ message: DemoMessageModelProtocol, status: MessageStatus) {
        if message.status != status {
            message.status = status
            self.notifyMessageChanged(message)
        }
    }

    private func notifyMessageChanged(_ message: DemoMessageModelProtocol) {
        DispatchQueue.main.async {
             self.onMessageChanged?(message)
        }
    }
}
