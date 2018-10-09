//
//  ChatListController.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/12/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import Firebase

class ChatListController: ViewController {
    @IBOutlet weak var tableView: UITableView!

    override func viewDidLoad() {
        if let id = CoreDataHelper.sharedInstance.currentAccount?.identity,
            FirebaseHelper.sharedInstance.channelListListener == nil {
                FirebaseHelper.sharedInstance.setUpChannelListListener(for: id)
        }

        self.tableView.register(UINib(nibName: ChatListCell.name, bundle: Bundle.main),
                                forCellReuseIdentifier: ChatListCell.name)
        self.tableView.rowHeight = 94
        self.tableView.tableFooterView = UIView(frame: .zero)
        self.tableView.dataSource = self

        NotificationCenter.default.addObserver(self,
                                               selector: #selector(ChatListController.updateCoreDataChannels(notification:)),
                                               name: Notification.Name(rawValue: FirebaseHelper.Notifications.ChannelAdded.rawValue),
                                               object: nil)
    }

    override func viewWillAppear(_ animated: Bool) {
        VirgilHelper.sharedInstance.closeSession()
        FirebaseHelper.sharedInstance.channelListener?.remove()
        FirebaseHelper.sharedInstance.channelListener = nil
    }

    @objc func updateCoreDataChannels(notification: Notification) {
        guard let userInfo = notification.userInfo,
            let channels = userInfo[FirebaseHelper.NotificationKeys.channels.rawValue] as? [String] else {
                Log.error("processing new channel failed")
                return
        }
        guard let id = CoreDataHelper.sharedInstance.currentAccount?.identity else {
            Log.error("Getting current user id from Core Data failed")
            return
        }
        for channel in channels {
            if !CoreDataHelper.sharedInstance.doesChannelExist(withGlobalName: channel) {
                FirebaseHelper.sharedInstance.getChannelMembers(channel: channel) { members, error in
                    let newChannelName = members.filter { $0 != id }.first
                    guard error == nil, let name = newChannelName else {
                        Log.error("Getting channel members failed")
                        return
                    }
                    _ = CoreDataHelper.sharedInstance.createChannel(withName: name, globalName: channel)
                    self.tableView.reloadData()
                }
            }
        }
    }

    @IBAction func addChannelTapped(_ sender: Any) {
        let alertController = UIAlertController(title: "Add", message: "Enter username", preferredStyle: .alert)

        alertController.addTextField(configurationHandler: {
            $0.placeholder = "Username"
            $0.delegate = self
            $0.keyboardAppearance = UIKeyboardAppearance.dark
        })

        alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: { _ in
            guard let username = alertController.textFields?.first?.text else {
                return
            }
            self.addChat(withUsername: username)
        }))

        alertController.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler: { _ in }))

        self.present(alertController, animated: true)
    }

    private func addChat(withUsername username: String) {
        guard !username.isEmpty else {
            self.alert("There are no such user")
            return
        }
        let username = username.lowercased()

        guard let currentUser = CoreDataHelper.sharedInstance.currentAccount?.identity else {
            self.alert("Seems like your profile corrupted")
            return
        }
        guard username != currentUser else {
            self.alert("You need to communicate with other people :)")
            return
        }
        guard !CoreDataHelper.sharedInstance.doesChannelExist(withName: username) else {
            self.alert("You already have this channel")
            return
        }

        FirebaseHelper.sharedInstance.doesUserExist(withUsername: username) { exist in
            guard exist else {
                self.alert("There are no such user")
                return
            }

            FirebaseHelper.sharedInstance.createChannel(currentUser: currentUser, user: username) { error in
                guard error == nil else {
                    Log.error("Firebse: creating channel failed with error: (\(error!.localizedDescription)")
                    return
                }

                self.tableView.reloadData()
            }
        }
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
}

extension ChatListController: UITableViewDataSource, UITableViewDelegate {
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: ChatListCell.name) as! ChatListCell

        guard let account = CoreDataHelper.sharedInstance.currentAccount,
            let channels = account.channels?.array as? [Channel] else {
                Log.debug("Can't form row: Core Data account or channels corrupted")
                return cell
        }
        let count = channels.count

        cell.tag = count - indexPath.row - 1
        cell.delegate = self
        cell.usernameLabel.text = channels[count - indexPath.row - 1].name

        return cell
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        guard let account = CoreDataHelper.sharedInstance.currentAccount,
            let channels = account.channels else {
                Log.error("Can't form row: Core Data account or channels corrupted")
                return 0
        }
        return channels.count
    }

    func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }
}

extension ChatListController: CellTapDelegate {
    func didTapOn(_ cell: UITableViewCell) {
        if let username = (cell as! ChatListCell).usernameLabel.text {
            self.view.isUserInteractionEnabled = false
            guard CoreDataHelper.sharedInstance.loadChannel(withName: username) else {
                    Log.error("Channel do not exist in Core Data")
                    self.view.isUserInteractionEnabled = true
                    return
            }
            guard let currentChannel = CoreDataHelper.sharedInstance.currentChannel,
                let globalName = currentChannel.globalName else {
                    Log.error("Get current channel failed")
                    return
            }

            let group = DispatchGroup()
            var err: Error?

            group.enter()
            VirgilHelper.sharedInstance.startSession(with: [username]) { error in
                err = error
                group.leave()
            }

            group.enter()
            FirebaseHelper.sharedInstance.updateMessages(of: globalName) { error in
                err = error
                group.leave()
            }

            group.notify(queue: .main) {
                if let error = err {
                    Log.error(error.localizedDescription)
                } else {
                    self.performSegue(withIdentifier: "goToChat", sender: self)
                }
                self.view.isUserInteractionEnabled = true
            }
        }
    }

    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        super.prepare(for: segue, sender: sender)

        if let chatController = segue.destination as? ChatViewController {
            let pageSize = ChatConstants.chatPageSize

            let dataSource = DataSource(pageSize: pageSize)
            chatController.title = CoreDataHelper.sharedInstance.currentChannel?.name
            chatController.dataSource = dataSource
            chatController.messageSender = dataSource.messageSender
        }
    }
}
