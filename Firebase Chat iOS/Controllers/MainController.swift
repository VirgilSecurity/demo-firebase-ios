//
//  MainController.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/12/18.
//  Copyright © 2018 Eugen Pivovarov. All rights reserved.
//

import Foundation
import FirebaseAuthUI
import FirebaseGoogleAuthUI

class MainController: ViewController, FUIAuthDelegate {
    var authUI: FUIAuth?
    @IBOutlet weak var tableView: UITableView!

    override func viewDidLoad() {
        authUI = FUIAuth.defaultAuthUI()!
        authUI?.delegate = self

        self.tableView.register(UINib(nibName: ChatListCell.name, bundle: Bundle.main),
                                forCellReuseIdentifier: ChatListCell.name)
        self.tableView.rowHeight = 94
        self.tableView.tableFooterView = UIView(frame: .zero)
        self.tableView.backgroundColor = UIColor(rgb: 0x2B303B)
        self.tableView.dataSource = self

        NotificationCenter.default.addObserver(self,
                                               selector: #selector(MainController.updateCoreDataChannels(notification:)),
                                               name: Notification.Name(rawValue: FirebaseHelper.Notifications.ChannelAdded.rawValue),
                                               object: nil)
    }

    override func viewWillAppear(_ animated: Bool) {
        self.authorize()
    }

    private func authorize() {
        guard let user = authUI?.auth?.currentUser, let email = user.email else {
            authUI?.providers = [FUIGoogleAuth()]
            present(authUI!.authViewController(), animated: true, completion: nil)
            return
        }
        self.updateUser(email: email)
    }

    func authUI(_ authUI: FUIAuth, didSignInWith user: User?, error: Error?) {
        guard let _ = user, error == nil, let email = user?.email else {
            Log.error("Signing in failed: \(error?.localizedDescription ?? "unknown error")")
            return
        }
        Log.debug("Signed in")
        self.updateUser(email: email)
    }

    private func updateUser(email: String) {
        if !CoreDataHelper.sharedInstance.loadAccount(withIdentity: email) {
            CoreDataHelper.sharedInstance.createAccount(withIdentity: email, exportedCard: "FIXME") {}
        }

        FirebaseHelper.sharedInstance.doesUserExist(withUsername: email) { exist in
            if !exist {
                FirebaseHelper.sharedInstance.createUser(email: email) { error in
                    guard error == nil else {
                        Log.error("Firebase: creating user failedwith error: \(error?.localizedDescription ?? "unknown error")")
                        self.alert(withTitle: "Creating user failed")
                        return
                    }
                    FirebaseHelper.sharedInstance.setUpListener(email: email)
                }
            } else {
                self.syncFirebaseWithCoreDataChannels(email: email) {
                    if FirebaseHelper.sharedInstance.listener == nil {
                        FirebaseHelper.sharedInstance.setUpListener(email: email)
                    }
                }
                self.tableView.reloadData()
            }
        }
    }

    private func syncFirebaseWithCoreDataChannels(email: String, completion: @escaping () -> ()) {
        FirebaseHelper.sharedInstance.getChannels(of: email) { channels, error in
            guard error == nil else {
                return
            }
            self.updateCoreDataChannels(channels: channels) {
                completion()
            }
        }
    }

    private func updateCoreDataChannels(channels: [String], completion: @escaping () -> ()?) {
        guard let user = authUI?.auth?.currentUser, let email = user.email else {
            Log.error("get current user failed")
            return
        }
        for channel in channels {
            if !CoreDataHelper.sharedInstance.doesChannelExist(withGlobalName: channel) {
                FirebaseHelper.sharedInstance.getChannelMembers(channel: channel) { members, error in
                    let newChannelName = members.filter { $0 != email }.first
                    guard error == nil, let name = newChannelName else {
                        Log.error("Getting channel members failed")
                        return
                    }
                    _ = CoreDataHelper.sharedInstance.createChannel(withName: name, globalName: channel, card: "FIXME")
                    self.tableView.reloadData()
                    completion()
                }
            }
        }
    }

    @objc func updateCoreDataChannels(notification: Notification) {
        guard  let userInfo = notification.userInfo,
            let channels = userInfo["channels"] as? [String] else {
                Log.error("processing new channel failed")
                return
        }
        self.updateCoreDataChannels(channels: channels) {
            return
        }
    }
    
    @IBAction func signOutTapped(_ sender: Any) {
        try! authUI?.signOut()
        FirebaseHelper.sharedInstance.listener?.remove()
        CoreDataHelper.sharedInstance.setCurrent(account: nil)
        self.tableView.reloadData()
        self.authorize()
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
        let username = username.lowercased()

        guard let currentUser = CoreDataHelper.sharedInstance.currentAccount?.identity else {
            self.alert(withTitle: "Seems like your profile corrupted")
            return
        }
        guard username != currentUser else {
            self.alert(withTitle: "You need to communicate with other people :)")
            return
        }
        guard !CoreDataHelper.sharedInstance.doesChannelExist(withName: username) else {
            self.alert(withTitle: "You already have this channel")
            return
        }

        FirebaseHelper.sharedInstance.doesUserExist(withUsername: username) { exist in
            guard exist else {
                self.alert(withTitle: "There are no such user")
                return
            }
            guard let globalName = FirebaseHelper.makeChannelName(currentUser, username) else {
                return
            }
            _ = CoreDataHelper.sharedInstance.createChannel(withName: username, globalName: globalName, card: "FIXME")

            FirebaseHelper.sharedInstance.createChannel(currentUser: currentUser, user: username) { error in
                guard error == nil else {
                    Log.error("Firebse: creating channel failed with error: (\(error?.localizedDescription ?? "unknown error")")
                    return
                }

                self.tableView.reloadData()
            }
        }
    }

    private func alert(withTitle: String) {
        let alert = UIAlertController(title: title, message: withTitle, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))

        self.present(alert, animated: true)
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
}


extension MainController: UITableViewDataSource, UITableViewDelegate {
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: ChatListCell.name) as! ChatListCell

        guard let account = CoreDataHelper.sharedInstance.currentAccount,
            let channels = account.channels?.array as? [Channel] else {
                Log.error("Can't form row: Core Data account or channels corrupted")
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

    func tableView(_ tableView: UITableView, willDisplay cell: UITableViewCell, forRowAt indexPath: IndexPath) {
        cell.backgroundColor = UIColor(rgb: 0x2B303B)
    }
}

extension MainController: CellTapDelegate {
    func didTapOn(_ cell: UITableViewCell) {
//        if let username = (cell as! ChatListCell).usernameLabel.text {
//            TwilioHelper.sharedInstance.setChannel(withUsername: (username))
//
//            guard CoreDataHelper.sharedInstance.loadChannel(withName: username),
//                let channel = CoreDataHelper.sharedInstance.currentChannel,
//                let exportedCard = channel.card
//                else {
//                    Log.error("Channel do not exist in Core Data")
//                    return
//            }
//
//            VirgilHelper.sharedInstance.setChannelCard(exportedCard)
//
//            self.performSegue(withIdentifier: "goToChat", sender: self)
    }

    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
//        super.prepare(for: segue, sender: sender)

//        if let chatController = segue.destination as? ChatViewController {
//            let pageSize = ChatConstants.chatPageSize
//
//            let dataSource = DataSource(pageSize: pageSize)
//            chatController.title = TwilioHelper.sharedInstance.getCompanion(ofChannel: TwilioHelper.sharedInstance.currentChannel)
//            chatController.dataSource = dataSource
//            chatController.messageSender = dataSource.messageSender
//        }
    }
}

extension MainController: UITextFieldDelegate {
    func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool {
        guard let text = textField.text else { return true }
        if string.rangeOfCharacter(from: ChatConstants.characterSet.inverted) != nil {
            Log.debug("string contains special characters")
            return false
        }
        let newLength = text.count + string.count - range.length
        return newLength <= ChatConstants.limitLength
    }
}
