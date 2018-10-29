//
//  SettingsViewController.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 11/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import UIKit
import Firebase

class SettingsViewController: ViewController {
    @IBOutlet weak var letterLabel: UILabel!
    @IBOutlet weak var usernameLabel: UILabel!
    @IBOutlet weak var tableView: UITableView!

    override func viewDidLoad() {
        super.viewDidLoad()

        self.tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")

        self.tableView.tableFooterView = UIView(frame: .zero)
        self.tableView.delegate = self
        self.tableView.dataSource = self

        self.usernameLabel.text = CoreDataHelper.sharedInstance.currentAccount?.identity
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
    }
}

extension SettingsViewController: UITableViewDelegate {
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)

        if indexPath.section == 0 {
            let alert = UIAlertController(title: nil, message: nil, preferredStyle: .actionSheet)
            alert.addAction(UIAlertAction(title: "Logout", style: .destructive) { _ in
                try? Auth.auth().signOut()

                try? E3KitHelper.sharedInstance?.cleanUp()

                FirestoreHelper.sharedInstance.channelListListener?.remove()
                FirestoreHelper.sharedInstance.channelListListener = nil

                CoreDataHelper.sharedInstance.setCurrent(account: nil)
                
                let vc = UIStoryboard(name: "Authentication", bundle: Bundle.main).instantiateInitialViewController() as! UINavigationController
                self.switchNavigationStack(to: vc)
            })

            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))

            self.present(alert, animated: true)
        }
    }

    func tableView(_ : UITableView, heightForFooterInSection section: Int) -> CGFloat {
        return 10
    }
}

extension SettingsViewController: UITableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return 1
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        let colorView = UIView()
        cell.selectedBackgroundView = colorView

        if indexPath.section == 0 {
            cell.textLabel?.text = "Logout"
            cell.textLabel?.textColor = UIColor(rgb: 0x9E3621)
            cell.accessoryType = .none
        }

        return cell
    }

    func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }
}
