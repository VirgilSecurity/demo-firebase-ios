//
//  KeyPasswordController.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 10/30/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import UIKit
import PKHUD

class KeyPasswordController: ViewController {
    @IBOutlet weak var passwordTextField: UITextField!
    @IBOutlet weak var bottomConstraint: NSLayoutConstraint!
    
    override func viewDidLoad() {
        super.viewDidLoad()

        NotificationCenter.default.addObserver(self,
                                               selector: #selector(KeyPasswordController.keyboardWillShow(notification:)),
                                               name: UIResponder.keyboardWillShowNotification,
                                               object: nil)

        NotificationCenter.default.addObserver(self,
                                               selector: #selector(KeyPasswordController.keyboardWillHide(notification:)),
                                               name: UIResponder.keyboardWillHideNotification,
                                               object: nil)
    }

    @objc func keyboardWillShow(notification: Notification) {
        guard let rect = (notification.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? NSValue)?.cgRectValue,
            let time = (notification.userInfo?[UIResponder.keyboardAnimationDurationUserInfoKey] as? NSNumber)?.doubleValue else {
                return
        }

        self.bottomConstraint.constant = -rect.height
        UIView.animate(withDuration: time) {
            self.view.layoutIfNeeded()
        }
    }

    @objc func keyboardWillHide(notification: Notification) {
        guard let time = (notification.userInfo?[UIResponder.keyboardAnimationDurationUserInfoKey] as? NSNumber)?.doubleValue else {
            return
        }

        self.bottomConstraint.constant = 0
        UIView.animate(withDuration: time) {
            self.view.layoutIfNeeded()
        }
    }

    @IBAction func confirmTapped(_ sender: Any) {
        guard let password = self.passwordTextField.text else {
            self.passwordTextField.becomeFirstResponder()
            return
        }
        self.view.endEditing(true)

        PKHUD.sharedHUD.contentView = PKHUDProgressView()
        PKHUD.sharedHUD.show()

        E3KitHelper.sharedInstance.backupPrivateKey(password: password) { error in
            guard error == nil else {
                self.alert("Setting key password failed with error: \(error!.localizedDescription)")
                return
            }
            self.goToChatList()
        }
    }

    @IBAction func laterTapped(_ sender: Any) {
        self.goToChatList()
    }

    private func goToChatList() {
        PKHUD.sharedHUD.hide(true) { _ in
            let vc = UIStoryboard(name: "TabBar", bundle: Bundle.main).instantiateInitialViewController() as! UINavigationController

            self.switchNavigationStack(to: vc)
        }
    }

    override func alert(_ message: String) {
        DispatchQueue.main.async {
            PKHUD.sharedHUD.hide(true) { _ in
                super.alert(message)
            }
        }
    }
}
