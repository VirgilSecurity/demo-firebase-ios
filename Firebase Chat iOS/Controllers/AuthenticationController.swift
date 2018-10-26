//
//  Authentication.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/29/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import UIKit
import Firebase
import PKHUD

class AuthenticationController: ViewController {
    @IBOutlet weak var idTextField: UITextField!
    @IBOutlet weak var passwordTextField: UITextField!
    @IBOutlet weak var bottomConstraint: NSLayoutConstraint!

    override func viewDidLoad() {
        super.viewDidLoad()

        try? VirgilHelper.sharedInstance?.cleanUp()
        FirebaseHelper.sharedInstance.channelListListener?.remove()
        FirebaseHelper.sharedInstance.channelListListener = nil
        CoreDataHelper.sharedInstance.setCurrent(account: nil)
        self.idTextField.delegate = self
        self.passwordTextField.delegate = self

        NotificationCenter.default.addObserver(self,
                                               selector: #selector(AuthenticationController.keyboardWillShow(notification:)),
                                               name: UIResponder.keyboardWillShowNotification,
                                               object: nil)

        NotificationCenter.default.addObserver(self,
                                               selector: #selector(AuthenticationController.keyboardWillHide(notification:)),
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

    @IBAction func backgroundTap(_ sender: Any) {
        self.view.endEditing(true)
    }

    @IBAction func signInButtonPressed(_ sender: Any) {
        guard let id = self.idTextField.text?.lowercased() else {
            self.idTextField.becomeFirstResponder()
            return
        }
        guard let password = self.passwordTextField.text else {
            self.passwordTextField.becomeFirstResponder()
            return
        }
        self.view.endEditing(true)

        PKHUD.sharedHUD.contentView = PKHUDProgressView()
        PKHUD.sharedHUD.show()

        Authorizer.signIn(identity: id, password: password) { error in
            guard error == nil else {
                self.alert("Sign in failed with error: \(error!.localizedDescription)")
                return
            }
            self.goToChatList()
        }
    }

    @IBAction func signUpButtonPressed(_ sender: Any) {
        guard let id = self.idTextField.text?.lowercased() else {
            self.idTextField.becomeFirstResponder()
            return
        }

        guard let password = self.passwordTextField.text else {
            self.passwordTextField.becomeFirstResponder()
            return
        }
        self.view.endEditing(true)

        PKHUD.sharedHUD.contentView = PKHUDProgressView()
        PKHUD.sharedHUD.show()

        Authorizer.signUp(identity: id, password: password) { error in
            guard error == nil else {
                self.alert("Sign up failed with error: \(error!.localizedDescription)")
                return
            }
            self.goToChatList()
        }
    }

    override func alert(_ message: String) {
        DispatchQueue.main.async {
            PKHUD.sharedHUD.hide(true) { _ in
                super.alert(message)
            }
        }
    }

    private func goToChatList() {
        DispatchQueue.main.async {
            PKHUD.sharedHUD.hide(true) { _ in
                let vc = UIStoryboard(name: "TabBar", bundle: Bundle.main).instantiateInitialViewController() as! UINavigationController

                self.switchNavigationStack(to: vc)
            }
        }
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
}
