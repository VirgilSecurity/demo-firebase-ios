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

    private let userAuthorizer: UserAuthorizer = UserAuthorizer()

    override func viewDidLoad() {
        super.viewDidLoad()
        
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

        userAuthorizer.signIn(identity: id, password: password) { error in
            guard error == nil else {
                self.alert("Sign in failed with error: \(error!.localizedDescription)")
                return
            }

            self.performSegue(withIdentifier: "goToKeyPassword", sender: self)
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

        userAuthorizer.signUp(identity: id, password: password) { error in
            guard error == nil else {
                self.alert("Sign up failed with error: \(error!.localizedDescription)")
                return
            }

            self.performSegue(withIdentifier: "goToKeyPassword", sender: self)
        }
    }

    override func alert(_ message: String) {
        DispatchQueue.main.async {
            PKHUD.sharedHUD.hide(true) { _ in
                super.alert(message)
            }
        }
    }

    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        super.prepare(for: segue, sender: sender)

        if let keyPasswordController = segue.destination as? KeyPasswordController {
            // keyPasswordController.title = CoreDataHelper.sharedInstance.currentChannel?.name
        }
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
}
