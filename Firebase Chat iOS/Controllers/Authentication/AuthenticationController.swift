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
        
        VirgilHelper.sharedInstance.reset()
        FirebaseHelper.sharedInstance.channelListListener?.remove()
        FirebaseHelper.sharedInstance.channelListListener = nil
        CoreDataHelper.sharedInstance.setCurrent(account: nil)
        self.idTextField.delegate = self
        self.passwordTextField.delegate = self

        NotificationCenter.default.addObserver(self,
                                               selector: #selector(AuthenticationController.keyboardWillShow(notification:)),
                                               name: Notification.Name.UIKeyboardWillShow,
                                               object: nil)

        NotificationCenter.default.addObserver(self,
                                               selector: #selector(AuthenticationController.keyboardWillHide(notification:)),
                                               name: Notification.Name.UIKeyboardWillHide,
                                               object: nil)
    }

    @objc func keyboardWillShow(notification: Notification) {
        guard let rect = (notification.userInfo?[UIKeyboardFrameEndUserInfoKey] as? NSValue)?.cgRectValue,
            let time = (notification.userInfo?[UIKeyboardAnimationDurationUserInfoKey] as? NSNumber)?.doubleValue else {
                return
        }

        self.bottomConstraint.constant = -rect.height
        UIView.animate(withDuration: time) {
            self.view.layoutIfNeeded()
        }
    }

    @objc func keyboardWillHide(notification: Notification) {
        guard let time = (notification.userInfo?[UIKeyboardAnimationDurationUserInfoKey] as? NSNumber)?.doubleValue else {
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

        Auth.auth().signIn(withEmail: self.makeFakeEmail(from: id), password: password) { authDataResult, error in
            guard let authDataResult = authDataResult, error == nil else {
                Log.error("Sign in failed with error: \(error?.localizedDescription ?? "unknown error")")
                self.alert(error?.localizedDescription ?? "Something went wrong")
                return
            }
            authDataResult.user.getIDToken { token, error in
                guard error == nil, let token = token else {
                    Log.error("Get ID Token with error: \(error?.localizedDescription ?? "unknown error")")
                    self.alert(error?.localizedDescription ?? "Something went wrong")
                    return
                }
                VirgilHelper.sharedInstance.signIn(with: id, token: token) { error in
                    guard error == nil else {
                        Log.error("Virgil sign up failed with error: \(error!.localizedDescription)")
                        self.alert(error!.localizedDescription)
                        return
                    }
                    self.goToChatList()
                }
            }
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

        Auth.auth().createUser(withEmail: self.makeFakeEmail(from: id), password: password) { authDataResult, error in
            guard let authDataResult = authDataResult, error == nil else {
                Log.error("Creating user failed with error: \(error?.localizedDescription ?? "unknown error")")
                self.alert(error?.localizedDescription ?? "Something went wrong")
                return
            }
            authDataResult.user.getIDToken { token, error in
                guard error == nil, let token = token else {
                    Log.error("Get ID Token with error: \(error?.localizedDescription ?? "unknown error")")
                    self.alert(error?.localizedDescription ?? "Something went wrong")
                    return
                }
                VirgilHelper.sharedInstance.signUp(with: id, token: token) { error in
                    guard error == nil else {
                        Log.error("Virgil sign in failed with error: \(error!.localizedDescription)")
                        self.alert(error!.localizedDescription)
                        return
                    }
                    self.goToChatList()
                }
            }
        }
    }

    private func makeFakeEmail(from id: String) -> String {
        return id + "@virgilfirebase.com"
    }

    private func goToChatList() {
        DispatchQueue.main.async {
            PKHUD.sharedHUD.hide(true) { _ in
                let vc = UIStoryboard(name: "Main", bundle: Bundle.main).instantiateInitialViewController() as! UINavigationController

                self.switchNavigationStack(to: vc)
            }
        }
    }

    private func alert(_ message: String) {
        DispatchQueue.main.async {
            PKHUD.sharedHUD.hide { _ in
                let controller = UIAlertController(title: self.title, message: message, preferredStyle: .alert)
                controller.addAction(UIAlertAction(title: "OK", style: .default))
                self.present(controller, animated: true)
            }
        }
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
}

extension AuthenticationController: UITextFieldDelegate {
    func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool {
        guard let text = textField.text else { return true }
        if string.rangeOfCharacter(from: ChatConstants.characterSet.inverted) != nil {
            Log.debug("String contains special characters")
            return false
        }
        let newLength = text.count + string.count - range.length
        return newLength <= ChatConstants.limitLength
    }
}

