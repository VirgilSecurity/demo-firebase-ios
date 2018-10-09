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

        try? VirgilHelper.sharedInstance.logout()
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
                
                VirgilHelper.initialize(tokenCallback: FirebaseHelper.makeTokenCallback(id: id, firebaseToken: token)) { error in
                    guard error == nil else {
                        Log.error("Virgil init with error: \(error!.localizedDescription)")
                        self.alert(error!.localizedDescription)
                        return
                    }
                    VirgilHelper.sharedInstance.bootstrapUser(password: password) { error in
                        guard error == nil else {
                            Log.error("Virgil sign in failed with error: \(error!.localizedDescription)")
                            self.alert(error!.localizedDescription)
                            return
                        }

                        CoreDataHelper.sharedInstance.setUpAccount(withIdentity: id)
                        self.goToChatList()
                    }
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
                    authDataResult.user.delete { _ in }
                    return
                }

                VirgilHelper.initialize(tokenCallback: FirebaseHelper.makeTokenCallback(id: id, firebaseToken: token)) { error in
                    guard error == nil else {
                        Log.error("Virgil init up failed with error: \(error!.localizedDescription)")
                        self.alert(error!.localizedDescription)
                        authDataResult.user.delete { _ in }
                        return
                    }

                    VirgilHelper.sharedInstance.bootstrapUser(password: password) { error in
                        guard error == nil else {
                            Log.error("Virgil sign up failed with error: \(error!.localizedDescription)")
                            self.alert(error!.localizedDescription)
                            authDataResult.user.delete { _ in }
                            return
                        }

                        CoreDataHelper.sharedInstance.createAccount(withIdentity: id)
                        FirebaseHelper.sharedInstance.doesUserExist(withUsername: id) { exist in
                            if !exist {
                                FirebaseHelper.sharedInstance.createUser(identity: id) { error in
                                    guard error == nil else {
                                        Log.error("Firebase: creating user failed with error: \(error?.localizedDescription ?? "unknown error")")
                                        self.alert(error?.localizedDescription ?? "Something went wrong")
                                        return
                                    }

                                    self.goToChatList()
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    override func alert(_ message: String) {
        DispatchQueue.main.async {
            PKHUD.sharedHUD.hide(true) { _ in
                super.alert(message)
            }
        }
    }

    private func makeFakeEmail(from id: String) -> String {
        return id + "@virgilfirebase.com"
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
