//
//  ViewController.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/10/18.
//  Copyright © 2018 Eugen Pivovarov. All rights reserved.
//

import UIKit

class ViewController: UIViewController, UITextFieldDelegate {
    deinit {
        Log.debug(self.description)
    }

    func switchNavigationStack(to navigationController: UINavigationController) {
        let window = UIApplication.shared.keyWindow!

        UIView.transition(with: window, duration: UIConstants.TransitionAnimationDuration, options: .transitionCrossDissolve, animations: {
            window.rootViewController = navigationController
        })
    }

    var isRootViewController: Bool {
        return self.navigationController?.viewControllers.count ?? 1 == 1
    }

    func alert(_ message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))

        self.present(alert, animated: true)
    }

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
