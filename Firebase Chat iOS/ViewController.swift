//
//  ViewController.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/10/18.
//  Copyright © 2018 Eugen Pivovarov. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
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
}
