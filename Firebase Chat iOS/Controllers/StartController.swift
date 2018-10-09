//
//  StartController.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 6/19/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import UIKit
import PKHUD
import Firebase

class StartViewController: ViewController {
    static let name = "Start"

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)

        PKHUD.sharedHUD.contentView = PKHUDProgressView()
        PKHUD.sharedHUD.show()

        Authorizer.signIn { signed, error in
            if signed {
                self.goToChatList()
            } else {
                self.goToLogin()
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

    private func goToLogin() {
        DispatchQueue.main.async {
            PKHUD.sharedHUD.hide(true) { _ in
                let vc = UIStoryboard(name: "Authentication", bundle: Bundle.main).instantiateInitialViewController() as! UINavigationController

                self.switchNavigationStack(to: vc)
            }
        }
    }
}
