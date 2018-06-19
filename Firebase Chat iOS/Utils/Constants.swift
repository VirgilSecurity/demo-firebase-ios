//
//  Constants.swift
//  VirgilSigner iOS
//
//  Created by Oleksandr Deundiak on 9/25/17.
//  Copyright © 2017 Virgil Security. All rights reserved.
//

import UIKit

class ChatConstants {
    static let limitLength = 32
    static let characterSet = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,-()/='+:?!%&*<>;{}#_")
    static let chatMaxCharectersCount: UInt = 1000
    static let chatPageSize = 10000
}

class UIConstants {
    static let TransitionAnimationDuration: TimeInterval = 0.3
}
