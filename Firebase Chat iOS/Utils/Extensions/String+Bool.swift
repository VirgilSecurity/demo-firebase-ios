//
//  String+Bool.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 10/12/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation

extension String {
    func bool() -> Bool {
        return NSString(string: self).boolValue
    }
}
