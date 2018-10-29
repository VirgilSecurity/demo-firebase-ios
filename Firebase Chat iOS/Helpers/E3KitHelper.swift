//
//  E3KitHelper.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 4/13/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import VirgilE3Kit

class E3KitHelper {
    static private(set) var sharedInstance: EThree!

    public static func initialize(tokenCallback: @escaping EThree.RenewJwtCallback,
                                  completion: @escaping (Error?) -> ()) {
        EThree.initialize(tokenCallback: tokenCallback) { eThree, error in
            self.sharedInstance = eThree
            
            completion(error)
        }
    }

    /// Makes SHA256 hash
    ///
    /// - Parameter string: String, from which to make hash
    /// - Returns: hex encoded String with SHA256 hash
    static func makeHash(from string: String) -> String? {
        guard let data = string.data(using: .utf8) else {
            Log.error("String to data failed")
            return nil
        }
        
        return E3KitHelper.sharedInstance.crypto.computeHash(for: data, using: .SHA256).hexEncodedString()
    }
}
