//
//  UserAuthorizer.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 10/9/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import FirebaseAuth
import VirgilE3Kit
import VirgilSDK

class UserAuthorizer {
    func signIn(completion: @escaping (Bool) -> ()) {
        if let user = Auth.auth().currentUser, let email = user.email {
            let identity = email.replacingOccurrences(of: "@virgilfirebase.com", with: "")
            user.getIDToken { token, error in
                guard error == nil, let token = token else {
                    Log.error("Get ID Token with error: \(error?.localizedDescription ?? "unknown error")")
                    completion(false)
                    return
                }

                let tokenCallback = self.makeTokenCallback(identity: identity, firebaseToken: token)
                E3KitHelper.initialize(tokenCallback: tokenCallback) { error in
                    guard error == nil else {
                        Log.error("Virgil init with error: \(error!.localizedDescription)")
                        completion(false)
                        return
                    }
                    CoreDataHelper.sharedInstance.setUpAccount(withIdentity: identity)
                    FirestoreHelper.sharedInstance.setUpUser(identity: identity,
                                                             completion: { completion($0 == nil ? true : false) })

                    completion(true)
                }
            }
        } else {
            completion(false)
        }
    }

    func signIn(identity: String, password: String, completion: @escaping (Error?) -> ()) {
        Auth.auth().signIn(withEmail: identity, password: password) { authDataResult, error in
            guard let authDataResult = authDataResult, error == nil else {
                completion(error)
                return
            }
            authDataResult.user.getIDToken { token, error in
                guard error == nil, let token = token else {
                    completion(error)
                    return
                }

                self.setUpVirgil(identity: identity, password: password, token: token) { error in
                    guard error == nil else {
                        completion(error)
                        return
                    }
                    CoreDataHelper.sharedInstance.setUpAccount(withIdentity: identity)
                    FirestoreHelper.sharedInstance.setUpUser(identity: identity, completion: completion)

                    completion(nil)
                }
            }
        }
    }

    func signUp(identity: String, password: String, completion: @escaping (Error?) -> ()) {
        Auth.auth().createUser(withEmail: identity, password: password) { authDataResult, error in
            guard let authDataResult = authDataResult, error == nil else {
                completion(error)
                return
            }

            let reverseCreatingUser = {
                authDataResult.user.delete { err in
                    if let err = err {
                        Log.error("User deletion failed after signUp with error: \(err.localizedDescription)")
                    }
                }
            }

            authDataResult.user.getIDToken { token, error in
                guard error == nil, let token = token else {
                    reverseCreatingUser()
                    completion(error)
                    return
                }

                self.setUpVirgil(identity: identity, password: password, token: token) { error in
                    guard error == nil else {
                        reverseCreatingUser()
                        completion(error)
                        return
                    }

                    CoreDataHelper.sharedInstance.createAccount(withIdentity: identity)
                    FirestoreHelper.sharedInstance.setUpUser(identity: identity, completion: completion)
                }
            }
        }
    }

    // MARK: - Private API

    private func setUpVirgil(identity: String, password: String, token: String, completion: @escaping (Error?) -> ()) {
        let tokenCallback = makeTokenCallback(identity: identity, firebaseToken: token)
        E3KitHelper.initialize(tokenCallback: tokenCallback) { error in
            guard error == nil else {
                completion(error)
                return
            }

            E3KitHelper.sharedInstance.bootstrap(password: password) { error in
                completion(error)
            }
        }
    }

    private func makeTokenCallback(identity: String, firebaseToken token: String) -> EThree.RenewJwtCallback {
        let headers = ["Content-Type": "application/json",
                       "Authorization": "Bearer " + token]

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let connection = HttpConnection()
            let requestURL = URL(string: AppDelegate.jwtEndpoint)!
            let request = Request(url: requestURL, method: .post, headers: headers)

            guard let jwtResponse = try? connection.send(request),
                let responseBody = jwtResponse.body,
                let json = try? JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any],
                let jwtStr = json?["token"] as? String else {
                    Log.error("Getting JWT failed")
                    completion(nil, NSError())
                    return
            }

            completion(jwtStr, nil)
        }

        return tokenCallback
    }
}
