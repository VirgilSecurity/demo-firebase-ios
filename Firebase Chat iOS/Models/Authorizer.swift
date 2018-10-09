//
//  Authorizer.swift
//  Firebase Chat iOS
//
//  Created by Eugen Pivovarov on 10/9/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import FirebaseAuth

class Authorizer {
    static func signIn(completion: @escaping (Bool, Error?) -> ()) {
        if let user = Auth.auth().currentUser,
            let identity = user.email?.replacingOccurrences(of: "@virgilfirebase.com", with: "") {
            user.getIDToken { token, error in
                guard error == nil, let token = token else {
                    Log.error("Get ID Token with error: \(error?.localizedDescription ?? "unknown error")")
                    completion(false, error)
                    return
                }
                VirgilHelper.initialize(tokenCallback: Authorizer.makeTokenCallback(identity: identity, firebaseToken: token))
                { error in
                    guard error == nil else {
                        Log.error("Virgil init with error: \(error!.localizedDescription)")
                        completion(false, error)
                        return
                    }
                    VirgilHelper.sharedInstance.bootstrapUser { error in
                        guard error == nil else {
                            Log.error("Virgil sign in failed with error: \(error!.localizedDescription)")
                            completion(false, error)
                            return
                        }
                        CoreDataHelper.sharedInstance.setUpAccount(withIdentity: identity)
                        completion(true, nil)
                    }
                }
            }
        } else {
            completion(false, nil)
        }
    }

    static func signIn(identity: String, password: String, completion: @escaping (Error?) -> ()) {
        Auth.auth().signIn(withEmail: self.makeFakeEmail(from: identity), password: password) { authDataResult, error in
            guard let authDataResult = authDataResult, error == nil else {
                completion(error)
                return
            }
            authDataResult.user.getIDToken { token, error in
                guard error == nil, let token = token else {
                    completion(error)
                    return
                }

                self.virgilAuthenticate(identity: identity, password: password, token: token) { error in
                    guard error == nil else {
                        completion(error)
                        return
                    }

                    CoreDataHelper.sharedInstance.setUpAccount(withIdentity: identity)
                }
            }
        }
    }

    static func signUp(identity: String, password: String, completion: @escaping (Error?) -> ()) {
        Auth.auth().createUser(withEmail: self.makeFakeEmail(from: identity), password: password) { authDataResult, error in
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

                self.virgilAuthenticate(identity: identity, password: password, token: token) { error in
                    guard error == nil else {
                        reverseCreatingUser()
                        completion(error)
                        return
                    }

                    CoreDataHelper.sharedInstance.createAccount(withIdentity: identity)
                    FirebaseHelper.sharedInstance.doesUserExist(withUsername: identity) { exist in
                        if !exist {
                            FirebaseHelper.sharedInstance.createUser(identity: identity) { error in
                                guard error == nil else {
                                    Log.error("Firebase: creating user failed with error: \(error!.localizedDescription)")
                                    completion(error)
                                    return
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private static func virgilAuthenticate(identity: String, password: String, token: String, completion: @escaping (Error?) -> ()) {
        VirgilHelper.initialize(tokenCallback: makeTokenCallback(identity: identity, firebaseToken: token)) { error in
            guard error == nil else {
                completion(error)
                return
            }

            VirgilHelper.sharedInstance.bootstrapUser(password: password) { error in
                guard error == nil else {
                    completion(error)
                    return
                }
            }
        }
    }

    private static func makeTokenCallback(identity: String, firebaseToken token: String) -> VirgilHelper.RenewJwtCallback {
        let tokenCallback: VirgilHelper.RenewJwtCallback = { completion in
            let connection = ServiceConnection()
            let jwtRequest = try? ServiceRequest(url: URL(string: AppDelegate.jwtEndpoint)!,
                                                 method: ServiceRequest.Method.post,
                                                 headers: ["Content-Type": "application/json",
                                                           "Authorization": "Bearer " + token],
                                                 params: ["identity": identity])
            guard let request = jwtRequest,
                let jwtResponse = try? connection.send(request),
                let responseBody = jwtResponse.body,
                let json = try? JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any],
                let jwtStr = json?["token"] as? String else {
                    Log.error("Getting JWT failed")
                    completion(nil, VirgilHelper.VirgilHelperError.gettingJwtFailed)
                    return
            }

            completion(jwtStr, nil)
        }

        return tokenCallback
    }

    private static func makeFakeEmail(from id: String) -> String {
        return id + "@virgilfirebase.com"
    }
}
