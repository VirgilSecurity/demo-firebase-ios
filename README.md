# demo-firebase-ios
End-to-end encrypted, HIPAA-compliant iOS chat sample app for Firebase. While this is a chat app, you can reuse it in any other apps to protect user data, documents, images using Virgil's end-to-end encryption. Only HIPAA-compliant for chat use-cases.

[Watch setup tutorial on YouTube](https://www.youtube.com/watch?v=6zpzbcm_3I8)

## Clone project

Start with cloning repository to your computer. Open *terminal*, navigate to the folder where you want to store the application and execute
```bash
git clone https://github.com/VirgilSecurity/demo-firebase-ios

cd demo-firebase-ios
```

## Prerequisites
**demo-firebase-ios** uses several modules, including **Virgil SDK** and **Firebase Firestore**. These packages are distributed via CocoaPods.

## Cocoapods

[Cocoapods](https://github.com/CocoaPods/CocoaPods) manages dependencies for your Xcode projects.

You can install Cocoapods with [Homebrew](http://brew.sh/) using the following command:

```bash
brew update
brew install cocoapods
```

## Update dependencies
This example already has Pod file with all required dependencies. All you need to do is to go to the project folder and update these dependencies.

```bash 
pod install
open Firebase\ Chat\ iOS.xcworkspace/
```

## Create Firebase project
Go to the [Firebase console](https://console.firebase.google.com) and if you haven't created a project yet, create one now. If you already have one that you want to use, open it and skip to the **Firebase app setup**

* Select the **Authentication** panel and then click the **Sign In Method** tab.
*  Click **Email/Password** and turn on the **Enable** switch, then click **Save**.
* Select the **Database** panel and then enable **Cloud Firestore**.
  * Click **Rules** and paste:
  ```
  service cloud.firestore {
    match /databases/{database}/documents {
      match /{document=**} {
        allow read, write: if request.auth.uid != null;
      }
    }
  }
  ```
* Click **PUBLISH**.

## Firebase iOS app setup
* In your Firebase project (on the Firebase console), click the **gear icon** -> **Project settings**
* Click**Add app** and choose **Add Firebase to your iOS app**
* Change the bundle ID to your own (or make one up).
* Download the **GoogleService-Info.plist** file from the Project Settings and copy it to the **Firebase Chat iOS** directory of this sample.

## Firebase cloud functions setup

> In order for the app to work, you need to deploy a Firebase function that creates JWT tokens for your authenticated users. If you already deployed this function for either the iOS or Android apps, you don't need to do it again.

* Otherwise, [follow the instructions here](https://github.com/VirgilSecurity/demo-firebase-func)
* Once the function is successfully created, go to the Firebase console -> Functions tab and copy your function's url
* Go to Xcode -> Firebase Chat iOS/Helpers/Virgil/VirgilHelper.swift and change variable jwtEndpoint to:
```
https://YOUR_FUNCTION_URL.cloudfunctions.net/api/generate_jwt
```

## Build and Run
At this point you are ready to build and run the application on your iPhone or Simulator.
* You will surely want to try your new chat app with 2 users. Not sure how to run 2 simulators? Check out [How to run multiple simulators on Xcode 9?](https://stackoverflow.com/questions/44384677/how-to-run-multiple-simulators-on-xcode-9)
* Check out what Firebase sees from your users' chats: Firebase dashboard -> Database -> Channels -> click on the thread -> Messages. This is what the rest of the world is seeing from the chat, without having access to the users' private keys (which we store on their devices).
* Would you like to "zero knowledge" save the user private keys, in case they switch/lose devices? [Sign up for our Private Key Backup preview service](http://eepurl.com/ddbAif)
* You can also watch the whole tutorial on [YouTube](https://www.youtube.com/watch?v=6zpzbcm_3I8).

## Credentials

To build this sample we used the following third-party frameworks:

* [Cloud Firestore](https://firebase.google.com/docs/firestore/) - as a database for messages, users and channels.
* [Cloud Functions](https://firebase.google.com/docs/functions/) - getting jwt.
* [Firebase Authentication](https://firebase.google.com/docs/auth/) - authentication.
* [Virgil SDK](https://github.com/VirgilSecurity/virgil-sdk-x) - managing users' Keys.
* [Virgil Crypto](https://github.com/VirgilSecurity/virgil-foundation-x) - encrypting and decrypting messages.
* [Chatto](https://github.com/badoo/Chatto) - representing UI of chatting.
* [PKHUD](https://github.com/pkluz/PKHUD) - reimplementing Apple's HUD.
