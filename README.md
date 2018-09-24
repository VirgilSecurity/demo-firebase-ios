# demo-firebase-ios
End-to-end encrypted, HIPAA-compliant iOS chat sample app for Firebase. While this is a chat app, you can reuse it in any other apps to protect user data, documents, images using Virgil's end-to-end encryption. Only HIPAA-compliant for chat use-cases.

[Watch setup tutorial on YouTube](https://www.youtube.com/watch?v=6zpzbcm_3I8)

## Clone project

Start with cloning repository to your computer. Open *terminal*, navigate to the folder where you want to store the application and execute
```bash
git clone https://github.com/VirgilSecurity/demo-firebase-ios
cd demo-firebase-ios
```

## Let's set up your Firebase account for the app
In order for the app to work, you need to deploy a Firebase function that gives out JWT tokens for your authenticated users. You'll also need to create a Firestore database with a specific rule set.

> You only need to do this once - if you did it already earlier or for your Android or JavaScript clients, don't need to do it again. 

* **[Follow instructions here](https://github.com/VirgilSecurity/demo-firebase-func)**

## Add your Firebase function URL and Firebase project config to your app

* **Copy your new Firebase function's URL**: go to the Firebase console -> your project -> Functions tab and copy your new function's url
* **Go to Xcode -> Firebase Chat iOS/Helpers/Virgil/VirgilHelper.swift and change variable jwtEndpoint to**:
```
https://YOUR_FUNCTION_URL.cloudfunctions.net/api/generate_jwt
```
* Go back to your project's page in Firebase console, click the **gear icon** -> **Project settings**
* Click **Add app** and choose **"iOS: Add Firebase to your iOS app"**
* Change the bundle ID to your own (or make one up), click **Register app**
* **Download GoogleService-Info.plist** into the **Firebase Chat iOS** directory of this sample.

## Install dependencies
The sample app uses several modules, including Virgil SDK and Firebase Firestore.

> **Cocoapods** manages dependencies for your Xcode projects. If you don't have it, install it with [Homebrew](http://brew.sh/):
 ```bash
 brew update
 brew install cocoapods
 ```

* **Update dependencies**
The sample already has a Pod file with all required dependencies: run the following commands to update these dependencies:
```bash 
pod install
open Firebase\ Chat\ iOS.xcworkspace/
```

## Build and Run
At this point you are ready to build and run the application on your iPhone or Simulator.

> You will surely want to try your new chat app with 2 users. Not sure how to run 2 simulators? Check out [How to run multiple simulators on Xcode 9?](https://stackoverflow.com/questions/44384677/how-to-run-multiple-simulators-on-xcode-9)

> Remember, the app deletes messages right after delivery (it's a HIPAA requirement to meet the conduit exception). If you want to see encrypted messages in your Firestore database, run only 1 app instance, send a message to your chat partner and check Firestore DB's contents before opening the other user's app to receive the message. If you don't want to implement this behavior in your own app, you can remove it from this sample.
