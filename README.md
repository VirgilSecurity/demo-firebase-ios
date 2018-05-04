# demo-firebase-ios
A simple iOS application that demonstrates how the end-to-end encryption works. The application uses firebase as a backend service for authentication and chat messaging.

## Getting Started

Start with cloning repository to your PC. Open *terminal*, navigate to the folder where you want to store the application and execute
```bash
$ git clone https://github.com/VirgilSecurity/demo-firebase-ios

$ cd demo-firebase-ios
```

## Prerequisites
**demo-firebase-ios** uses several modules, including **Virgil SDK** and **Firebase Firestore**. These packages are distributed via CocoaPods.

### Cocoapods

[Cocoapods](https://github.com/CocoaPods/CocoaPods) manages dependencies for your Xcode projects.

You can install Cocoapods with [Homebrew](http://brew.sh/) using the following command:

```bash
$ brew update
$ brew install cocoapods
```

#### Updating dependencies
This example already has Pod file with all required dependencies. All you need to do is to go to the project folder and update these dependencies.

```bash 
$ cd PathToProjectFolder/demo-firebase-ios
$ pod install
$ open Firebase\ Chat\ iOS.xcworkspace/
```

### Firebase set up
* Change bundleID of Xcode project to yours. 
* Go to the [Firebase console](https://console.firebase.google.com) and create your own project.
* Add this sample app to a Firebase project, use the bundleID from the Xcode project.
* Select the **Auth** panel and then click the **Sign In Method** tab.
* Click **Email/Password** and turn on the **Enable** switch, then click **Save**.
* Download the generated GoogleService-Info.plist file, and copy it to the root directory of this sample.

#### Cloud functions
* ...
* Go to the VirgilHelper.swift and change variable jwtEndpoint to yours.

## Build and Run
At this point you are ready to build and run the application on iPhone and/or Simulator.

## Credentials

To build this sample were used next third-party frameworks

* [Cloud Firestore](https://firebase.google.com/docs/firestore/) - as a database for messages, users and channels.
* [Cloud Functions](https://firebase.google.com/docs/functions/) - getting jwt.
* [Firebase Authentication](https://firebase.google.com/docs/auth/) - authentication.
* [Virgil SDK](https://github.com/VirgilSecurity/virgil-sdk-x) - managing users' Keys.
* [Virgil Crypto](https://github.com/VirgilSecurity/virgil-foundation-x) - encrypting and decrypting messages.
* [Chatto](https://github.com/badoo/Chatto) - representing UI of chatting.
* [PKHUD](https://github.com/pkluz/PKHUD) - reimplementing Apple's HUD.
