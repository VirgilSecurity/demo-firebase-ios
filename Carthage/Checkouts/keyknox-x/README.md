# Virgil KeyKnox Objective-C/Swift SDK

[![Build Status](https://api.travis-ci.org/VirgilSecurity/keyknox-x.svg?branch=master)](https://travis-ci.org/VirgilSecurity/keyknox-x)
[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/VirgilKeyknox.svg)](https://img.shields.io/cocoapods/v/VirgilKeyknox.svg)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![Platform](https://img.shields.io/cocoapods/p/VirgilKeyknox.svg?style=flat)](http://cocoadocs.org/docsets/VirgilKeyknox)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [SDK Features](#sdk-features) | [Install and configure SDK](#install-and-configure-sdk) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>[Virgil Security](https://virgilsecurity.com) provides an SDK which allows you to communicate with Virgil Keyknox Service.
Virgil Keyknox Service allows users to store their sensitive data (such as Private Key) encrypted (with end-to-end encryption) for using and sharing it between different devices.

## SDK Features
- use [Virgil Crypto library][_virgil_crypto]
- use [Virgil SDK][_virgil_sdk]
- upload encrypted sensitive data to Virgil Keyknox Service
- download the data from Virgil Keyknox Service
- update and synchronize the data

## Install and configure SDK

### Installation

Virgil Keyknox SDK is provided as a set of frameworks. These frameworks are distributed via Carthage and CocoaPods. Also in this guide, you find one more package called VirgilCrypto (Virgil Crypto Library) that is used by the SDK to perform cryptographic operations.

Frameworks are available for:
- iOS 9.0+
- macOS 10.10+
- tvOS 9.0+
- watchOS 2.0+

### COCOAPODS

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

To integrate Virgil Keyknox into your Xcode project using CocoaPods, specify it in your *Podfile*:

```bash
target '<Your Target Name>' do
  use_frameworks!

  pod 'VirgilKeyknox', '~> 0.2.0'
end
```

Then, run the following command:

```bash
$ pod install
```

### Carthage

[Carthage](https://github.com/Carthage/Carthage) is a decentralized dependency manager that builds your dependencies and provides you with binary frameworks.

You can install Carthage with [Homebrew](http://brew.sh/) using the following command:

```bash
$ brew update
$ brew install carthage
```

To integrate Virgil Keyknox into your Xcode project using Carthage, create an empty file with name *Cartfile* in your project's root folder and add following lines to your *Cartfile*

```
github "VirgilSecurity/keyknox-x" ~> 0.2.0
```

#### Linking against prebuilt binaries

To link prebuilt frameworks to your app, run following command:

```bash
$ carthage update
```

This will build each dependency or download a pre-compiled framework from github Releases.

##### Building for iOS/tvOS/watchOS

On your application targets’ “General” settings tab, in the “Linked Frameworks and Libraries” section, add following frameworks from the *Carthage/Build* folder inside your project's folder:
 - VirgilSDKKeyknox
 - VirgilSDK
 - VirgilCryptoAPI
 - VirgilCryptoApiImpl
 - VirgilCrypto
 - VSCCrypto

On your application targets’ “Build Phases” settings tab, click the “+” icon and choose “New Run Script Phase.” Create a Run Script in which you specify your shell (ex: */bin/sh*), add the following contents to the script area below the shell:

```bash
/usr/local/bin/carthage copy-frameworks
```

and add the paths to the frameworks you want to use under “Input Files”, e.g.:

```
$(SRCROOT)/Carthage/Build/iOS/VirgilSDKKeyknox.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilSDK.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoAPI.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoAPIImpl.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCrypto.framework
$(SRCROOT)/Carthage/Build/iOS/VSCCrypto.framework
```

##### Building for macOS

On your application target's “General” settings tab, in the “Embedded Binaries” section, drag and drop following frameworks from the Carthage/Build folder on disk:
 - VirgilSDKKeyknox
 - VirgilSDK
 - VirgilCryptoAPI
 - VirgilCryptoApiImpl
 - VirgilCrypto
 - VSCCrypto

Additionally, you'll need to copy debug symbols for debugging and crash reporting on macOS.

On your application target’s “Build Phases” settings tab, click the “+” icon and choose “New Copy Files Phase”.
Click the “Destination” drop-down menu and select “Products Directory”. For each framework, drag and drop corresponding dSYM file.

#### Integrating as subproject

It is possible to use carthage just for fetching the right sources for further integration into your project.
Run following command:

```bash
$ carthage update --no-build
```

This will fetch dependencies into a *Carthage/Checkouts* folder inside your project's folder. Then, drag and drop VirgilCrypto.xcodeproj, VirgilCryptoAPI.xcodeproj, VirgilSDK.xcodeproj and VirgilSDKKeyknox.xcodeproj from corresponding folders inside Carthage/Checkouts folder to your Xcode Project Navigator sidebar.

Next, on your application target's “General” settings tab, in the “Embedded Binaries” section add the following frameworks from subprojects:
 - VirgilSDKKeyknox
 - VirgilSDK
 - VirgilCryptoAPI
 - VirgilCryptoApiImpl
 - VirgilCrypto
 - VSCCrypto

 ### Configure SDK

To begin using Virgil Keyknox SDK you'll need to initialize `SyncKeyStorage` class. This class is responsible for synchronization between Keychain and Keyknox Cloud.
In order to initialize `SyncKeyStorage` class you'll need the following values:
- `accessTokenProvider`
- `public keys` of all devices/users that should have access to data
- `private key` of current device/user
- `identity` of the user (the device can have different users)

```swift
import VirgilSDK
import VirgilSDKKeyknox

// Setup Access Token provider to provide access token for Virgil services
// Check https://github.com/VirgilSecurity/virgil-sdk-x
let accessTokenProvider = ""

// Download public keys of users that should have access to data from Virgil Cards service
// Check https://github.com/VirgilSecurity/virgil-sdk-x
let publicKeys = []

// Load private key from Keychain
let privateKey = ""

let syncKeyStorage = SyncKeyStorage(identity: "Alice",
                                    accessTokenProvider: accessTokenProvider,
                                    publicKeys: publicKeys, privateKey: privateKey)
```

## Docs
Virgil Security has a powerful set of APIs, and the documentation below can get you started today.

* [Virgil Security Documentation][_documentation]

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.slack.com/join/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).

[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto
[_virgil_sdk]: https://github.com/VirgilSecurity/virgil-sdk-x
[_documentation]: https://developer.virgilsecurity.com/
[_dashboard]: https://dashboard.virgilsecurity.com/

