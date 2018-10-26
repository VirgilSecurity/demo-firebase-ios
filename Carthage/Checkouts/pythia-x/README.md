# Virgil Pythia Objective-C/Swift SDK

[![Build Status](https://api.travis-ci.org/VirgilSecurity/pythia-x.svg?branch=master)](https://travis-ci.org/VirgilSecurity/pythia-x)
[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/VirgilPythia.svg)](https://cocoapods.org/pods/VirgilPythia) 
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![Platform](https://img.shields.io/cocoapods/p/VirgilPythia.svg?style=flat)](http://cocoadocs.org/docsets/VirgilPythia)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>[Virgil Security](https://virgilsecurity.com) provides an SDK which allows you to communicate with Virgil Pythia Service and implement Pythia protocol in order to generate user's BrainKey. 
**BrainKey** is a user's Private Key which is based on user's password. BrainKey can be easily restored and is resistant to online and offline attacks.

## SDK Features
- communicate with Virgil Pythia Service
- generate user's BrainKey
- use [Virgil Crypto library][_virgil_crypto]

## Installation

Virgil Pythia SDK is provided as a set of frameworks. These frameworks are distributed via Carthage and CocoaPods. Also in this guide, you find one more package called VirgilCrypto (Virgil Crypto Library) that is used by the SDK to perform cryptographic operations.

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

To integrate Virgil Pythia into your Xcode project using CocoaPods, specify it in your *Podfile*:

```bash
target '<Your Target Name>' do
  use_frameworks!

  pod 'VirgilPythia', '~> 0.3.0'
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

To integrate Virgil Pythia into your Xcode project using Carthage, create an empty file with name *Cartfile* in your project's root folder and add following lines to your *Cartfile*

```
github "VirgilSecurity/pythia-x" ~> 0.3.0
```

#### Linking against prebuilt binaries

To link prebuilt frameworks to your app, run following command:

```bash
$ carthage update --no-use-binaries
```

This will build each dependency or download a pre-compiled framework from github Releases.

##### Building for iOS/tvOS/watchOS

On your application targets’ “General” settings tab, in the “Linked Frameworks and Libraries” section, add following frameworks from the *Carthage/Build* folder inside your project's folder:
 - VirgilSDKPythia
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
$(SRCROOT)/Carthage/Build/iOS/VirgilSDKPythia.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilSDK.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoAPI.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoAPIImpl.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCrypto.framework
$(SRCROOT)/Carthage/Build/iOS/VSCCrypto.framework
```

##### Building for macOS

On your application target's “General” settings tab, in the “Embedded Binaries” section, drag and drop following frameworks from the Carthage/Build folder on disk:
 - VirgilSDKPythia
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

This will fetch dependencies into a *Carthage/Checkouts* folder inside your project's folder. Then, drag and drop VirgilCrypto.xcodeproj, VirgilCryptoAPI.xcodeproj, VirgilSDK.xcodeproj and VirgilSDKPythia.xcodeproj from corresponding folders inside Carthage/Checkouts folder to your Xcode Project Navigator sidebar.

Next, on your application target's “General” settings tab, in the “Embedded Binaries” section add the following frameworks from subprojects:
 - VirgilSDKPythia
 - VirgilSDK
 - VirgilCryptoAPI
 - VirgilCryptoApiImpl
 - VirgilCrypto
 - VSCCrypto

## Usage Examples

*PYTHIA* Service can be used directly as a means to generate strong cryptographic keys based on user's **password**. We call these keys the **BrainKeys**. Thus when you need to restore a Private Key you use only user's Password and Pythia Service.

### Generate BrainKey

Use this flow to generate a new BrainKey for a user.

In order to create a user's BrainKey, go through the following operations:
- Register your E2EE application on [Virgil Dashboard][_dashboard] and get your app credentials
- Generate your API key or use available
- Set up **JWT provider** using previously mentioned parameters (**App ID, API key, API key ID**) on the Server side
- Generate JWT token with **user's identity** inside and transmit it to Client side (user's side)
- On Client side set up **access token provider** in order to specify JWT provider
- Setup BrainKey function with access token provider and pass user's password 
- Send BrainKey request to Pythia Service
- Generate keypair based on BrainKey that you've got from Pythia Service and create user's Card 
- Pass user's Card to cardManager
- Publish user's Card that is related to the BrainKey

```swift
import VirgilSDK
import VirgilSDKPythia

/// 1. Specify your JWT provider

// Get generated token from server-side
let authenticatedQueryToServerSide: ((String) -> Void) -> Void = { completion in
    completion("eyJraWQiOiI3MGI0NDdlMzIxZjNhMGZkIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIn0.eyJleHAiOjE1MTg2OTg5MTcsImlzcyI6InZpcmdpbC1iZTAwZTEwZTRlMWY0YmY1OGY5YjRkYzg1ZDc5Yzc3YSIsInN1YiI6ImlkZW50aXR5LUFsaWNlIiwiaWF0IjoxNTE4NjEyNTE3fQ.MFEwDQYJYIZIAWUDBAIDBQAEQP4Yo3yjmt8WWJ5mqs3Yrqc_VzG6nBtrW2KIjP-kxiIJL_7Wv0pqty7PDbDoGhkX8CJa6UOdyn3rBWRvMK7p7Ak")
}

// Setup AccessTokenProvider
let accessTokenProvider = CallbackJwtProvider { tokenContext, completion in
    authenticatedQueryToServerSide { jwtString in
        completion(jwtString, nil)
    }
}

/// 2. Setup BrainKey

let brainKeyContext = BrainKeyContext.makeContext(accessTokenProvider: accessTokenProvider)
let brainKey = BrainKey(context: brainKeyContext)

let keyPair = try! brainKey.generateKeyPair(password: "Your password").startSync().getResult()

/// 3. Publish user's on the Cards Service
let card = try! cardManager.publishCard(privateKey: keyPair.privateKey, publicKey: keyPair.publicKey).startSync().getResult()
```

## Docs
Virgil Security has a powerful set of APIs, and the documentation below can get you started today.

* [Breach-Proof Password][_pythia_use_case] Use Case
* [The Pythia PRF Service](https://eprint.iacr.org/2015/644.pdf) - foundation principles of the protocol
* [Virgil Security Documentation][_documentation]

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.slack.com/join/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).

[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto
[_pythia_use_case]: https://developer.virgilsecurity.com/docs/cs/use-cases/v5/breach-proof-password
[_documentation]: https://developer.virgilsecurity.com/
[_dashboard]: https://dashboard.virgilsecurity.com/

