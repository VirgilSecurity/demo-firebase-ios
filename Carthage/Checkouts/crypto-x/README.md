# Virgil Security Objective-C/Swift Crypto Library

[![Build Status](https://api.travis-ci.org/VirgilSecurity/crypto-x.svg?branch=master)](https://travis-ci.org/VirgilSecurity/crypto-x)
[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/VirgilCrypto.svg)](https://img.shields.io/cocoapods/v/VirgilCrypto.svg)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![Platform](https://img.shields.io/cocoapods/p/VirgilCrypto.svg?style=flat)](http://cocoadocs.org/docsets/VirgilCrypto)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

### [Introduction](#introduction) | [Library purposes](#library-purposes) | [Usage examples](#usage-examples) | [Installation](#installation) | [Docs](#docs) | [License](#license) | [Contacts](#support)

## Introduction
VirgilCrypto is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and an open-source high-level [cryptographic library](https://github.com/VirgilSecurity/virgil-crypto) that allows you to perform all necessary operations for securely storing and transferring data in your digital solutions. Crypto Library is written in C++ and is suitable for mobile and server platforms.

Virgil Security, Inc., guides software developers into the forthcoming security world in which everything will be encrypted (and passwords will be eliminated). In this world, the days of developers having to raise millions of dollars to build a secure chat, secure email, secure file-sharing, or a secure anything have come to an end. Now developers can instead focus on building features that give them a competitive market advantage while end-users can enjoy the privacy and security they increasingly demand.

## Library purposes
* Asymmetric Key Generation
* Encryption/Decryption of data and streams
* Generation/Verification of digital signatures
* PFS (Perfect Forward Secrecy)

## Usage examples

#### Generate a key pair

Generate a Private Key with the default algorithm (EC_X25519):
```swift
import VirgilCryptoApiImpl

let crypto = VirgilCrypto()
let keyPair = try! crypto.generateKeyPair()
```

#### Generate and verify a signature

Generate signature and sign data with a private key:
```swift
import VirgilCryptoApiImpl

let crypto = VirgilCrypto()

// prepare a message
let messageToSign = "Hello, Bob!"
let dataToSign = messageToSign.data(using: .utf8)!

// generate a signature
let signature = try! crypto.generateSignature(of: dataToSign, using: senderPrivateKey)
```

Verify a signature with a public key:
```swift
import VirgilCryptoApiImpl

let crypto = VirgilCrypto()

// verify a signature
let verified = crypto.verifySignature(signature, of: dataToSign, with: senderPublicKey)
```
#### Encrypt and decrypt data

Encrypt Data on a Public Key:

```swift
import VirgilCryptoApiImpl

let crypto = VirgilCrypto()

// prepare a message
let messageToEncrypt = "Hello, Bob!"
let dataToEncrypt = messageToEncrypt.data(using: .utf8)!

// encrypt the message
let encryptedData = try! crypto.encrypt(dataToEncrypt, for: [receiverPublicKey])
```
Decrypt the encrypted data with a Private Key:
```swift
import VirgilCryptoApiImpl

let crypto = VirgilCrypto()

// prepare data to be decrypted
let decryptedData = try! crypto.decrypt(encryptedData, with: receiverPrivateKey)

// decrypt the encrypted data using a private key
let decryptedMessage = String(data: decryptedData, encoding: .utf8)!
```
Need more examples? Visit our [developer documentation](https://developer.virgilsecurity.com/docs/how-to#cryptography).

## Installation

VirgilCrypto is provided as a set of frameworks. These frameworks are distributed via Carthage and CocoaPods.

All frameworks are available for:
- iOS 9.0+
- macOS 10.10+
- tvOS 9.0+
- watchOS 2.0+

### COCOAPODS

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

To integrate VirgilCrypto into your Xcode project using CocoaPods, specify it in your *Podfile*:

```bash
target '<Your Target Name>' do
  use_frameworks!

  pod 'VirgilCryptoApiImpl', '~> 3.2.0'
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

To integrate VirgilSDK into your Xcode project using Carthage, create an empty file with name *Cartfile* in your project's root folder and add following lines to your *Cartfile*

```
github "VirgilSecurity/crypto-x" ~> 3.2.0
```

#### Linking against prebuilt binaries

To link prebuilt frameworks to your app, run following command:

```bash
$ carthage update --no-use-binaries
```

This will build each dependency or download a pre-compiled framework from github Releases.

##### Building for iOS/tvOS/watchOS

On your application target's “General” settings tab, in the “Linked Frameworks and Libraries” section, add following frameworks from the *Carthage/Build* folder inside your project's folder:
 - VirgilCryptoAPI
 - VirgilCryptoApiImpl
 - VirgilCrypto
 - VSCCrypto

On your application target's “Build Phases” settings tab, click the “+” icon and choose “New Run Script Phase”. Create a Run Script in which you specify your shell (ex: */bin/sh*), add the following contents to the script area below the shell:

```bash
/usr/local/bin/carthage copy-frameworks
```

and add the paths to the frameworks you want to use under “Input Files”, e.g.:

```
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoAPI.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoAPIImpl.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCrypto.framework
$(SRCROOT)/Carthage/Build/iOS/VSCCrypto.framework
```

##### Building for macOS

On your application target's “General” settings tab, in the “Embedded Binaries” section, drag and drop following frameworks from the Carthage/Build folder on disk:
 - VirgilCryptoAPI
 - VirgilCryptoApiImpl
 - VirgilCrypto
 - VSCCrypto

Additionally, you'll need to copy debug symbols for debugging and crash reporting on macOS.

On your application target’s “Build Phases” settings tab, click the “+” icon and choose “New Copy Files Phase”.
Click the “Destination” drop-down menu and select “Products Directory”. For each framework, drag and drop the corresponding dSYM file.

#### Integrating as subproject

It is possible to use carthage just for fetching the right sources for further integration into your project.
Run following command:

```bash
$ carthage update --no-build
```

This will fetch dependencies into a *Carthage/Checkouts* folder inside your project's folder. Then, drag and drop VirgilCrypto.xcodeproj and VirgilCryptoAPI.xcodeproj from corresponding folders inside Carthage/Checkouts folder to your Xcode Project Navigator sidebar.

Next, on your application target's “General” settings tab, in the “Embedded Binaries” section add following frameworks from subprojects:
 - VirgilCryptoAPI
 - VirgilCryptoApiImpl
 - VirgilCrypto
 - VSCCrypto

## Docs
- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto)
- [More usage examples](https://developer.virgilsecurity.com/docs/how-to#cryptography)

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://join.slack.com/t/VirgilSecurity/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).
