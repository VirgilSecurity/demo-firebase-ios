# Virgil E3Kit Objective-C/Swift SDK

[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![Platform](https://img.shields.io/cocoapods/p/VirgilSDK.svg?style=flat)](http://cocoadocs.org/docsets/VirgilSDK)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides an SDK which symplifies work with Virgil services and presents easy to use API for adding security to any application. In a few simple steps you can setup user encryption with multidevice support.

## SDK Features
- multidevice support
- manage users' Public Keys


## Installation

Virgil E3Kit is provided as a set of frameworks. These frameworks are distributed via Carthage.  Also in this guide, you find one more package called VirgilCrypto (Virgil Crypto Library) that is used by the E3Kit to perform cryptographic operations.

All frameworks are available for:
- iOS 9.0+
- macOS 10.10+
- tvOS 9.0+
- watchOS 2.0+

### Carthage

[Carthage](https://github.com/Carthage/Carthage) is a decentralized dependency manager that builds your dependencies and provides you with binary frameworks.

You can install Carthage with [Homebrew](http://brew.sh/) using the following command:

```bash
$ brew update
$ brew install carthage
```

To integrate VirgilSDK into your Xcode project using Carthage, create an empty file with name *Cartfile* in your project's root folder and add following lines to your *Cartfile*

```
github "VirgilSecurity/e3kit-x" ~> 0.1.0
```

#### Linking against prebuilt binaries

To link prebuilt frameworks to your app, run following command:

```bash
$ carthage update --no-use-binaries
```

This will build each dependency or download a pre-compiled framework from github Releases.

##### Building for iOS/tvOS/watchOS

On your application targets’ “General” settings tab, in the “Linked Frameworks and Libraries” section, add following frameworks from the *Carthage/Build* folder inside your project's folder:
 - VirgilSDK
 - VirgilCryptoAPI
 - VirgilCryptoApiImpl
 - VirgilCrypto
 - VSCCrypto
 - VirgilPythiaSDK
 - VirgilKeyknoxSDK

On your application targets’ “Build Phases” settings tab, click the “+” icon and choose “New Run Script Phase.” Create a Run Script in which you specify your shell (ex: */bin/sh*), add the following contents to the script area below the shell:

```bash
/usr/local/bin/carthage copy-frameworks
```

and add the paths to the frameworks you want to use under “Input Files”, e.g.:

```
$(SRCROOT)/Carthage/Build/iOS/VirgilSDK.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoAPI.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoAPIImpl.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCrypto.framework
$(SRCROOT)/Carthage/Build/iOS/VSCCrypto.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilPythiaSDK.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilKeyknoxSDK.framework
```

##### Building for macOS

On your application target's “General” settings tab, in the “Embedded Binaries” section, drag and drop following frameworks from the Carthage/Build folder on disk:
 - VirgilSDK
 - VirgilCryptoAPI
 - VirgilCryptoApiImpl
 - VirgilCrypto
 - VSCCrypto
 - VirgilPythiaSDK
 - VirgilKeyknoxSDK

Additionally, you'll need to copy debug symbols for debugging and crash reporting on macOS.

On your application target’s “Build Phases” settings tab, click the “+” icon and choose “New Copy Files Phase”.
Click the “Destination” drop-down menu and select “Products Directory”. For each framework, drag and drop corresponding dSYM file.

#### Integrating as subproject

It is possible to use carthage just for fetching the right sources for further integration into your project.
Run following command:

```bash
$ carthage update --no-build
```

This will fetch dependencies into a *Carthage/Checkouts* folder inside your project's folder. Then, drag and drop VirgilCrypto.xcodeproj, VirgilCryptoAPI.xcodeproj and VirgilSDK.xcodeproj from corresponding folders inside Carthage/Checkouts folder to your Xcode Project Navigator sidebar.

Next, on your application target's “General” settings tab, in the “Embedded Binaries” section add the following frameworks from subprojects:
 - VirgilSDK
 - VirgilCryptoAPI
 - VirgilCryptoApiImpl
 - VirgilCrypto
 - VSCCrypto
 - VirgilPythiaSDK
 - VirgilKeyknoxSDK


#### Bootstrap User
Use the following lines of code to authenticate user.

```swift
import VirgilE3Kit

// initialize E3Kit
EThree.initialize(tokenCallback) { eThree, error in 
    guard let eThree = eThree, error == nil else {
      // error handling here
    }
    eThree.bootstrap(password: password) { error in 
        // done
    }
}
```

#### Encrypt & decrypt

Virgil E3Kit lets you use a user's Private key and his or her Public Keys to sign, then encrypt text.

```swift
import VirgilE3Kit

// prepare a message
let messageToEncrypt = "Hello, Bob!"

// initialize E3Kit
EThree.initialize(tokenCallback) { eThree, error in 
    // Authenticate user 
    eThree!.bootstrap(password: password) { error in 
        // Search user's publicKeys to encrypt for
        eThree!.lookUpPublicKeys(of: ["Alice", "Den"]) { publicKeys, errors in 
            // encrypt text
            let encryptedMessage = try! eThree.encrypt(messageToEncrypt, for: publicKeys)
        }
    }
}
```

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.slack.com/join/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).

[_virgil_crypto]: https://github.com/VirgilSecurity/crypto-x
[_cards_service]: https://developer.virgilsecurity.com/docs/api-reference/card-service/v5
[_use_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/use-card-for-crypto-operation
[_get_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/get-card
[_search_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/search-card
[_create_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/create-card
[_own_crypto]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-own-crypto-library
[_key_storage]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-key-storage
[_card_verifier]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-card-verifier
[_card_manager]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-card-manager
[_setup_authentication]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-authentication
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_configure_sdk]: https://developer.virgilsecurity.com/docs/how-to#sdk-configuration
[_more_examples]: https://developer.virgilsecurity.com/docs/how-to#public-key-management
