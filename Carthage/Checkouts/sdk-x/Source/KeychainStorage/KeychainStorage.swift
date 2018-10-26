//
// Copyright (C) 2015-2018 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation

/// Declares error codes for KeychainStorage. See KeychainStorageError
///
/// - utf8ConvertingError: Error while converting string to utf8 binary
/// - emptyKeychainResponse: Keychain response is nil
/// - wrongResponseType: Unexpected keychain response type
/// - errorParsingKeychainResponse: Error while deserializing keychain response
/// - invalidAppBundle: Bundle.main.bundleIdentifier is empty
/// - keychainError: Keychain returned error
@objc(VSSKeychainStorageErrorCodes) public enum KeychainStorageErrorCodes: Int {
    case utf8ConvertingError = 1
    case emptyKeychainResponse = 2
    case wrongResponseType = 3
    case errorParsingKeychainResponse = 4
    case invalidAppBundle = 5
    case keychainError = 6
}

/// Class respresenting error returned from KeychainStorage
@objc(VSSKeychainStorageError) public final class KeychainStorageError: NSObject, CustomNSError {
    /// Error domain
    public static var errorDomain: String { return "VirgilSDK.KeyStorageErrorDomain" }

    /// Error code. See KeychainStorageErrorCodes
    public var errorCode: Int { return self.errCode.rawValue }

    /// Error code. See KeychainStorageErrorCodes
    @objc public let errCode: KeychainStorageErrorCodes

    /// OSStatus returned from Keychain
    public let osStatus: OSStatus?

    /// OSStatus as NSNumber
    @objc public var osStatusNumber: NSNumber? {
        if let osStatus = self.osStatus {
            return NSNumber(integerLiteral: Int(osStatus))
        }
        else {
            return nil
        }
    }

    internal init(errCode: KeychainStorageErrorCodes) {
        self.errCode = errCode
        self.osStatus = nil

        super.init()
    }

    internal init(osStatus: OSStatus?) {
        self.errCode = .keychainError
        self.osStatus = osStatus

        super.init()
    }
}

// swiftlint:disable function_body_length type_body_length file_length

/// Class responsible for Keychain interactions.
@objc(VSSKeychainStorage) open class KeychainStorage: NSObject {
#if os(macOS)
    /// Comment for all macOS password entries created by this class. Used for filtering
    @objc public static let commentStringPrefix = "CREATED_BY_VIRGILSDK"

    /// Comment string
    ///
    /// - Returns: Comment string for macOS Keychain entries
    @objc public func commentString() -> String {
        return "\(KeychainStorage.commentStringPrefix).OWNER_APP=\(self.storageParams.appName)"
    }

    /// Created access for trusted application + current application
    ///
    /// - Parameter name: entry nake
    /// - Returns: SecAccess
    /// - Throws: KeychainStorageError
    @objc public func createAccess(forName name: String) throws -> SecAccess {
        // Make an exception list of trusted applications; that is,
        // applications that are allowed to access the item without
        // requiring user confirmation:
        var myselfT: SecTrustedApplication?

        var status = SecTrustedApplicationCreateFromPath(nil, &myselfT)
        guard status == errSecSuccess, let myself = myselfT else {
            throw KeychainStorageError(osStatus: status)
        }

        var trustedList = [SecTrustedApplication]()
        trustedList.append(myself)

        for application in self.storageParams.trustedApplications {
            var appT: SecTrustedApplication?

            status = SecTrustedApplicationCreateFromPath(application, &appT)
            guard status == errSecSuccess, let app = appT else {
                throw KeychainStorageError(osStatus: status)
            }

            trustedList.append(app)
        }

        //Create an access object:
        var accessT: SecAccess?
        status = SecAccessCreate(name as CFString, trustedList as CFArray, &accessT)
        guard status == errSecSuccess, let access = accessT else {
            throw KeychainStorageError(osStatus: status)
        }

        return access
    }
#endif

    /// Private key identifier format
    @objc public static let privateKeyIdentifierFormat = ".%@.privatekey.%@\0"

    /// KeychainStorage parameters
    @objc public let storageParams: KeychainStorageParams

    /// Initializer
    ///
    /// - Parameter storageParams: KeychainStorage parameters
    @objc public init(storageParams: KeychainStorageParams) {
        self.storageParams = storageParams

        super.init()
    }

    /// Stores sensitive data to Keychain
    ///
    /// - Parameters:
    ///   - data: Sensitive data
    ///   - name: Alias for data
    ///   - meta: Additional meta info
    /// - Returns: Stored entry
    /// - Throws: KeychainStorageError
    @objc open func store(data: Data, withName name: String, meta: [String: String]?) throws -> KeychainEntry {
        let tag = String(format: KeychainStorage.privateKeyIdentifierFormat, self.storageParams.appName, name)

    #if os(iOS) || os(tvOS) || os(watchOS)
        guard let tagData = tag.data(using: .utf8),
            let nameData = name.data(using: .utf8) else {
                throw KeychainStorageError(errCode: .utf8ConvertingError)
        }

        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationLabel as String: nameData,
            kSecAttrApplicationTag as String: tagData,

            kSecAttrAccessible as String: self.storageParams.accessibility as CFString,
            kSecAttrLabel as String: name,
            kSecAttrIsPermanent as String: true,
            kSecAttrCanEncrypt as String: true,
            kSecAttrCanDecrypt as String: false,
            kSecAttrCanDerive as String: false,
            kSecAttrCanSign as String: true,
            kSecAttrCanVerify as String: false,
            kSecAttrCanWrap as String: false,
            kSecAttrCanUnwrap as String: false,
            kSecAttrSynchronizable as String: false,

            kSecReturnData as String: true,
            kSecReturnAttributes as String: true
        ]

        // Access groups are not supported in simulator
        #if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
        if let accessGroup = self.storageParams.accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }
        #endif
    #elseif os(macOS)
        let access = try self.createAccess(forName: name)

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: tag,

            kSecAttrLabel as String: name,
            kSecAttrSynchronizable as String: false,

            kSecAttrAccess as String: access,
            kSecAttrComment as String: self.commentString(),

            kSecReturnData as String: true,
            kSecReturnAttributes as String: true
        ]

        #if DEBUG
        query[kSecAttrIsInvisible as String] = false
        #else
        query[kSecAttrIsInvisible as String] = true
        #endif
    #endif

        let keyEntry = KeyEntry(name: name, value: data, meta: meta)
        let keyEntryData = NSKeyedArchiver.archivedData(withRootObject: keyEntry)

        query[kSecValueData as String] = keyEntryData

        var dataObject: AnyObject?

        let status = SecItemAdd(query as CFDictionary, &dataObject)

        let data = try KeychainStorage.validateKeychainResponse(dataObject: dataObject, status: status)

        return try KeychainStorage.parseKeychainEntry(from: data)
    }

    /// Updated entry in Keychain
    ///
    /// - Parameters:
    ///   - name: Alias
    ///   - data: New data
    ///   - meta: New meta info
    /// - Throws: KeychainStorageError
    @objc open func updateEntry(withName name: String, data: Data, meta: [String: String]?) throws {
        let tag = String(format: KeychainStorage.privateKeyIdentifierFormat, self.storageParams.appName, name)

    #if os(iOS) || os(tvOS) || os(watchOS)
        guard let tagData = tag.data(using: .utf8),
            let nameData = name.data(using: .utf8) else {
                throw KeychainStorageError(errCode: .utf8ConvertingError)
        }

        var query = [String: Any]()
        query = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationLabel as String: nameData,
            kSecAttrApplicationTag as String: tagData
        ]

        // Access groups are not supported in simulator
        #if !targetEnvironment(simulator)
        if let accessGroup = self.storageParams.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        #endif
    #elseif os(macOS)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: tag,

            kSecAttrComment as String: self.commentString()
        ]
    #endif

        let keyEntry = KeyEntry(name: name, value: data, meta: meta)
        let keyEntryData = NSKeyedArchiver.archivedData(withRootObject: keyEntry)

        let keySpecificData: [String: Any] = [
            kSecValueData as String: keyEntryData
        ]

        let status = SecItemUpdate(query as CFDictionary, keySpecificData as CFDictionary)

        guard status == errSecSuccess else {
            throw KeychainStorageError(osStatus: status)
        }
    }

    /// Retrieves entry from keychain
    ///
    /// - Parameter name: Alias
    /// - Returns: Retrieved entry
    /// - Throws: KeychainStorageError
    @objc open func retrieveEntry(withName name: String) throws -> KeychainEntry {
        let tag = String(format: KeychainStorage.privateKeyIdentifierFormat, self.storageParams.appName, name)

    #if os(iOS) || os(tvOS) || os(watchOS)
        guard let tagData = tag.data(using: .utf8),
            let nameData = name.data(using: .utf8) else {
                throw KeychainStorageError(errCode: .utf8ConvertingError)
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationLabel as String: nameData,
            kSecAttrApplicationTag as String: tagData,

            kSecReturnData as String: true,
            kSecReturnAttributes as String: true
        ]
    #elseif os(macOS)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: tag,

            kSecReturnData as String: true,
            kSecReturnAttributes as String: true,

            kSecAttrComment as String: self.commentString()
        ]
    #endif

        var dataObject: AnyObject?

        let status = SecItemCopyMatching(query as CFDictionary, &dataObject)

        let data = try KeychainStorage.validateKeychainResponse(dataObject: dataObject, status: status)

        return try KeychainStorage.parseKeychainEntry(from: data)
    }

    /// Retrieves all entries in Keychain
    ///
    /// - Returns: Retrieved entries
    /// - Throws: KeychainStorageError
    @objc open func retrieveAllEntries() throws -> [KeychainEntry] {
    #if os(iOS) || os(tvOS) || os(watchOS)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,

            kSecReturnData as String: true,
            kSecReturnAttributes as String: true,

            kSecMatchLimit as String: kSecMatchLimitAll
        ]
    #elseif os(macOS)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,

            kSecReturnData as String: true,
            kSecReturnAttributes as String: true,

            // Workaround: kSecMatchLimitAll doesn't work
            // Seems like UInt32.max / 2 is maximum allowed value, which should be enough for one application
            kSecMatchLimit as String: NSNumber(value: UInt32.max / 2),

            kSecAttrComment as String: self.commentString()
        ]
    #endif

        var dataObject: AnyObject?

        let status = SecItemCopyMatching(query as CFDictionary, &dataObject)

        if status == errSecItemNotFound {
            return []
        }

        let data = try KeychainStorage.validateKeychainResponse(dataObject: dataObject, status: status)

        guard let arr = data as? [AnyObject] else {
            throw KeychainStorageError(errCode: .wrongResponseType)
        }

        return arr.compactMap { try? KeychainStorage.parseKeychainEntry(from: $0) }
    }

    /// Deletes entry from Keychain
    ///
    /// - Parameter name: Alias
    /// - Throws: KeychainStorageError
    @objc open func deleteEntry(withName name: String) throws {
        let tag = String(format: KeychainStorage.privateKeyIdentifierFormat, self.storageParams.appName, name)

    #if os(iOS) || os(tvOS) || os(watchOS)
        guard let tagData = tag.data(using: .utf8),
            let nameData = name.data(using: .utf8) else {
                throw KeychainStorageError(errCode: .utf8ConvertingError)
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationLabel as String: nameData,
            kSecAttrApplicationTag as String: tagData
        ]
    #elseif os(macOS)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: name,
            kSecAttrService as String: tag,

            kSecAttrComment as String: self.commentString()
        ]
    #endif

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess else {
            throw KeychainStorageError(osStatus: status)
        }
    }

    /// Deletes all entries from Keychain
    ///
    /// - Throws: KeychainStorageError
    @objc open func deleteAllEntries() throws {
    #if os(iOS) || os(tvOS) || os(watchOS)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]
    #elseif os(macOS)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,

            // Workaround: kSecMatchLimitAll doesn't work
            // Seems like UInt32.max / 2 is maximum allowed value, which should be enough for one application
            kSecMatchLimit as String: NSNumber(value: UInt32.max / 2),

            kSecAttrComment as String: self.commentString()
        ]
    #endif

        let status = SecItemDelete(query as CFDictionary)

        if status == errSecItemNotFound {
            return
        }

        guard status == errSecSuccess else {
            throw KeychainStorageError(osStatus: status)
        }
    }

    /// Checks if entry exists in Keychain
    ///
    /// - Parameter name: Alias
    /// - Returns: true if entry exists, false otherwise
    /// - Throws: KeychainStorageError
    open func existsEntry(withName name: String) throws -> Bool {
        do {
            _ = try self.retrieveEntry(withName: name)

            return true
        }
        catch let error as KeychainStorageError {
            if error.errCode == .keychainError, let osStatus = error.osStatus, osStatus == errSecItemNotFound {
                return false
            }

            throw error
        }
        catch {
            throw error
        }
    }

    private static func validateKeychainResponse(dataObject: AnyObject?, status: OSStatus) throws -> AnyObject {
        guard status == errSecSuccess else {
            throw KeychainStorageError(osStatus: status)
        }

        guard let data = dataObject else {
            throw KeychainStorageError(errCode: .emptyKeychainResponse)
        }

        return data
    }

    private static func parseKeychainEntry(from data: AnyObject) throws -> KeychainEntry {
        guard let dict = data as? [String: Any] else {
            throw KeychainStorageError(errCode: .wrongResponseType)
        }

        guard let creationDate = dict[kSecAttrCreationDate as String] as? Date,
            let modificationDate = dict[kSecAttrModificationDate as String] as? Date,
            let rawData = dict[kSecValueData as String] as? Data,
            let storedKeyEntry = NSKeyedUnarchiver.unarchiveObject(with: rawData) as? KeyEntry else {
                throw KeychainStorageError(errCode: .errorParsingKeychainResponse)
        }

        return KeychainEntry(data: storedKeyEntry.value, name: storedKeyEntry.name,
                             meta: storedKeyEntry.meta, creationDate: creationDate, modificationDate: modificationDate)
    }
}
