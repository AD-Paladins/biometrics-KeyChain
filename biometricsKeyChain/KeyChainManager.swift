//
//  KeyChainManager.swift
//  biometricsKeyChain
//
//  Created by andres on 9/17/19.
//  Copyright © 2019 Andres Paladines. All rights reserved.
//

import Foundation
import LocalAuthentication

class KeyChainManager {
    
    static func loadKeyChain(key: String) -> String? {
        let service = Constants.KEYCHAIN_SERVICE
        let itemKey = key
        let keychainAccessGroupName = Constants.KEYCHAIN_ACCESS_GROUP
        
        var secret_value : String? = nil
        let queryLoad: [String: AnyObject] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: itemKey as AnyObject,
            kSecAttrService as String: service as AnyObject,
            kSecReturnData as String: kCFBooleanTrue,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrAccessGroup as String: keychainAccessGroupName as AnyObject
        ]
        var result: AnyObject?
        
        let resultCodeLoad = withUnsafeMutablePointer(to: &result) {
            SecItemCopyMatching(queryLoad as CFDictionary, UnsafeMutablePointer($0))
        }
        
        if resultCodeLoad == noErr {
            if let result = result as? Data,
                let keyValue = NSString(data: result, encoding: String.Encoding.utf8.rawValue) as String? {
                secret_value = keyValue
            }
        } else {
            print("Error loading from Keychain: \(resultCodeLoad)")
            secret_value = nil
        }
        
        return secret_value
    }
    
    
    static func deleteKeyChain(key: String) -> Bool {
        let service = Constants.KEYCHAIN_SERVICE
        let itemKey = key
        let keychainAccessGroupName = Constants.KEYCHAIN_ACCESS_GROUP
        
        let queryDelete: [String: AnyObject] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: itemKey as AnyObject,
            kSecAttrService as String: service as AnyObject,
            kSecAttrAccessGroup as String: keychainAccessGroupName as AnyObject
        ]
        
        let resultCodeDelete = SecItemDelete(queryDelete as CFDictionary)
        
        if resultCodeDelete != noErr {
            print("Error deleting from Keychain: \(resultCodeDelete)")
            return false
        }
        return true
    }
    
    //    before add, you need to delete previous value for key.
    static func addKeyChain(key: String, value: String) -> Bool {
        let itemKey = key
        let itemValue = value
        let service = Constants.KEYCHAIN_SERVICE
        let keychainAccessGroupName = Constants.KEYCHAIN_ACCESS_GROUP
        
        guard let valueData = itemValue.data(using: String.Encoding.utf8) else {
            print("Error saving text to Keychain")
            return false
        }
        
        let queryAdd: [String: AnyObject] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: itemKey as AnyObject,
            kSecAttrService as String: service as AnyObject,
            kSecValueData as String: valueData as AnyObject,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecAttrAccessGroup as String: keychainAccessGroupName as AnyObject
        ]
        
        let resultCode = SecItemAdd(queryAdd as CFDictionary, nil)
        
        if resultCode != noErr {
            print("Error saving to Keychain: \(resultCode)")
            return false
        }
        return true
    }
}
