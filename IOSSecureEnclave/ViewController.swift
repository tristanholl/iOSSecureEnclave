//
//  ViewController.swift
//  DeviceBinding
//
//  Created by Tristan Holl on 30.07.19.
//  Copyright © 2019 Tristan Holl. All rights reserved.
//

import UIKit
import CommonCrypto

extension Data {
    
    init?(fromHexEncodedString string: String) {
        
        // Convert 0 ... 9, a ... f, A ...F to their decimal value,
        // return nil for all other input characters
        func decodeNibble(u: UInt16) -> UInt8? {
            switch(u) {
            case 0x30 ... 0x39:
                return UInt8(u - 0x30)
            case 0x41 ... 0x46:
                return UInt8(u - 0x41 + 10)
            case 0x61 ... 0x66:
                return UInt8(u - 0x61 + 10)
            default:
                return nil
            }
        }
        
        self.init(capacity: string.utf16.count/2)
        var even = true
        var byte: UInt8 = 0
        for c in string.utf16 {
            guard let val = decodeNibble(u: c) else { return nil }
            if even {
                byte = val << 4
            } else {
                byte += val
                self.append(byte)
            }
            even = !even
        }
        guard even else { return nil }
    }
}

class ViewController: UIViewController {

    @IBOutlet var inputText: UITextView!
    @IBOutlet var outputText: UITextView!
    
    struct KeyPair {
        static let manager: EllipticCurveKeyPair.Manager = {
            let publicAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAlwaysThisDeviceOnly, flags: [])
            let privateAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: [.userPresence, .privateKeyUsage])
            let config = EllipticCurveKeyPair.Config(
                publicLabel: "thsenc.sign.public",
                privateLabel: "thsenc.sign.private",
                operationPrompt: "Confirm",
                publicKeyAccessControl: publicAccessControl,
                privateKeyAccessControl: privateAccessControl,
                token: .secureEnclave)
            return EllipticCurveKeyPair.Manager(config: config)
        }()
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }

    @IBAction func buttonPublicKey(_ sender: Any) {
        do {
            let key = try KeyPair.manager.publicKey().data().PEM //.base64EncodedString()

            outputText.text = key
        }
        catch {
            // Error
            print(error)
        }
        view.endEditing(true)
    }
    
    @IBAction func buttonPublicKeyHex(_ sender: Any) {
        do {
            let key = try KeyPair.manager.publicKey().data().raw.map { String(format: "%02hhx", $0) }.joined()
            
            outputText.text = key
        }
        catch {
            // Error
            print(error)
        }
        view.endEditing(true)
    }
    
    @IBAction func buttonPublicKeyb64(_ sender: Any) {
        do {
            let key = try KeyPair.manager.publicKey().data().raw.base64EncodedString()
            
            outputText.text = key
        }
        catch {
            // Error
            print(error)
        }
        view.endEditing(true)
    }
    
    @IBAction func SignContent(_ sender: Any) {
        let digest = inputText.text.data(using: .utf8)!
        print(digest.map { String(format: "%02hhx", $0) }.joined())
        
        do {
            let signature = try KeyPair.manager.sign(digest, hash: .sha256)
            
            outputText.text = signature.map { String(format: "%02hhx", $0) }.joined()
        }
        catch {
            // Error
            print(error)
        }
        view.endEditing(true)
    }
    
    @IBAction func copyContentToInput(_ sender: Any) {
        inputText.text = outputText.text
        outputText.text = ""
    }
    
    @IBAction func deleteFields(_ sender: Any) {
        inputText.text = ""
        outputText.text = ""
    }
    
    @IBAction func encryptData(_ sender: Any) {
        let digest = inputText.text.data(using: .utf8)!
        
        do {
            let encrypted = try KeyPair.manager.encrypt(digest, hash: .sha256)
            
            outputText.text = encrypted.map { String(format: "%02hhx", $0) }.joined()
            
        } catch {
            // Error
            print(error)
        }
        view.endEditing(true)
    }
 
    
    @IBAction func decryptData(_ sender: Any) {
        let encrypted_hex = inputText.text!
        let encrypted = Data(fromHexEncodedString:encrypted_hex)!
        
        print(encrypted_hex)
        
        do {
            let decrypted = try KeyPair.manager.decrypt(encrypted, hash: .sha256)
            
             outputText.text = String(data: decrypted, encoding: .utf8)
        } catch {
            // Error
            print(error)
        }
        view.endEditing(true)
    }
}
