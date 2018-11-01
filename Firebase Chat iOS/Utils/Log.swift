//
//  Log.swift
//  VirgilMessenger
//
//  Created by Oleksandr Deundiak on 8/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class Log {
    class func debug(_ closure: @autoclosure () -> String, functionName: String = #function, file: String = #file, line: UInt = #line) {
        #if DEBUG
            self.log("<DEBUG>: \(closure())", functionName: functionName, file: file, line: line)
        #endif
    }

    class func error( _ closure: @autoclosure () -> String, functionName: String = #function, file: String = #file, line: UInt = #line) {
        self.log("<ERROR>: \(closure())", functionName: functionName, file: file, line: line)
    }

    private class func log(_ closure: @autoclosure () -> String, functionName: String = #function, file: String = #file, line: UInt = #line) {
        let str = "VIRGILFIREBASE_LOG: \(functionName) : \(closure())"
        Log.writeInLog(str)
    }

    private class func writeInLog(_ message: String) {
        NSLogv("%@", getVaList([message]))
    }
}
