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

/// Class used for logging
public class Log {
    /// Log with DEBUG level
    ///
    /// - Parameters:
    ///   - closure: fake closure to caprute loging details
    ///   - functionName: functionName
    ///   - file: file
    ///   - line: line
    public class func debug(_ closure: @autoclosure () -> String, functionName: String = #function,
                            file: String = #file, line: UInt = #line) {
        #if DEBUG
            self.log("<DEBUG>: \(closure())", functionName: functionName, file: file, line: line)
        #endif
    }

    /// Log with ERROR level
    ///
    /// - Parameters:
    ///   - closure: fake closure to caprute loging details
    ///   - functionName: functionName
    ///   - file: file
    ///   - line: line
    public class func error(_ closure: @autoclosure () -> String, functionName: String = #function,
                            file: String = #file, line: UInt = #line) {
        self.log("<ERROR>: \(closure())", functionName: functionName, file: file, line: line)
    }

    private class func log(_ closure: @autoclosure () -> String, functionName: String = #function,
                           file: String = #file, line: UInt = #line) {
        let str = "VIRGILSDK_LOG: \(functionName) : \(closure())"
        Log.writeInLog(str)
    }

    private class func writeInLog(_ message: String) {
        NSLogv("%@", getVaList([message]))
    }
}
