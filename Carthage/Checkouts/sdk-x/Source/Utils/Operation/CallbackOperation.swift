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

/// Declares error types and codes
///
/// - errorAndResultMissing: Both Result and Error are missing in callback
@objc(VSSCallbackOperationError) public enum CallbackOperationError: Int, Error {
    case errorAndResultMissing = 1
}

/// Async GenericOperation that can be initialized with callback
open class CallbackOperation<T>: GenericOperation<T> {
    /// Task type
    public typealias Task = (CallbackOperation<T>, @escaping (T?, Error?) -> Void) -> Void

    /// Task to execute
    public let task: Task

    /// Initializer
    ///
    /// - Parameter task: task to execute
    public init(task: @escaping Task) {
        self.task = task

        super.init()
    }

    /// Main function
    override open func main() {
        self.task(self) { res, error in
            if let res = res {
                self.result = .success(res)
            }
            else if let error = error {
                self.result = .failure(error)
            }
            else {
                self.result = .failure(CallbackOperationError.errorAndResultMissing)
            }

            self.finish()
        }
    }
}
