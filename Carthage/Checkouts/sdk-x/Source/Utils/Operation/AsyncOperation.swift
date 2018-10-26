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

/// Class for AsyncOperations
open class AsyncOperation: Operation {
    /// Operation error
    open var error: Error?
    /// Overrides Operation variable
    override open var isAsynchronous: Bool { return true }
    /// Overrides Operation variable
    override open var isExecuting: Bool { return self.state == .executing }
    /// Overrides Operation variable
    override open var isFinished: Bool { return self.state == .finished }
    /// Operation state
    private var state = State.ready {
        willSet {
            self.willChangeValue(forKey: self.state.keyPath)
            self.willChangeValue(forKey: newValue.keyPath)
        }
        didSet {
            self.didChangeValue(forKey: self.state.keyPath)
            self.didChangeValue(forKey: oldValue.keyPath)
        }
    }

    /// Describes Operation state
    public enum State: String {
        case ready     = "Ready"
        case executing = "Executing"
        case finished  = "Finished"

        fileprivate var keyPath: String { return "is" + self.rawValue }
    }

    /// Overrides Operation function
    /// WARNING: You do not need override this function. Override main() func instead
    override open func start() {
        guard !self.isCancelled else {
            self.state = .finished
            return
        }

        self.state = .executing
        self.main()
    }

    /// Call this function when you task is finished
    /// WARNING: You do not need override this function. Override main() func instead
    open func finish() {
        self.state = .finished
    }

    /// Implement your task here
    override open func main() {
    }
}
