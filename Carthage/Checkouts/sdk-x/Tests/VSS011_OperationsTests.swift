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
import VirgilSDK
import XCTest

class VSS011_OperationsTests: XCTestCase {
    class DelayOperation: AsyncOperation {
        override func main() {
            sleep(1)
            
            self.finish()
        }
    }
    
    func test001_AsyncOperation() {
        let op = DelayOperation()
        XCTAssert(op.isReady)
        XCTAssert(!op.isExecuting)
        XCTAssert(!op.isFinished)
        XCTAssert(!op.isCancelled)
        
        let q = OperationQueue()
        q.qualityOfService = .userInteractive
        q.addOperation(op)
        
        sleep(5)
        XCTAssert(op.isReady)
        XCTAssert(!op.isExecuting)
        XCTAssert(op.isFinished)
        XCTAssert(!op.isCancelled)
        
        XCTAssert(q.operations.isEmpty)
    }
    
    func test002_AsyncOperationCancel() {
        let op1 = DelayOperation()
        let op2 = DelayOperation()
        op2.addDependency(op1)
        
        let q = OperationQueue()
        q.qualityOfService = .userInteractive
        q.addOperations([op1, op2], waitUntilFinished: false)
        
        sleep(1)
        op2.cancel()
        
        sleep(5)
        XCTAssert(op2.isReady)
        XCTAssert(!op2.isExecuting)
        XCTAssert(op2.isFinished)
        XCTAssert(op2.isCancelled)
        XCTAssert(op1.isReady)
        XCTAssert(!op1.isExecuting)
        XCTAssert(op1.isFinished)
        XCTAssert(!op1.isCancelled)
        
        XCTAssert(q.operations.isEmpty)
    }
    
    class DelayGenericNoResult: GenericOperation<Void> {
        override func main() {
            sleep(3)
            
            self.finish()
        }
    }
    
    func test003_GenericOperationNoResultAsync() {
        let ex = self.expectation(description: "")
        
        let op = DelayGenericNoResult()
        
        op.start { result in
            guard case .failure(let error) = result,
                let genericOpError = error as? GenericOperationError,
                genericOpError == .resultIsMissing else {
                    XCTFail()
                    return
            }
            
            ex.fulfill()
        }
        
        self.waitForExpectations(timeout: 10) { error in
            guard error == nil else {
                XCTFail()
                return
            }
        }
    }
    
    func test004_GenericOperationNoResultSync() {
        let op = DelayGenericNoResult()
        
        let result = op.startSync()
        
        guard case .failure(let error) = result,
            let genericOpError = error as? GenericOperationError,
            genericOpError == .resultIsMissing else {
                XCTFail()
                return
        }
    }
    
    func test005_GenericOperationTimeout() {
        let op = DelayGenericNoResult()
        
        let result = op.startSync(timeout: 2)
        
        guard case .failure(let error) = result,
            let genericOpError = error as? GenericOperationError,
            genericOpError == .timeout else {
                XCTFail()
                return
        }
    }
    
    class DelayGeneric: GenericOperation<Bool> {
        override func main() {
            sleep(1)
            
            self.result = .success(true)
            
            self.finish()
        }
    }
    
    func test006_GenericOperationAsync() {
        let ex = self.expectation(description: "")
        
        let op = DelayGeneric()
        
        op.start { result in
            guard case .success(let res) = result,
                res else {
                    XCTFail()
                    return
            }
            
            ex.fulfill()
        }
        
        self.waitForExpectations(timeout: 10) { error in
            guard error == nil else {
                XCTFail()
                return
            }
        }
    }
    
    func test007_GenericOperationSync() {
        let op = DelayGeneric()
        
        let result = op.startSync()
        
        guard case .success(let res) = result,
            res else {
                XCTFail()
                return
        }
    }
    
    func test008_CallbackOperationErrorAndResultMissing() {
        let op = CallbackOperation<Bool>() { _, completion in
            sleep(1)
            
            completion(nil, nil)
        }
        
        let result = op.startSync()
        
        guard case .failure(let error) = result,
            let genericOpError = error as? CallbackOperationError,
            genericOpError == .errorAndResultMissing else {
                XCTFail()
                return
        }
    }
    
    func test009_CallbackOperationError() {
        let customErr = NSError(domain: "domain", code: 100500, userInfo: nil)
        let op = CallbackOperation<Bool>() { _, completion in
            sleep(1)
            
            completion(nil, customErr)
        }
        
        let result = op.startSync()
        
        guard case .failure(let error) = result,
            (error as NSError) === customErr else {
                XCTFail()
                return
        }
    }
    
    func test010_CallbackOperationBoth() {
        let customErr = NSError(domain: "domain", code: 100500, userInfo: nil)
        let op = CallbackOperation<Bool>() { _, completion in
            sleep(1)
            
            completion(true, customErr)
        }
        
        let result = op.startSync()
        
        guard case .success(let res) = result,
            res else {
                XCTFail()
                return
        }
    }
    
    func test011_CallbackOperation() {
        let op = CallbackOperation<Bool>() { _, completion in
            sleep(1)
            
            completion(true, nil)
        }
        
        let result = op.startSync()
        
        guard case .success(let res) = result,
            res else {
                XCTFail()
                return
        }
    }
    
    func test012_ResultTest() {
        let result1 = Result<Int>.success(3)
        
        XCTAssert(try! result1.getResult() == 3)
        
        let result2 = Result<Int>.failure(NSError(domain: "TEST", code: 12345))
        
        var errorWasThrown = false
        
        do {
            let _ = try result2.getResult()
        }
        catch {
            let error = error as NSError
            guard error.domain == "TEST", error.code == 12345 else {
                XCTFail()
                return
            }
            
            errorWasThrown = true
        }
        
        XCTAssert(errorWasThrown)
    }
}
