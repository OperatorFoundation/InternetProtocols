import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(InternetProtocolsTests.allTests),
    ]
}
#endif
