// CODE NOT PRODUCTION READY!!!
// DO NOT USE!!!

//  File.swift
//  
//
//  Created by Joshua Clark on 3/11/22.
//

import Bits
import Datable
import Foundation

public struct ICMP: Codable
{
    public var type: UInt8
    public var code: UInt8? = 0
    public var checksum: UInt16? = 0
    public var ipPacket: Packet? = nil
    public var pointer: UInt8? = nil
    public var gatewayInternetAddress: Int32? = nil
    public var identifier: UInt16? = nil
    public var sequenceNumber: UInt16? = nil
    public var originateTimeStamp: UInt32? = nil
    public var receiveTimestamp: UInt32? = nil
    public var transmitTimestamp: UInt32? = nil
    public var echoMessage: Data? = nil
}

extension ICMP: MaybeDatable
{
    public init?(data: Data)
    {
//        if debugPrint { print("・ start parsing UDP") }
        var bits = Bits(data: data)
        
        guard let type = bits.unpackByte() else {
            return nil
        }
        self.type = type
        
        guard let code = bits.unpackByte() else {
            return nil
        }
        self.code = code
        
        guard let checksumBytes = bits.unpack(bytes: 2) else {
            return nil
        }
        guard let checksum = checksumBytes.maybeNetworkUint16 else {
            return nil
        }
        self.checksum = checksum
        
        
        switch self.type {
            // echo message, echo reply message
            // TODO: in each case, make an instance of the subclass that gets the bits class and does the below code in its own inits
            case 0, 8:
                guard let identifierBytes = bits.unpack(bytes: 2) else {
                    return nil
                }
                guard let identifier = identifierBytes.maybeNetworkUint16 else {
                    return nil
                }
                self.identifier = identifier
                
                guard let sequenceNumberBytes = bits.unpack(bytes: 2) else {
                    return nil
                }
                guard let sequenceNumber = sequenceNumberBytes.maybeNetworkUint16 else {
                    return nil
                }
                self.sequenceNumber = sequenceNumber
                
                return nil
                
            // Destination Unreachable Message, Source Quench Message, Time Exceeded Message
            case 3, 4, 11:
                return nil
            //
            case 5:
                return nil
            // Parameter Problem Message
            case 12:
                return nil
            //
            case 13, 14:
                return nil
            //
            case 15, 16:
                return nil
                
            default:
                return nil
        }
    }
    
    public var data: Data
    {
//        if debugPrint { print("・ start parsing UDP") }
        var bits = Bits()
        
        guard bits.pack(byte: self.type) else {
            return Data()
        }
        
        guard let code = self.code else {
            return Data()
        }
        guard bits.pack(byte: code) else {
            return Data()
        }
        
        guard let checksum = self.checksum else {
            return Data()
        }
        guard let checksumBytes = checksum.maybeNetworkData else {
            return Data()
        }
        guard bits.pack(bytes: checksumBytes) else {
            return Data()
        }
        
        switch self.type {
            // echo message, echo reply message
            // TODO: in each case, make an instance of the subclass that gets the bits class and does the below code in its own inits
            case 0, 8:
                guard let identifier = self.identifier else {
                    return Data()
                }
                guard let identifierBytes = identifier.maybeNetworkData else {
                    return Data()
                }
                guard bits.pack(bytes: identifierBytes) else {
                    return Data()
                }
                
                guard let sequenceNumber = self.sequenceNumber else {
                    return Data()
                }
                guard let sequenceNumberBytes = sequenceNumber.maybeNetworkData else {
                    return Data()
                }
                guard bits.pack(bytes: sequenceNumberBytes) else {
                    return Data()
                }
                
                guard let echoMessage = self.echoMessage else {
                    return Data()
                }
                guard bits.pack(bytes: echoMessage) else {
                    return Data()
                }
                
                guard let result = bits.unpackRemainingBytes() else {
                    return Data()
                }
                
                return result
            // Destination Unreachable Message, Source Quench Message, Time Exceeded Message
            case 3, 4, 11:
                return Data()
            //
            case 5:
                return Data()
            // Parameter Problem Message
            case 12:
                return Data()
            //
            case 13, 14:
                return Data()
            //
            case 15, 16:
                return Data()
                
            default:
                return Data()
        }
    }
}

extension ICMP
{
    public init?(type: UInt8)
    {
        self.type = type
        // verify that the fields are correct based on the type
        switch type {
            case 0:
                if code! != 0 {
                    print("Invalid ICMP code value for type 0 (Echo Reply Message)")
                    return nil
                }
                
                if identifier == nil || sequenceNumber == nil || echoMessage == nil {
                    print("ICMP type 0 (Echo Reply Message) requires identifier, sequenceNumber, and echoMessage")
                }
                
                if pointer != nil && originateTimeStamp != nil && receiveTimestamp != nil && transmitTimestamp != nil {
                    print("ICMP type 0 (Echo Reply Message) only requires a code, checksum, identifier, sequenceNumber, and echoMessage")
                    return nil
                }
            case 3:
                if code! > 5 {
                    print("Invalid ICMP code value for type 3 (Destination Unreachable Message)")
                    return nil
                }
                
                if pointer != nil && gatewayInternetAddress != nil && identifier != nil && sequenceNumber != nil && originateTimeStamp != nil && receiveTimestamp != nil && transmitTimestamp != nil && echoMessage != nil {
                    print("ICMP type 3 (Destination Unreachable Message) only takes a code and a checksum")
                    return nil
                }
                
            case 4:
                if code! != 0 {
                    print("Invalid ICMP code value for type 4 (Source Quench Message)")
                    return nil
                }
                
                if pointer != nil && gatewayInternetAddress != nil && identifier != nil && sequenceNumber != nil && originateTimeStamp != nil && receiveTimestamp != nil && transmitTimestamp != nil && echoMessage != nil {
                    print("ICMP type 4 (Source Quench Message) only requires a code, checksum, and pointer")
                    return nil
                }
                
            case 5:
                if code! > 3 {
                    print("Invalid ICMP code value for type 5 (Redirect Message)")
                    return nil
                }
                
                if gatewayInternetAddress == nil {
                    print("ICMP type 5 (Redirect Message) requires a gatewayInternetAddress")
                }
                
                if pointer != nil && identifier != nil && sequenceNumber != nil && originateTimeStamp != nil && receiveTimestamp != nil && transmitTimestamp != nil && echoMessage != nil {
                    print("ICMP type 5 (Redirect Message) only requires a code, checksum, and gatewayInternetAddress")
                    return nil
                }
                
            case 8:
                if code! != 0 {
                    print("Invalid ICMP code value for type 8 (Echo Message)")
                    return nil
                }
                
                if identifier == nil || sequenceNumber == nil || echoMessage == nil {
                    print("ICMP type 8 (Echo Message) requires identifier, sequenceNumber, and echoMessage")
                }
                
                if pointer != nil && originateTimeStamp != nil && receiveTimestamp != nil && transmitTimestamp != nil {
                    print("ICMP type 8 (Echo Message) only requires a code, checksum, identifier, sequenceNumber, and echoMessage")
                    return nil
                }
            case 11:
                if code! > 1 {
                    print("Invalid ICMP code value for type 11 (Time Exceeded Message)")
                    return nil
                }
                
                if pointer != nil && gatewayInternetAddress != nil && identifier != nil && sequenceNumber != nil && originateTimeStamp != nil && receiveTimestamp != nil && transmitTimestamp != nil && echoMessage != nil {
                    print("ICMP type 11 (Time Exceeded Message) only requires a code and a checksum")
                    return nil
                }
                
            case 12:
                if code! != 0 {
                    print("Invalid ICMP code value for type 12 (Parameter Problem Message)")
                    return nil
                }
                
                if pointer == nil {
                    print("ICMP type 12 (Parameter Problem Message) requires a pointer")
                }
                
                if identifier != nil && gatewayInternetAddress != nil && sequenceNumber != nil && originateTimeStamp != nil && receiveTimestamp != nil && transmitTimestamp != nil && echoMessage != nil {
                    print("ICMP type 12 (Parameter Problem Message) only requires a code, checksum, and pointer")
                    return nil
                }
                
            case 13:
                if code! != 0 {
                    print("Invalid ICMP code value for type 13 (Timestamp Message)")
                    return nil
                }
                
                if identifier == nil || sequenceNumber == nil || originateTimeStamp == nil || receiveTimestamp == nil || transmitTimestamp == nil {
                    print("ICMP type 13 (Timestamp Message) requires identifier, sequenceNumber, and echoMessage")
                }
                
                if pointer != nil && echoMessage != nil {
                    print("ICMP type 13 (Timestamp Message) only requires a code, checksum, identifier, sequenceNumber, originateTimestamp, receiveTimestamp, and transmitTimestamp")
                    return nil
                }
            case 14:
                if code! != 0 {
                    print("Invalid ICMP code value for type 14 (Timestamp Reply Message)")
                    return nil
                }
                
                if identifier == nil || sequenceNumber == nil || originateTimeStamp == nil || receiveTimestamp == nil || transmitTimestamp == nil {
                    print("ICMP type 14 (Timestamp Reply Message) requires identifier, sequenceNumber, and echoMessage")
                }
                
                if pointer != nil && echoMessage != nil {
                    print("ICMP type 14 (Timestamp Reply Message) only requires a code, checksum, identifier, sequenceNumber, originateTimestamp, receiveTimestamp, and transmitTimestamp")
                    return nil
                }
            case 15:
                if code! != 0 {
                    print("Invalid ICMP code value for type 15 (Information Request Message)")
                    return nil
                }
                
                if identifier == nil || sequenceNumber == nil {
                    print("ICMP type 15 (Information Request Message) requires identifier, and sequenceNumber")
                }
                
                if pointer != nil && originateTimeStamp != nil && receiveTimestamp != nil && transmitTimestamp != nil && echoMessage != nil {
                    print("ICMP type 15 (Information Request Message) only requires a code, checksum, identifier, and sequenceNumber")
                    return nil
                }
            case 16:
                if code! != 0 {
                    print("Invalid ICMP code value for type 16 (Information Reply Message)")
                    return nil
                }
                
                if identifier == nil || sequenceNumber == nil {
                    print("ICMP type 16 (Information Reply Message) requires identifier, and sequenceNumber")
                }
                
                if pointer != nil && originateTimeStamp != nil && receiveTimestamp != nil && transmitTimestamp != nil && echoMessage != nil {
                    print("ICMP type 16 (Information Reply Message) only requires a code, checksum, identifier, and sequenceNumber")
                    return nil
                }
            default:
                print("Invalid ICMP type value")
                return nil
        }
    }
}

extension ICMP: CustomStringConvertible
{
    public var description: String {
        //return ICMP values of interest as a human readable string
        
        var returnString: String = ""
        returnString += "Type: " + self.type.string + "\n"
        
        if let checksum = self.checksum {
        returnString += "Checksum: 0x" + String(format: "%04x", checksum) + " - 0d" + checksum.string + "\n"
        }
        else
        {
            returnString += "Checksum: nil\n"
        }
        
        if let echoMessage = self.echoMessage
        {
            returnString += "Echo Message: "
            returnString += printDataBytes(bytes: echoMessage.data, hexDumpFormat: true, seperator: " ", decimal: false, enablePrinting: false) + "\n"
        }
        else
        {
            returnString += "Payload: nil\n"
        }
        
        return returnString
    }
}
