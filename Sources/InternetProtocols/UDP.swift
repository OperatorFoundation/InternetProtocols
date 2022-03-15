//
//  File.swift
//  
//
//  Created by Joshua Clark on 3/11/22.
//

import Bits
import Datable
import Foundation
import Net

public struct UDP: Codable
{
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let length: UInt16
    public let checksum: UInt16
    public let payload: Data?
}

extension UDP: MaybeDatable
{
    public init?(data: Data)
    {
        if debugPrint { print("・ start parsing UDP") }
        var bits = Bits(data: data)
        
        guard let sourcePort = bits.unpack(bytes: 2) else { return nil }
        guard let sourcePortUint16 = sourcePort.maybeNetworkUint16 else { return nil }
        self.sourcePort = sourcePortUint16
        if debugPrint { print("・ UDPsourcePort: 0x" + String(format: "%02x", self.sourcePort) + " - 0d" + String(format: "%u", self.sourcePort)) }
        
        guard let destinationPort = bits.unpack(bytes: 2) else { return nil }
        guard let destinationPortUint16 = destinationPort.maybeNetworkUint16 else { return nil }
        self.destinationPort = destinationPortUint16
        if debugPrint { print("・ UDPdestinationPort: 0x" + String(format: "%02x", self.destinationPort) + " - 0d" + String(format: "%u", self.destinationPort)) }
        
        guard let length = bits.unpack(bytes: 2) else { return nil }
        guard let lengthUint16 = length.maybeNetworkUint16 else { return nil }
        self.length = lengthUint16
        if debugPrint { print("・ Length: 0x" + String(format: "%02x", self.length) + " - 0d" + String(format: "%u", self.length)) }
        
        guard let checksum = bits.unpack(bytes: 2) else { return nil }
        guard let checksumUint16 = checksum.maybeNetworkUint16 else { return nil }
        self.checksum = checksumUint16
        if debugPrint { print("・ checksum: 0x" + String(format: "%02x", self.checksum)) }
        
        //payload
        if Int(bits.count/8) > 0
        {
            guard let payload = bits.unpack(bytes: Int(bits.count/8)) else { return nil }
            
            self.payload = payload
            if debugPrint
            {
                print("・ UDP payload:")
                _ = printDataBytes(bytes: payload, hexDumpFormat: true, seperator: "", decimal: false)
                print("")
            }
        }
        else
        {
            if debugPrint { print("・ UDP payload: nil\n") }
            self.payload = nil
        }
    }
    
    public var data: Data
    {
        var result = Data()
        
        result.append(sourcePort.data)
        result.append(destinationPort.data)
        result.append(length.data)
        result.append(checksum.data)
        
        if let payloadData = payload
        {
            result.append(payloadData)
        }
        return result
    }
}

extension UDP
{
    static let udpHeaderLength = 8
    
    public init?(sourcePort: UInt16, destinationPort: UInt16, payload: Data?) {
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.payload = payload
        
        
        let length: Int
        if let payload = payload {
            length = payload.count + UDP.udpHeaderLength
        } else {
            length = UDP.udpHeaderLength
        }
        
        guard length <= 65507 else {
            return nil
        }
        self.length = UInt16(length)
        self.checksum = UInt16(0)
    }
    
    public init?(sourcePort: UInt16, destinationPort: UInt16, length: UInt16, checksum: UInt16?, payload: Data?, IPv4: IPv4)
    {
        //FIX, add parameter validation code
        //write test functions for this initializer
                
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.length = length
        self.payload = payload
        
        if let checksumNonNil = checksum //if checksum is nil then calculate it otherwise use the checksum passed
        {
            self.checksum = checksumNonNil
        }
        else
        {
            self.checksum = UInt16(0)
        }
    }
}

extension UDP: CustomStringConvertible
{
    public var description: String {
        //return UDP values of interest as a human readable string
        
        var returnString: String = ""
        returnString += "Source Port: " + self.sourcePort.string + "\n"
        returnString += "Destination Port: " + self.destinationPort.string + "\n"
        returnString += "Length: 0x" + String(format: "%04x", self.length) + " - 0d" + self.length.string + "\n"
        returnString += "Checksum: 0x" + String(format: "%04x", self.checksum) + " - 0d" + self.checksum.string + "\n"
        
        if let payload = self.payload
        {
            returnString += "Payload: "
            returnString += printDataBytes(bytes: payload.data, hexDumpFormat: true, seperator: " ", decimal: false, enablePrinting: false) + "\n"
        }
        else
        {
            returnString += "Payload: nil\n"
        }
        
        return returnString
    }
}
