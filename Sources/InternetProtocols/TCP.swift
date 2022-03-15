//
//  File.swift
//  
//
//  Created by Joshua Clark on 3/11/22.
//

import Bits
import Datable
import Foundation

public struct TCP: Codable
{
    static let tcpDataOffsetNoOptions: Bits! = Bits(byte: 5, droppingFromLeft: 4)
    
    public let sourcePort: UInt16 //2 bytes
    public let destinationPort: UInt16 //2 bytes
    public let sequenceNumber: Data //4 bytes
    public let acknowledgementNumber: Data //4 bytes
    public let offset: Bits //4 bits
    public let reserved: Bits //3 bits
    public let ns: Bool //1 bit
    public let cwr: Bool //1 bit
    public let ece: Bool //1 bit
    public let urg: Bool //1 bit
    public let ack: Bool //1 bit
    public let psh: Bool //1 bit
    public let rst: Bool //1 bit
    public let syn: Bool //1 bit
    public let fin: Bool //1 bit
    public let windowSize: UInt16 //2 bytes
    public let checksum: UInt16 //2 bytes
    public let urgentPointer: UInt16 //2 bytes
    public let options: Data?
    public let payload: Data?
}

extension TCP: MaybeDatable
{
    public init?(data: Data)
    {
        //https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
        //https://tools.ietf.org/html/rfc7414 - roadmap to TCP RFCs
        
        if debugPrint { print("・ start parsing TCP") }
        
        var bits = Bits(data: data)
        
        guard let sourcePort = bits.unpack(bytes: 2) else { return nil }
        guard let sourcePortUint16 = sourcePort.maybeNetworkUint16 else { return nil }
        self.sourcePort = sourcePortUint16
        if debugPrint { print("・ sourcePort: 0x" + String(format: "%02x", self.sourcePort) + " - 0d" + String(format: "%u", self.sourcePort)) }
        
        guard let destinationPort = bits.unpack(bytes: 2) else { return nil }
        guard let destinationPortUint16 = destinationPort.maybeNetworkUint16 else { return nil }
        self.destinationPort = destinationPortUint16
        if debugPrint { print("・ destPort: 0x" + String(format: "%02x", self.destinationPort) + " - 0d" + String(format: "%u", self.destinationPort)) }
        
        guard let sequenceNumber = bits.unpack(bytes: 4) else { return nil }
        self.sequenceNumber = sequenceNumber.data
        if debugPrint
        {
            print("・ SequenceNum: 0x", terminator: "")
            _ = printDataBytes(bytes: sequenceNumber, hexDumpFormat: false, seperator: "", decimal: false)
        }
        
        guard let acknowledgementNumber = bits.unpack(bytes: 4) else { return nil }
        self.acknowledgementNumber = acknowledgementNumber.data
        if debugPrint
        {
            print("・ acknowledgementNum: 0x", terminator: "")
            _ = printDataBytes(bytes: acknowledgementNumber, hexDumpFormat: false, seperator: "", decimal: false)
        }
        
        guard let offsetReservedFlags = bits.unpack(bytes: 2) else { return nil }
        var dataReservedFlagsBits = Bits(data: offsetReservedFlags)
        guard let offsetReservedFlagsUint16 = offsetReservedFlags.maybeNetworkUint16 else { return nil }
        if debugPrint { print("・ offsetReservedFlags: 0x" + String(format: "%02x", offsetReservedFlagsUint16) + " - 0b" + String(offsetReservedFlagsUint16, radix: 2)) }
        
        guard let offset = dataReservedFlagsBits.unpack(bits: 4) else { return nil }
        guard let offsetUint8 = offset.maybeNetworkUint8 else { return nil }
        self.offset = offset
        if debugPrint { print("・ Offset: 0x" + String(format: "%02x", offsetUint8) + " - 0b" + String(offsetUint8, radix: 2)) }
        
        guard let reserved = dataReservedFlagsBits.unpack(bits: 3) else { return nil }
        guard let reservedUint8 = reserved.maybeNetworkUint8 else { return nil }
        self.reserved = reserved
        if debugPrint { print("・ reserved: 0x" + String(format: "%02x", reservedUint8) + " - 0b" + String(reservedUint8, radix: 2)) }
        
        guard let ns = dataReservedFlagsBits.unpackBool() else { return nil }
        self.ns = ns
        if debugPrint { print("・ ns: " + String(ns) ) }
        
        guard let cwr = dataReservedFlagsBits.unpackBool() else { return nil }
        self.cwr = cwr
        if debugPrint { print("・ cwr: " + String(self.cwr)) }
        
        guard let ece = dataReservedFlagsBits.unpackBool() else { return nil }
        self.ece = ece
        if debugPrint { print("・ ece: " + String(self.ece)) }
        
        guard let urg = dataReservedFlagsBits.unpackBool() else { return nil }
        self.urg = urg
        if debugPrint { print("・ urg: " + String(self.urg)) }
        
        guard let ack = dataReservedFlagsBits.unpackBool() else { return nil }
        self.ack = ack
        if debugPrint { print("・ ack: " + String(self.ack)) }
        
        guard let psh = dataReservedFlagsBits.unpackBool() else { return nil }
        self.psh = psh
        if debugPrint { print("・ psh: " + String(self.psh)) }
        
        guard let rst = dataReservedFlagsBits.unpackBool() else { return nil }
        self.rst = rst
        if debugPrint { print("・ rst: " + String(self.rst)) }
        
        guard let syn = dataReservedFlagsBits.unpackBool() else { return nil }
        self.syn = syn
        if debugPrint { print("・ syn: " + String(self.syn)) }
        
        guard let fin = dataReservedFlagsBits.unpackBool() else { return nil }
        self.fin = fin
        if debugPrint { print("・ fin: " + String(self.fin)) }
        
        guard let windowSize = bits.unpack(bytes: 2) else { return nil }
        guard let windowSizeUint16 = windowSize.maybeNetworkUint16 else { return nil }
        self.windowSize = windowSizeUint16
        if debugPrint { print("・ windowSize: 0x" + String(format: "%02x", self.windowSize) + " - 0d" + String(format: "%u", self.windowSize)) }
        
        guard let checksum = bits.unpack(bytes: 2) else { return nil }
        guard let checksumUint16 = checksum.maybeNetworkUint16 else { return nil }
        self.checksum = checksumUint16
        if debugPrint { print("・ checksum: 0x" + String(format: "%02x", self.checksum) + " - 0d" + String(format: "%u", self.checksum)) }
        
        guard let urgentPointer = bits.unpack(bytes: 2) else { return nil }
        guard let urgentPointerUint16 = urgentPointer.maybeNetworkUint16 else { return nil }
        self.urgentPointer = urgentPointerUint16
        if debugPrint { print("・ urgentPointer: 0x" + String(format: "%02x", self.urgentPointer) + " - 0d" + String(format: "%u", self.urgentPointer)) }
        
        if offsetUint8  > 5 && offsetUint8 < 16
        {
            let bytesToRead = Int((offsetUint8 - 5) * 4)
            guard let options = bits.unpack(bytes: bytesToRead) else { return nil }
            self.options = options.data
            
            if debugPrint
            {
                print("・ options: ", terminator: "")
                _ = printDataBytes(bytes: options, hexDumpFormat: false, seperator: " ", decimal: false)
            }
        }
        else
        {
            if debugPrint { print("・ options: nil") }
            self.options = nil
        }
        
        if Int(bits.count/8) > 0
        {
            guard let payload = bits.unpack(bytes: Int(bits.count/8)) else { return nil }
            self.payload = payload
            if debugPrint
            {
                print("・ TCP payload:")
                _ = printDataBytes(bytes: payload, hexDumpFormat: true, seperator: "", decimal: false)
                print("")
            }
        }
        else
        {
            if debugPrint { print("・ TCP payload: nil\n") }
            self.payload = nil
        }
    }
    
    public var data: Data
    {
        var result = Data()
        result.append(sourcePort.data)
        result.append(destinationPort.data)
        result.append(sequenceNumber.data)
        result.append(acknowledgementNumber.data)
        
        var offsetReservedFlags: Bits = Bits()
        let _ = offsetReservedFlags.pack(bits: offset)
        let _ = offsetReservedFlags.pack(bits: reserved)
        let _ = offsetReservedFlags.pack(bool: ns)
        let _ = offsetReservedFlags.pack(bool: cwr)
        let _ = offsetReservedFlags.pack(bool: ece)
        let _ = offsetReservedFlags.pack(bool: urg)
        let _ = offsetReservedFlags.pack(bool: ack)
        let _ = offsetReservedFlags.pack(bool: psh)
        let _ = offsetReservedFlags.pack(bool: rst)
        let _ = offsetReservedFlags.pack(bool: syn)
        let _ = offsetReservedFlags.pack(bool: fin)
        result.append(offsetReservedFlags.data)
        
        result.append(windowSize.data)
        result.append(checksum.data)
        result.append(urgentPointer.data)
        if let optionsData = options
        {
            result.append(optionsData)
        }
        if let payloadData = payload
        {
            result.append(payloadData)
        }
        return result
    }
}

extension TCP
{
    public init?(sourcePort: UInt16, destinationPort: UInt16, sequenceNumber: Data, acknowledgementNumber: Data,
                 offset: Bits, reserved: Bits, ns: Bool, cwr: Bool, ece: Bool, urg: Bool, ack: Bool, psh: Bool,
                 rst: Bool, syn: Bool, fin: Bool, windowSize: UInt16, checksum: UInt16?, urgentPointer: UInt16,
                 options: Data?, payload: Data?, IPv4: IPv4)
    {
        //FIX, add parameter validation code
        //write test functions for this initializer
        
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.sequenceNumber = sequenceNumber
        self.acknowledgementNumber = acknowledgementNumber
        self.offset = offset
        self.reserved = reserved
        self.ns = ns
        self.cwr = cwr
        self.ece = ece
        self.urg = urg
        self.ack = ack
        self.psh = psh
        self.rst = rst
        self.syn = syn
        self.fin = fin
        self.windowSize = windowSize
        self.urgentPointer = urgentPointer
        self.options = options
        self.payload = payload
        
        if let checksumNonNil = checksum //if checksum is nil then calculate it otherwise use the checksum passed
        {
            self.checksum = checksumNonNil
        }
        else
        {
            var checksumData: Data = Data()
            
            let psuedoheader = IPv4.pseudoHeaderTCP
            
            //pack all the tcp stuff and the psudo header, then calculate the checksum
            //handle optionals
            checksumData.append(psuedoheader)
            checksumData.append(self.sourcePort.data)
            checksumData.append(self.destinationPort.data)
            checksumData.append(self.sequenceNumber)
            checksumData.append(self.acknowledgementNumber)
            var offsetReservedFlags: Bits = Bits()
            let _ = offsetReservedFlags.pack(bits: self.offset)
            let _ = offsetReservedFlags.pack(bits: self.reserved)
            let _ = offsetReservedFlags.pack(bool: self.ns)
            let _ = offsetReservedFlags.pack(bool: self.cwr)
            let _ = offsetReservedFlags.pack(bool: self.ece)
            let _ = offsetReservedFlags.pack(bool: self.urg)
            let _ = offsetReservedFlags.pack(bool: self.ack)
            let _ = offsetReservedFlags.pack(bool: self.psh)
            let _ = offsetReservedFlags.pack(bool: self.rst)
            let _ = offsetReservedFlags.pack(bool: self.syn)
            let _ = offsetReservedFlags.pack(bool: self.fin)
            
            checksumData.append(offsetReservedFlags.data)
            checksumData.append(self.windowSize.data)
            
            checksumData.append(self.urgentPointer.data)
            
            if let optionsData = self.options
            {
                checksumData.append(optionsData.data)
            }
            
            if let payloadData = self.payload
            {
                checksumData.append(payloadData)
            }
            
            if let checkresult = calculateChecksum(bytes: checksumData)
            {
                self.checksum = checkresult
            }
            else
            {
                return nil
            }
        }
        
        
    }
    
    
}

extension TCP
{
    // does not calculate checksum
    // used exclusively for the IPv4 init with TCP payload
    public init(sourcePort: UInt16, destinationPort: UInt16, sequenceNumber: SequenceNumber = SequenceNumber(0), acknowledgementNumber: SequenceNumber = SequenceNumber(0), syn: Bool = false, ack: Bool = false, fin: Bool = false, rst: Bool = false, windowSize: UInt16, payload: Data? = nil) throws
    {
        let reserved: Bits! = Bits(byte: 0, droppingFromLeft: 5)

        // does not calculate checksum
        self.init(sourcePort: sourcePort, destinationPort: destinationPort, sequenceNumber: sequenceNumber.data, acknowledgementNumber: acknowledgementNumber.data, offset: TCP.tcpDataOffsetNoOptions, reserved: reserved, ns: false, cwr: false, ece: false, urg: false, ack: ack, psh: false, rst: rst, syn: syn, fin: fin, windowSize: windowSize, checksum: 0, urgentPointer: 0, options: nil, payload: payload)
    }
    
    // does calculate checksum, but requires IPv4 parameter
    public init?(sourcePort: UInt16, destinationPort: UInt16, sequenceNumber: SequenceNumber = SequenceNumber(0), acknowledgementNumber: SequenceNumber = SequenceNumber(0), syn: Bool = false, ack: Bool = false, fin: Bool = false, rst: Bool = false, windowSize: UInt16, payload: Data? = nil, ipv4: IPv4) throws
    {
        let reserved: Bits! = Bits(byte: 0, droppingFromLeft: 5)
    
        
        self.init(sourcePort: sourcePort, destinationPort: destinationPort, sequenceNumber: sequenceNumber.data, acknowledgementNumber: acknowledgementNumber.data, offset: TCP.tcpDataOffsetNoOptions, reserved: reserved, ns: false, cwr: false, ece: false, urg: false, ack: ack, psh: false, rst: rst, syn: syn, fin: fin, windowSize: windowSize, checksum: nil, urgentPointer: 0, options: nil, payload: payload, IPv4: ipv4)
    }
}

extension TCP: CustomStringConvertible
{
    public var description: String {
        //return TCP values of interest as a human readable string
        
        var returnString: String = ""
        
        returnString += "Source Port: " + self.sourcePort.string + "\n"
        returnString += "Destination Port: " + self.destinationPort.string + "\n"
        
        returnString += "Sequence Number: "
        returnString += printDataBytes(bytes: sequenceNumber.data, hexDumpFormat: false, seperator: " ", decimal: false, enablePrinting: false) + "\n"
        
        returnString += "Acknowledgement Number: "
        returnString += printDataBytes(bytes: acknowledgementNumber.data, hexDumpFormat: false, seperator: " ", decimal: false, enablePrinting: false) + "\n"
        
        guard let offsetUint8 = offset.maybeNetworkUint8 else { return "Error converting offset" }
        returnString += "Offset: 0x" + String(format: "%02x", offsetUint8) + " - 0b" + String(offsetUint8, radix: 2) + "\n"
        
        guard let reservedUint8 = reserved.maybeNetworkUint8 else { return "Error converting reserved" }
        returnString += "Reserved: 0x" + String(format: "%02x", reservedUint8) + " - 0b" + String(reservedUint8, radix: 2) + "\n"
        
        returnString += "NS: " + String(self.ns) + "\n"
        returnString += "CWR: " + String(self.cwr) + "\n"
        returnString += "ECE: " + String(self.ece) + "\n"
        returnString += "URG: " + String(self.urg) + "\n"
        returnString += "ACK: " + String(self.ack) + "\n"
        returnString += "PSH: " + String(self.psh) + "\n"
        returnString += "RST: " + String(self.rst) + "\n"
        returnString += "SYN: " + String(self.syn) + "\n"
        returnString += "FIN: " + String(self.fin) + "\n"
        returnString += "Window Size: 0x" + String(format: "%04x", self.windowSize) + " - 0d" + self.windowSize.string + "\n"
        returnString += "Checksum: 0x" + String(format: "%04x", self.checksum) + " - 0d" + self.checksum.string + "\n"
        returnString += "Urgent Pointer: 0x" + String(format: "%04x", self.urgentPointer) + " - 0d" + self.urgentPointer.string + "\n"
        
        if let options = self.options
        {
            returnString += "Options: "
            returnString += printDataBytes(bytes: options.data, hexDumpFormat: false, seperator: " ", decimal: false, enablePrinting: false) + "\n"
        }
        else
        {
            returnString += "Options: nil\n"
        }
        
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
