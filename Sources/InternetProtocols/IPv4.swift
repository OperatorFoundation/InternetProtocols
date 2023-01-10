//
//  IPv4.swift
//  
//
//  Created by Joshua Clark on 3/11/22.
//

import Foundation

import Bits
import Datable
import Net
import SwiftHexTools

public struct IPv4: Codable
{
    //http://www.networksorcery.com/enp/protocol/ip.htm
    
    static let internetHeaderLengthNoOptions: UInt8 = 5 // In 4 byte chunks
    
    public let version: Bits //UInt8 //4 bits
    public let IHL: Bits //UInt8 //4 bits
    public let DSCP: Bits //UInt8 //6 bits
    public let ECN: Bits //UInt8 //2 bits
    public let length: UInt16 //2 bytes   --number
    public let identification: UInt16 //2 bytes
    public let reservedBit: Bool //UInt8 //1 bit //bool
    public let dontFragment: Bool //UInt8 //1 bit //bool
    public let moreFragments: Bool //UInt8 //1 bit //bool
    public let fragmentOffset: UInt16 //UInt16 //13 bits   --number
    public let ttl: UInt8 //1 byte   --number
    public let protocolNumber: IPprotocolNumber //UInt8 //1 byte
    public let checksum: UInt16 //2 bytes
    public let sourceAddress: Data //4 bytes
    public let destinationAddress: Data //4 bytes
    public let options: Data? //up to 32 bytes
    public let payload: Data?
    public let ethernetPadding: Data?
}

extension IPv4: MaybeDatable
{
    public init?(data: Data)
    {
        if debugPrint { print("・ start parsing IPv4") }
        var bits = Bits(data: data)
        
        //unpack a byte then parse into bits
        guard let VerIHL = bits.unpack(bytes: 1) else { return nil }
        var VerIHLbits = Bits(data: VerIHL)
        
        guard let version = VerIHLbits.unpack(bits: 4) else { return nil }
        guard let versionUint8 = version.maybeNetworkUint8 else { return nil }
        guard versionUint8 == 4 else { return nil }
        self.version = version //Uint8
        if debugPrint { print("・ Version: 0x" + String(format: "%02x", versionUint8)) }
        
        guard let IHL = VerIHLbits.unpack(bits: 4) else { return nil }
        guard let IHLUint8 = IHL.maybeNetworkUint8 else { return nil }
        self.IHL = IHL //Uint8
        if debugPrint { print("・ IHL: 0x" + String(format: "%02x", IHLUint8)) }
        
        guard let DSCPECN = bits.unpack(bytes: 1) else { return nil }
        var DSCPECNbits = Bits(data: DSCPECN)
        guard let DSCP = DSCPECNbits.unpack(bits: 6) else { return nil }
        guard let DSCPUint8 = DSCP.maybeNetworkUint8 else { return nil }
        self.DSCP = DSCP //Uint8
        if debugPrint { print("・ DSCP: 0x" + String(format: "%02x", DSCPUint8)) }
        
        guard let ECN = DSCPECNbits.unpack(bits: 2) else { return nil }
        guard let ECNUint8 = ECN.maybeNetworkUint8 else { return nil }
        self.ECN = ECN //Uint8
        if debugPrint { print("・ ECN: 0x" + String(format: "%02x", ECNUint8)) }
        
        guard let length = bits.unpack(bytes: 2) else { return nil }
        guard let lengthUint16 = length.maybeNetworkUint16 else { return nil }
        self.length = lengthUint16
        if debugPrint { print("・ Length: 0x" + String(format: "%02x", self.length) + " - 0d" + String(format: "%u", self.length)) }
        
        guard let identification = bits.unpack(bytes: 2) else { return nil }
        guard let identificationUint16 = identification.maybeNetworkUint16 else { return nil }
        self.identification = identificationUint16
        if debugPrint { print("・ Identification: 0x" + String(format: "%02x", self.identification)) }
        
        guard let flagsFragmentOffset = bits.unpack(bytes: 2) else { return nil }
        var flagsFragmentOffsetbits = Bits(data: flagsFragmentOffset)
        
        guard let reservedBit = flagsFragmentOffsetbits.unpackBool() else { return nil }
        guard let dontFragment = flagsFragmentOffsetbits.unpackBool() else { return nil }
        guard let moreFragments = flagsFragmentOffsetbits.unpackBool() else { return nil }
        
        self.reservedBit = reservedBit
        self.dontFragment = dontFragment
        self.moreFragments = moreFragments
        
        if debugPrint { print("・ reservedBit: " + String(self.reservedBit) ) }
        if debugPrint { print("・ dontFragment: " + String(self.dontFragment) ) }
        if debugPrint { print("・ moreFragments: " + String(self.moreFragments) ) }
        
        
        guard let fragmentOffset = flagsFragmentOffsetbits.unpack(bits: 13) else { return nil }
        guard let fragmentOffsetUint16 = fragmentOffset.maybeNetworkUint16 else { return nil }
        self.fragmentOffset = fragmentOffsetUint16 //Uint16
        if debugPrint { print("・ FragmentOffset: 0d" + String(format: "%u", fragmentOffsetUint16)) }
        
        guard let ttl = bits.unpack(bytes: 1) else { return nil }
        guard let ttlUint8 = ttl.maybeNetworkUint8 else { return nil }
        self.ttl = ttlUint8
        if debugPrint { print("・ TTL: 0d" + String(format: "%u", self.ttl)) }
        
        guard let protocolNumber = bits.unpack(bytes: 1) else
        {
            _ = printDataBytes(bytes: bits.data, hexDumpFormat: false, seperator: ".", decimal: true)
            return nil
        } //fix should use IPprotocolNumber()
        guard let protocolNumberUint8 = protocolNumber.maybeNetworkUint8 else
        {
            return nil
        }
        guard let protocolNumType = IPprotocolNumber(data: protocolNumber) else
        {
            return nil
        }
        self.protocolNumber = protocolNumType
        if debugPrint { print("・ ProtocolNumber: 0d" + String(format: "%u", protocolNumberUint8 ) + " - \(protocolNumType)") }
        
        guard let checksum = bits.unpack(bytes: 2) else { return nil }
        guard let checksumUint16 = checksum.uint16 else { return nil }
        self.checksum = checksumUint16
        if debugPrint { print("・ Checksum: 0x" + String(format: "%02x", self.checksum)) }
        
        guard let sourceAddress = bits.unpack(bytes: 4) else { return nil }
        self.sourceAddress = sourceAddress.data
        if debugPrint
        {
            print("・ sourceAddress: ", terminator: "")
            _ = printDataBytes(bytes: self.sourceAddress, hexDumpFormat: false, seperator: ".", decimal: true)
        }
        
        guard let destinationAddress = bits.unpack(bytes: 4) else { return nil }
        self.destinationAddress = destinationAddress.data
        if debugPrint
        {
            print("・ destinationAddress: ", terminator: "")
            _ = printDataBytes(bytes: self.destinationAddress, hexDumpFormat: false, seperator: ".", decimal: true)
        }
        
        if IHLUint8 > 5
        {
            //options exist if IHL > 5, each IHL point is 32 bits (4 bytes), upto IHL = 15 or 320 bits, 40 bytes
            guard let options = bits.unpack(bytes: Int((IHLUint8 - 5) * 4)) else
            {
                return nil
            }
            self.options = options
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
        
        var payloadLength = lengthUint16 - UInt16(IHLUint8 * 4)
        if payloadLength > bits.count/8
        {
            if debugPrint { print("・ ⚠️ malformed packet: IPv4 total length exceeds packet length. Attempting to continue parsing packet.") }
            payloadLength = UInt16(bits.count/8)
        }
        
        guard let payload = bits.unpack(bytes: Int(payloadLength)) else
        {
            return nil
        }
        self.payload = payload
        if debugPrint
        {
            print("・ IPv4 payload:")
            _ = printDataBytes(bytes: payload, hexDumpFormat: true, seperator: "", decimal: false)
        }
        
        if bits.count > 0
        {
            guard let padding = bits.unpack(bytes: Int(bits.count/8)) else
            {
                return nil
            }
            self.ethernetPadding = padding
            if debugPrint
            {
                print("・ ethernet padding: ", terminator: "")
                _ = printDataBytes(bytes: padding, hexDumpFormat: false, seperator: " ", decimal: false)
                print("")
            }
        }
        else
        {
            self.ethernetPadding = nil
            if debugPrint { print("・ ethernet padding: nil\n") }
        }
        
    }
    
    public var data: Data
    {
        var result = Data()
        
        var verIHLDSCPECN: Bits = Bits()
        let _ = verIHLDSCPECN.pack(bits: version) //4bits
        let _ = verIHLDSCPECN.pack(bits: IHL) //4bits
        let _ = verIHLDSCPECN.pack(bits: DSCP) //6bits
        let _ = verIHLDSCPECN.pack(bits: ECN) //2bits
        result.append(verIHLDSCPECN.data)
        
        result.append(length.data)
        result.append(identification.data)
        
        var flagsFragOff: Bits = Bits()
        let _ = flagsFragOff.pack(bool: reservedBit) //1 bit
        let _ = flagsFragOff.pack(bool: dontFragment) //1 bit
        let _ = flagsFragOff.pack(bool: moreFragments) //1 bit
        let fragmentOffsetBits = Bits(bytes: fragmentOffset, droppingFromLeft: 3)!
        let _ = flagsFragOff.pack(bits: fragmentOffsetBits) //13 bits
        result.append(flagsFragOff.data)
        
        result.append(ttl)
        if let protocolNumberData = protocolNumber.data
        {
            result.append(protocolNumberData)
        }
        result.append(checksum.data)
        result.append(sourceAddress)
        result.append(destinationAddress)
        if let optionsData = options
        {
            result.append(optionsData)
        }
        if let realpayload = payload
        {
            result.append(realpayload)
        }
        
        return result
    }
}

extension IPv4
{
    public init?(version: Bits, IHL: Bits, DSCP: Bits, ECN: Bits, length: UInt16, identification: UInt16, reservedBit: Bool, dontFragment: Bool, moreFragments: Bool, fragmentOffset: UInt16, ttl: UInt8, protocolNumber: IPprotocolNumber, checksum: UInt16?, sourceAddress: Data, destinationAddress: Data, options: Data?, payload: Data?, ethernetPadding: Data?)
    {
        //FIX, add parameter validation code
        //write test functions for this initializer
        
        self.version = version
        self.IHL = IHL
        self.DSCP = DSCP
        self.ECN = ECN
        self.length = length
        self.identification = identification
        self.reservedBit = reservedBit
        self.dontFragment = dontFragment
        self.moreFragments = moreFragments
        self.fragmentOffset = fragmentOffset
        self.ttl = ttl
        self.protocolNumber = protocolNumber
        
        self.sourceAddress = sourceAddress
        self.destinationAddress = destinationAddress
        self.options = options
        self.payload = payload
        self.ethernetPadding = ethernetPadding
        
        var checksumData: Data = Data()

        var verIHL: Bits = Bits()
        let _ = verIHL.pack(bits: self.version)
        let _ = verIHL.pack(bits: self.IHL)
        checksumData.append(verIHL.data)

        var DSCPECN: Bits = Bits()
        let _ = DSCPECN.pack(bits: self.DSCP)
        let _ = DSCPECN.pack(bits: self.ECN)
        checksumData.append(DSCPECN.data)

        checksumData.append(self.length.data)
        checksumData.append(self.identification.data)

        var flagsFrags: Bits = Bits()
        let _ = flagsFrags.pack(bool: self.reservedBit)
        let _ = flagsFrags.pack(bool: self.dontFragment)
        let _ = flagsFrags.pack(bool: self.moreFragments)
        guard let fragmentOffsetBits = Bits(bytes: self.fragmentOffset, droppingFromLeft: 3) else
        {
            return nil
        }

        let _ = flagsFrags.pack(bits: fragmentOffsetBits)
        checksumData.append(flagsFrags.data)

        checksumData.append(self.ttl.data)
        checksumData.append(self.protocolNumber.rawValue)
        checksumData.append(self.sourceAddress)
        checksumData.append(self.destinationAddress)

        if let optionsData = self.options
        {
            checksumData.append(optionsData.data)
        }

        if let paddingData = self.ethernetPadding
        {
            checksumData.append(paddingData.data)
        }

        if let checkresult = calculateChecksum(bytes: checksumData)
        {
            if let checksumNotNil = checksum
            {
                guard checksumNotNil == checkresult else
                {
                    print("Checksum mismatch \(checksumNotNil) != \(checkresult)")
                    return nil
                }
            }

            self.checksum = checkresult
        }
        else
        {
            return nil
        }
    }
    
    func pseudoHeaderTCP(tcpLength: UInt16) -> Data
    {
        var results: Data = Data()
        let reservedZero: UInt8 = 0

        print("pseudoHeaderTCP")
        print("source address: \(self.sourceAddress.count) bytes - \(self.sourceAddress.hex)")
        print("destination address: \(self.destinationAddress.count) bytes - \(self.destinationAddress.hex)")
        print("reserved: \(reservedZero.data.count) bytes - \(reservedZero.data.hex)")
        print("protocolNumber: \(self.protocolNumber.rawValue.data.count) bytes - \(self.protocolNumber.rawValue.data.hex) (\(self.protocolNumber))")
        print("tcpLength: \(tcpLength.data.count) bytes - \(tcpLength.data.hex) (\(tcpLength))")

        results.append(self.sourceAddress)
        results.append(self.destinationAddress)
        results.append(reservedZero.data)
        results.append(self.protocolNumber.rawValue)
        results.append(tcpLength.maybeNetworkData!)
        
        return results
    }
    
    func pseudoHeaderUDP(udpLength: UInt16) -> Data
    {
        var results: Data = Data()
        let reservedZero: UInt8 = 0
        results.append(self.sourceAddress)
        results.append(self.destinationAddress)
        results.append(reservedZero.data)
        results.append(self.protocolNumber.rawValue)
        results.append(udpLength.data)
        
        return results
    }
}

extension IPv4
{
    public init?(sourceAddress: IPv4Address, destinationAddress: IPv4Address, payload: Data?, protocolNumber: IPprotocolNumber) throws
    {
    //  checksum: UInt16?, sourceAddress: Data, destinationAddress: Data, options: Data?, payload: Data?, ethernetPadding: Data?
        guard let version = Bits(byte: 4, droppingFromLeft: 4) else {
            return nil
        }
        
        guard let ihl = Bits(byte: IPv4.internetHeaderLengthNoOptions, droppingFromLeft: 4) else {
            return nil
        }
                
        // TODO: might need to change later, unsure of proper value
        // see Configuration guidelines section, Service class: Standard in: https://en.wikipedia.org/wiki/Differentiated_services
        guard let dscp = Bits(byte: 0, droppingFromRight: 2) else {
            return nil
        }
        
        // TODO: might need to change later, unsure of proper value
        // see Operation of ECN with IP section in: https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
        guard let ecn = Bits(byte: 0, droppingFromLeft: 6) else {
            return nil
        }
        
        let length: UInt16
        if let payload = payload
        {
            length = UInt16(payload.count) + (UInt16(IPv4.internetHeaderLengthNoOptions) * 4)
        }
        else
        {
            length = UInt16(IPv4.internetHeaderLengthNoOptions) * 4 // internetHeaderLengthNoOptions is in 4 byte chunks
        }
        
        // see https://datatracker.ietf.org/doc/html/rfc6864
        let identification = UInt16.random(in: 0...UInt16.max)
        
        let reservedBit = false
        let dontFragment = false
        let moreFragments = false

        // see https://en.wikipedia.org/wiki/Time_to_live#:~:text=In%20the%20IPv4%20header%2C%20TTL,recommended%20initial%20value%20is%2064
        let ttl = UInt8(64)
        
        let protocolNumber = protocolNumber
        
        self.init(version: version, IHL: ihl, DSCP: dscp, ECN: ecn, length: length, identification: identification, reservedBit: reservedBit, dontFragment: dontFragment, moreFragments: moreFragments, fragmentOffset: 0, ttl: ttl, protocolNumber: protocolNumber, checksum: nil, sourceAddress: sourceAddress.rawValue, destinationAddress: destinationAddress.rawValue, options: nil, payload: payload, ethernetPadding: nil)
    }
    
    // returns IPv4 header with TCP payload
    public init?(sourceAddress: IPv4Address, destinationAddress: IPv4Address, sourcePort: UInt16, destinationPort: UInt16, sequenceNumber: SequenceNumber = SequenceNumber(0), acknowledgementNumber: SequenceNumber = SequenceNumber(0), syn: Bool = false, ack: Bool = false, fin: Bool = false, rst: Bool = false, windowSize: UInt16, payload: Data? = nil) throws
    {
        guard let ipv4 = try IPv4(sourceAddress: sourceAddress, destinationAddress: destinationAddress, payload: nil, protocolNumber: IPprotocolNumber.TCP) else {
            return nil
        }
        
        guard let tcp = try TCP(sourcePort: sourcePort, destinationPort: destinationPort, sequenceNumber: sequenceNumber, acknowledgementNumber: acknowledgementNumber, syn: syn, ack: ack, fin: fin, rst: rst, windowSize: windowSize, payload: payload, ipv4: ipv4) else {
            return nil
        }
        
        try self.init(sourceAddress: sourceAddress, destinationAddress: destinationAddress, payload: tcp.data, protocolNumber: IPprotocolNumber.TCP)
    }
}

extension IPv4: CustomStringConvertible
{
    public var description: String {
        //return IPv4 values of interest as a human readable string
        var returnString: String = ""
        
        guard let versionUint8 = version.maybeNetworkUint8 else { return "Error converting version" }
        returnString += "Version: 0x" + String(format: "%02x", versionUint8) + " - 0b" + String(versionUint8, radix: 2) + "\n"
        
        guard let IHLUint8 = IHL.maybeNetworkUint8 else { return "Error converting IHL" }
        returnString += "IHL: 0x" + String(format: "%02x", IHLUint8) + " - 0b" + String(IHLUint8, radix: 2) + "(" + String(IHLUint8 * 4) + " bytes)\n"
        
        guard let DSCPUint8 = DSCP.maybeNetworkUint8 else { return "Error converting DSCP" }
        returnString += "DSCP: 0x" + String(format: "%02x", DSCPUint8) + " - 0b" + String(DSCPUint8, radix: 2) + "\n"
        
        guard let ECNUint8 = ECN.maybeNetworkUint8 else { return "Error converting ECN" }
        returnString += "ECN: 0x" + String(format: "%02x", ECNUint8) + " - 0b" + String(ECNUint8, radix: 2) + "\n"
        
        returnString += "Length: 0x" + String(format: "%04x", self.length) + " - 0d" + self.length.string + "\n"
        returnString += "Identification: 0x" + String(format: "%04x", self.identification) + " - 0d" + self.identification.string + "\n"
        
        returnString += "Reserved: " + String(self.reservedBit) + "\n"
        returnString += "Don't Fragment: " + String(self.dontFragment) + "\n"
        returnString += "More Fragments: " + String(self.moreFragments) + "\n"
        
        returnString += "FragmentOffset: 0x" + String(format: "%04x", fragmentOffset) + "\n"
        
        returnString += "TTL: 0x" + String(format: "%02x", self.ttl) + " - 0d" + self.ttl.string + "\n"
        
        returnString += "Protocol Number: 0x" + String(format: "%02x", self.protocolNumber.rawValue) + " - \(self.protocolNumber)\n"
        
        returnString += "Checksum: 0x" + String(format: "%04x", self.checksum) + " - 0d" + self.checksum.string + "\n"
        
        returnString += "Source Address: "
        returnString += printDataBytes(bytes: sourceAddress.data, hexDumpFormat: false, seperator: ".", decimal: true, enablePrinting: false)
        returnString += " ("
        returnString += printDataBytes(bytes: sourceAddress.data, hexDumpFormat: false, seperator: " ", decimal: false, enablePrinting: false)
        returnString +=  ")\n"
        
        returnString += "Destination Address: "
        returnString += printDataBytes(bytes: destinationAddress.data, hexDumpFormat: false, seperator: ".", decimal: true, enablePrinting: false)
        returnString += " ("
        returnString += printDataBytes(bytes: destinationAddress.data, hexDumpFormat: false, seperator: " ", decimal: false, enablePrinting: false)
        returnString +=  ")\n"
        
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
            returnString += "Payload: \n"
            returnString += printDataBytes(bytes: payload.data, hexDumpFormat: true, seperator: " ", decimal: false, enablePrinting: false) + "\n"
        }
        else
        {
            returnString += "Payload: nil\n"
        }
        
        return returnString
    }
}


