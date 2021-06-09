//
//  Parser.swift
//
//
//  Created by Dr. Brandon Wiley on 3/9/20.
//

import Foundation
import Datable
import Bits

public var debugPrint: Bool = false

public func printDataBytes(bytes: Data, hexDumpFormat: Bool, seperator: String, decimal: Bool, enablePrinting: Bool = true) -> String
{
    var returnString: String = ""
    if hexDumpFormat
    {
        var count = 0
        var newLine: Bool = true
        for byte in bytes
        {
            if newLine
            {
                if enablePrinting { print("・ ", terminator: "") }
                newLine = false
            }
            if enablePrinting { print(String(format: "%02x", byte), terminator: " ") }
            returnString += String(format: "%02x", byte)
            returnString += " "
            count += 1
            if count % 8 == 0
            {
                if enablePrinting { print(" ", terminator: "") }
                returnString += " "
            }
            if count % 16 == 0
            {
                if enablePrinting { print("") }
                returnString += "\n"
                newLine = true
            }
        }
    }
    else
    {
        var i = 0
        for byte in bytes
        {
            if decimal
            {
                if enablePrinting { print(String(format: "%u", byte), terminator: "") }
                returnString += String(format: "%u", byte)
            }
            else
            {
                if enablePrinting { print(String(format: "%02x", byte), terminator: "") }
                returnString += String(format: "%02x", byte)
            }
            i += 1
            if i < bytes.count
            {
                if enablePrinting { print(seperator, terminator: "") }
                returnString += seperator
            }
        }
    }
    if enablePrinting { print("") }
    return returnString
}

public func calculateChecksum(bytes: Data) -> UInt16?
{
    // ref https://en.wikipedia.org/wiki/IPv4_header_checksum
    // ref https://tools.ietf.org/html/rfc791#page-14 //IP
    // ref https://tools.ietf.org/html/rfc793#page-16 //TCP
    // ref https://tools.ietf.org/html/rfc768 //UDP
    // note when sending UDP packet, the checksum is optional and is indicated as not being calculated when 0x0000 is sent, so if sending wiht a checksum and the calculated checksum = 0x0000 then you must send 0xFFFF or things will think it was not calculated
    
    var sum: UInt32 = 0 //0xFFFF + 0xFFFF = 0x1FFFE which is more than a UInt16 can hold
    
    var ourBytes = bytes
    
    if ourBytes.count % 2 != 0 //make sure we have an even number of bytes
    {
        ourBytes.append(0x00) //per RFCs append a 0x00 byte to the end to make it even, then calc checksum
    }
    
    for i in 0..<(ourBytes.count/2) //2 bytes at a time
    {
        let twoBytes = ourBytes.subdata( in: (i*2)..<(i*2+2) )
        
        guard let value = twoBytes.uint32 else { return nil } //convert bytes to number value
        
        sum += value //add number value to sum
        if sum > 0xFFFF //handle carry by subtracting 0xFFFF
        {
            sum -= 0xFFFF
        }
    }
    let checksum = ~UInt16(sum) //one's compliment of sum returned as 2 bytes (UInt16)
    
    return checksum
}

public struct Packet: Codable
{
    public let rawBytes: Data
    public let timestamp: Int //time in microseconds since unix epoch
    public var ethernet: Ethernet?
    public var ipv4: IPv4?
    public var tcp: TCP?
    public var udp: UDP?
    public var debugPrints: Bool?
    
    public init(rawBytes: Data, timestamp: Date,  debugPrints: Bool = false)
    {
        debugPrint = debugPrints
        
        self.rawBytes = rawBytes
        
        // Multiply time interval by 1,000,000 before converting to an int to retain microseconds precision
        self.timestamp = Int(timestamp.timeIntervalSince1970 * 1000000)
        
        if debugPrint
        {
            print("・ timestamp (in microseconds): \(self.timestamp)")
        }
        
        if let ethernetPacket = Ethernet(data: rawBytes )
        {
            self.ethernet = ethernetPacket
            
            if ethernetPacket.type == EtherType.IPv4
            {
                if let IPv4Packet = IPv4(data: ethernetPacket.payload)
                {
                    self.ipv4 = IPv4Packet
                    
                    if let payload = IPv4Packet.payload
                    {
                        switch IPv4Packet.protocolNumber
                        {
                        case .TCP:
                            if let TCPsegment = TCP(data: payload)
                            {
                                self.tcp = TCPsegment
                            }
                        case .UDP:
                            if let UDPsegment = UDP(data: payload)
                            {
                                self.udp = UDPsegment
                            }
                        default :
                            return
                        }
                    }
                }
            }
        }
    }
}

// IEEE 802.3 Ethernet frame
public struct Ethernet: Codable
{
    public let MACDestination: Data // 6 bytes
    public let MACSource: Data // 6 bytes
    public let type: EtherType? // 2 bytes
    public let tag1: Data? // 4 bytes
    public let tag2: Data? // 4 bytes
    public let payload: Data // variable, 46-1500 bytes, specified by length
    public let size: UInt16? //for 802.3 Ethernet where ethertype is actually the size
}

extension Ethernet: MaybeDatable
{
    public init?(data: Data)
    {
        if debugPrint { print("・ Start parsing Ethernet") }
        DatableConfig.endianess = .little
        var bits = Bits(data: data)
        
        guard let MACDestination = bits.unpack(bytes: 6) else
        {
            return nil
        }
        self.MACDestination = MACDestination
        if debugPrint
        {
            print("・ dst: ", terminator: "")
            _ = printDataBytes(bytes: self.MACDestination, hexDumpFormat: false, seperator: ":", decimal: false)
            
        }
        
        guard let MACSource = bits.unpack(bytes: 6) else
        {
            return nil
        }
        self.MACSource = MACSource
        if debugPrint
        {
            print("・ src: ", terminator: "")
            _ = printDataBytes(bytes: self.MACSource, hexDumpFormat: false, seperator: ":", decimal: false)
            
        }
        
        // links for type or tag documentation
        // https://en.wikipedia.org/wiki/IEEE_802.1Q
        // https://en.wikipedia.org/wiki/EtherType
        // https://en.wikipedia.org/wiki/IEEE_802.1ad
        guard let typeOrTagPrefix = bits.unpack(bytes: 2) else
        {
            return nil
        }
        if debugPrint
        {
            print("・ typeOrTagPrefix: 0x", terminator: "")
            _ = printDataBytes(bytes: typeOrTagPrefix, hexDumpFormat: false, seperator: "", decimal: false)
        }
        
        DatableConfig.endianess = .big
        guard var typeOrTagUInt16 = typeOrTagPrefix.uint16 else
        {
            return nil
        }
        if debugPrint { print("・ typeOrTagPrefix: 0d\(typeOrTagUInt16)") }
        
        
        if typeOrTagUInt16 < 1537 //value represents size and not a type
        {
            self.size = typeOrTagUInt16
            if debugPrint { print("・ 802.3 Size: 0d\(typeOrTagUInt16)") }
            typeOrTagUInt16 = 0x0000
        }
        else
        {
            self.size = nil
        }
        
        let tempType = EtherType(data: typeOrTagUInt16)
        //        {
        //            if debugPrint { print("・ This EtherType is not known to parser") }
        //
        //            //return nil
        //        }
        //
        switch tempType
        {
        //fix, add cases for other ethertypes
        case .IPv4:
            guard let tempType = EtherType(data: typeOrTagUInt16) else
            {
                return nil
            }
            self.tag1 = nil
            self.tag2 = nil
            self.type = tempType
            
        case .singleTagVLAN:
            //type is really vlan tag 802.1Q, type=0x8100
            guard let tag2 = bits.unpack(bytes: 2) else
            {
                return nil
            } //collect 2nd half of tag
            
            //Combine type and tag2 then store in self.tag1
            //fix, should the tag be both the 0x8100 and VLAN ID?
            var tempTag = typeOrTagPrefix
            tempTag.append(tag2.data)
            self.tag1 = tempTag.data
            
            //update the type since this frame has 802.1Q tagging and type comes after the tag
            guard let type = bits.unpack(bytes: 2) else
            {
                return nil
            }
            guard let typeUInt16 = type.uint16 else
            {
                return nil
            }
            
            if typeUInt16 > 1536
            {
                guard let tempType = EtherType(data: typeUInt16) else
                {
                    return nil
                }
                self.type = tempType
                self.tag2 = nil
            }
            else
            {
                self.type = nil
                self.tag2 = nil
            }
            
        case .IPv6:
            guard let tempType = EtherType(data: typeOrTagUInt16) else
            {
                return nil
            }
            self.tag1 = nil
            self.tag2 = nil
            self.type = tempType
            
        case .ARP:
            guard let tempType = EtherType(data: typeOrTagUInt16) else
            {
                return nil
            }
            self.tag1 = nil
            self.tag2 = nil
            self.type = tempType
            
        case nil:
            if debugPrint { print("・ This EtherType is unknown: \(String(describing: tempType))") }
            self.tag1 = nil
            self.tag2 = nil
            self.type = tempType
            
        default:
            if debugPrint { print("・ This EtherType is not currently handled: \(String(describing: tempType))") }
            self.tag1 = nil
            self.tag2 = nil
            self.type = tempType
        }
        
        
        if let tag1 = self.tag1
        {
            if debugPrint
            {
                print("・ Tag1: 0x", terminator: "")
                _ = printDataBytes(bytes: tag1, hexDumpFormat: false, seperator: "", decimal: false)
            }
        }
        else
        {
            if debugPrint { print("・ Tag1: nil") }
        }
        
        if let tag2 = self.tag2
        {
            if debugPrint
            {
                print("・ Tag2: 0x", terminator: "")
                _ = printDataBytes(bytes: tag2, hexDumpFormat: false, seperator: "", decimal: false)
            }
        }
        else
        {
            if debugPrint { print("・ Tag2: nil") }
        }
        if debugPrint {
            if let typeUnwrapped = self.type
            {
                print("・ EtherType: \(typeUnwrapped)")
                if let typeUnData = typeUnwrapped.data
                {
                    print("・ EtherType: 0x", terminator: "")
                    _ = printDataBytes(bytes: typeUnData, hexDumpFormat: false, seperator: "", decimal: false)
                }
            }
            else
            {
                print("・ Ethertype: nil")
            }
            
            
        }
        
        
        guard let payload = bits.unpack(bytes: Int(bits.count/8)) else
        {
            return nil
        }
        self.payload = payload
        if debugPrint
        {
            print("・ Ethernet payload:")
            _ = printDataBytes(bytes: payload, hexDumpFormat: true, seperator: "", decimal: false)
            print("")
        }
    }
    
    
    public var data: Data
    {
        DatableConfig.endianess = .big
        var result = Data()
        
        result.append(MACDestination)
        result.append(MACSource)
        
        if let typeUnwrapped = type
        {
            if let typeData = typeUnwrapped.data
            {
                result.append(typeData)
            }
        }
        
        if let t = tag1
        {
            result.append(t)
        }
        
        if let t = tag2
        {
            result.append(t)
        }
        
        result.append(payload)
        
        return result
    }
}

extension Ethernet
{
    public init?(MACDestination: Data, MACSource: Data, type: EtherType?, tag1: Data?, tag2: Data?, payload: Data, ethernetSize: UInt16? )
    {
        //FIX, add parameter validation code
        //use asserts for something that should always be true
        
        //size checks, then parse and check that results match
        //checks to make sure the type/tag/size/length all make sense. For example if the ethertype doesn't match vlan tagging then there should be a nil tag1 and tag2. etc
        //write test functions for this initializer
        
        if MACDestination.count == 6
        {
            self.MACDestination = MACDestination
        }
        else
        {
            return nil
        }
        
        if MACSource.count == 6
        {
            self.MACSource = MACSource
        }
        else
        {
            return nil
        }
        
        if let passedType = type
        {
            if let typeData = passedType.data
            {
                if typeData.count == 2
                {
                    self.type = type
                }
                else
                {
                    return nil
                }
            }
            else
            {
                return nil
            }
        }
        else
        {
            self.type = nil
        }

        if let passedTag1 = tag1
        {
            if passedTag1.count == 4
            {
                self.tag1 = tag1
            }
            else
            {
                return nil
            }
        }
        else
        {
            self.tag1 = nil
        }
      
        if let passedTag2 = tag2
        {
            if passedTag2.count == 4
            {
                self.tag2 = tag2
            }
            else
            {
                return nil
            }
        }
        else
        {
            self.tag2 = nil
        }
        
        if payload.count >= 46 && payload.count <= 1500
        {
            self.payload = payload
        }
        else
        {
            return nil
        }
        
        if let passedEthernetSize = ethernetSize
        {
            if passedEthernetSize <= 1536 && passedEthernetSize >= 46
            {
                self.size = ethernetSize
            }
            else
            {
                return nil
            }
        }
        else
        {
            self.size = nil
        }
        
        
        if let parsedEthernet = Ethernet(data: self.data)
        {
            if parsedEthernet.MACDestination != self.MACDestination
            {
                return nil
            }
            
            if parsedEthernet.MACSource != self.MACSource
            {
                return nil
            }
            
            if parsedEthernet.payload != self.payload
            {
                return nil
            }
            
            if parsedEthernet.type != self.type
            {
                return nil
            }
            
            if parsedEthernet.tag1 != self.tag1
            {
                return nil
            }
            
            if parsedEthernet.tag2 != self.tag2
            {
                return nil
            }
            
            if parsedEthernet.size != self.size
            {
                return nil
            }
            
            
        }
        else
        {
            return nil
        }

        
    }

}

extension Ethernet: CustomStringConvertible
{
    public var description: String {
        //return Ethernet values of interest as a human readable string
        var returnString: String = ""
        
        returnString += "MAC Destination: "
        returnString += printDataBytes(bytes: MACDestination.data, hexDumpFormat: false, seperator: ":", decimal: false, enablePrinting: false)
        returnString += "\n"
        
        returnString += "MAC Source: "
        returnString += printDataBytes(bytes: MACSource.data, hexDumpFormat: false, seperator: ":", decimal: false, enablePrinting: false)
        returnString += "\n"
        
        if let type = self.type
        {
            returnString += "Ether Type: 0x" + String(format: "%04x", type.rawValue) + " - \(type)\n"
        }
        else
        {
            returnString += "Ether Type: nil\n"
        }
        
        if let tag1 = self.tag1
        {
            returnString += "Tag 1: 0x"
            returnString += printDataBytes(bytes: tag1, hexDumpFormat: false, seperator: " ", decimal: false, enablePrinting: false)
            returnString += "\n"
        }
        
        if let tag2 = self.tag2
        {
            returnString += "Tag 2: 0x"
            returnString += printDataBytes(bytes: tag2, hexDumpFormat: false, seperator: " ", decimal: false, enablePrinting: false)
            returnString += "\n"
        }
        
        if let size = self.size
        {
            returnString += "Size: 0x"
            returnString += String(format: "%04x", size) + " - 0d" + String(size) + "\n"
        }
    
        returnString += "Payload: \n"
        returnString += printDataBytes(bytes: self.payload.data, hexDumpFormat: true, seperator: " ", decimal: false, enablePrinting: false) + "\n"
        
        return returnString
    }
}

public struct IPv4: Codable
{
    //http://www.networksorcery.com/enp/protocol/ip.htm
    
    public let version: Bits //UInt8 //4 bits
    public let IHL: Bits //UInt8 //4 bits
    public let DSCP: Bits //UInt8 //6 bits
    public let ECN: Bits //UInt8 //2 bits
    public let length: UInt16 //2 bytes   --number
    public let identification: UInt16 //2 bytes
    public let reservedBit: Bool //UInt8 //1 bit //bool
    public let dontFragment: Bool //UInt8 //1 bit //bool
    public let moreFragments: Bool //UInt8 //1 bit //bool
    public let fragmentOffset: Bits //UInt16 //13 bits   --number
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
        DatableConfig.endianess = .little
        var bits = Bits(data: data)
        
        //unpack a byte then parse into bits
        guard let VerIHL = bits.unpack(bytes: 1) else { return nil }
        var VerIHLbits = Bits(data: VerIHL)
        
        guard let version = VerIHLbits.unpack(bits: 4) else { return nil }
        guard let versionUint8 = version.uint8 else { return nil }
        self.version = version //Uint8
        if debugPrint { print("・ Version: 0x" + String(format: "%02x", versionUint8)) }
        
        guard let IHL = VerIHLbits.unpack(bits: 4) else { return nil }
        guard let IHLUint8 = IHL.uint8 else { return nil }
        self.IHL = IHL //Uint8
        if debugPrint { print("・ IHL: 0x" + String(format: "%02x", IHLUint8)) }
        
        guard let DSCPECN = bits.unpack(bytes: 1) else { return nil }
        var DSCPECNbits = Bits(data: DSCPECN)
        guard let DSCP = DSCPECNbits.unpack(bits: 6) else { return nil }
        guard let DSCPUint8 = DSCP.uint8 else { return nil }
        self.DSCP = DSCP //Uint8
        if debugPrint { print("・ DSCP: 0x" + String(format: "%02x", DSCPUint8)) }
        
        guard let ECN = DSCPECNbits.unpack(bits: 2) else { return nil }
        guard let ECNUint8 = ECN.uint8 else { return nil }
        self.ECN = ECN //Uint8
        if debugPrint { print("・ ECN: 0x" + String(format: "%02x", ECNUint8)) }
        
        DatableConfig.endianess = .big
        guard let length = bits.unpack(bytes: 2) else { return nil }
        guard let lengthUint16 = length.uint16 else { return nil }
        self.length = lengthUint16
        if debugPrint { print("・ Length: 0x" + String(format: "%02x", self.length) + " - 0d" + String(format: "%u", self.length)) }
        
        guard let identification = bits.unpack(bytes: 2) else { return nil }
        guard let identificationUint16 = identification.uint16 else { return nil }
        self.identification = identificationUint16
        if debugPrint { print("・ Identification: 0x" + String(format: "%02x", self.identification)) }
        DatableConfig.endianess = .little
        
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
        
        
        DatableConfig.endianess = .big
        guard let fragmentOffset = flagsFragmentOffsetbits.unpack(bits: 13) else { return nil }
        guard let fragmentOffsetUint16 = fragmentOffset.uint16 else { return nil }
        self.fragmentOffset = fragmentOffset //Uint16
        if debugPrint { print("・ FragmentOffset: 0d" + String(format: "%u", fragmentOffsetUint16)) }
        DatableConfig.endianess = .little
        
        guard let ttl = bits.unpack(bytes: 1) else { return nil }
        guard let ttlUint8 = ttl.uint8 else { return nil }
        self.ttl = ttlUint8
        if debugPrint { print("・ TTL: 0d" + String(format: "%u", self.ttl)) }
        
        guard let protocolNumber = bits.unpack(bytes: 1) else
        {
            _ = printDataBytes(bytes: bits.data, hexDumpFormat: false, seperator: ".", decimal: true)
            return nil
        } //fix should use IPprotocolNumber()
        guard let protocolNumberUint8 = protocolNumber.uint8 else
        {
            return nil
        }
        guard let protocolNumType = IPprotocolNumber(data: protocolNumber) else
        {
            return nil
        }
        self.protocolNumber = protocolNumType
        if debugPrint { print("・ ProtocolNumber: 0d" + String(format: "%u", protocolNumberUint8 ) + " - \(protocolNumType)") }
        
        DatableConfig.endianess = .big
        guard let checksum = bits.unpack(bytes: 2) else { return nil }
        guard let checksumUint16 = checksum.uint16 else { return nil }
        self.checksum = checksumUint16
        if debugPrint { print("・ Checksum: 0x" + String(format: "%02x", self.checksum)) }
        DatableConfig.endianess = .little
        
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
        DatableConfig.endianess = .big
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
        let _ = flagsFragOff.pack(bits: fragmentOffset) //13 bits
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
    public init?(version: Bits, IHL: Bits, DSCP: Bits, ECN: Bits, length: UInt16, identification: UInt16, reservedBit: Bool, dontFragment: Bool, moreFragments: Bool, fragmentOffset: Bits, ttl: UInt8, protocolNumber: IPprotocolNumber, checksum: UInt16?, sourceAddress: Data, destinationAddress: Data, options: Data?, payload: Data?, ethernetPadding: Data?)
    {
        //FIX, add parameter validation code
        //write test functions for this initializer
        
        DatableConfig.endianess = .big
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
        
        if let checksumNotNil = checksum
        {
            self.checksum = checksumNotNil
        }
        else
        {
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
            let _ = flagsFrags.pack(bits: self.fragmentOffset)
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
                self.checksum = checkresult
            } else
            {
                return nil
            }
            
        }
        
        
        
        
    }
    
    
    var pseudoHeaderTCP: Data
    {
        var results: Data = Data()
        let reservedZero: UInt8 = 0
        
        results.append(self.sourceAddress)
        results.append(self.destinationAddress)
        results.append(reservedZero.data)
        results.append(self.protocolNumber.rawValue)
        
        let TCPLen = self.length - (self.IHL.uint16! * 4)
        results.append(TCPLen.data)
        
        return results
    }
    
    var pseudoHeaderUDP: Data
    {
        var results: Data = Data()
        let reservedZero: UInt8 = 0
        results.append(self.sourceAddress)
        results.append(self.destinationAddress)
        results.append(reservedZero.data)
        results.append(self.protocolNumber.rawValue)
        
        let UDPLen = self.length - (self.IHL.uint16! * 4)
        results.append(UDPLen.data)
        
        return results
    }
    
    
}

extension IPv4: CustomStringConvertible
{
    public var description: String {
        //return IPv4 values of interest as a human readable string
        var returnString: String = ""
        
        guard let versionUint8 = version.uint8 else { return "Error converting version" }
        returnString += "Version: 0x" + String(format: "%02x", versionUint8) + " - 0b" + String(versionUint8, radix: 2) + "\n"
        
        guard let IHLUint8 = IHL.uint8 else { return "Error converting IHL" }
        returnString += "IHL: 0x" + String(format: "%02x", IHLUint8) + " - 0b" + String(IHLUint8, radix: 2) + "(" + String(IHLUint8 * 4) + " bytes)\n"
        
        guard let DSCPUint8 = DSCP.uint8 else { return "Error converting DSCP" }
        returnString += "DSCP: 0x" + String(format: "%02x", DSCPUint8) + " - 0b" + String(DSCPUint8, radix: 2) + "\n"
        
        guard let ECNUint8 = ECN.uint8 else { return "Error converting ECN" }
        returnString += "ECN: 0x" + String(format: "%02x", ECNUint8) + " - 0b" + String(ECNUint8, radix: 2) + "\n"
        
        returnString += "Length: 0x" + String(format: "%04x", self.length) + " - 0d" + self.length.string + "\n"
        returnString += "Identification: 0x" + String(format: "%04x", self.identification) + " - 0d" + self.identification.string + "\n"
        
        returnString += "Reserved: " + String(self.reservedBit) + "\n"
        returnString += "Don't Fragment: " + String(self.dontFragment) + "\n"
        returnString += "More Fragments: " + String(self.moreFragments) + "\n"
        
        guard let fragmentOffsetUint16 = fragmentOffset.uint16 else { return "Error converting Fragment Offset" }
        returnString += "FragmentOffset: 0x" + String(format: "%04x", fragmentOffsetUint16) + " - 0d" + String(fragmentOffsetUint16) + "\n"
        
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

public struct IPv6: Codable
{
    public let version: Bits //UInt8 //4 bits
    public let trafficClass: Bits //UInt8 //8 bits
    public let flowLabel: Bits //UInt32//20bits
    
    public let payloadLength: UInt16 //2 bytes
    public let nextHeader: UInt8 //1 byte
    public let hopLimit: UInt8 //1 byte
    public let sourceAddress: Data //16 bytes
    public let destinationAddress: Data //16 bytes
    //options?
    public let payload: Data
}

//extension IPv6: MaybeDatable
//{
//    public init?(data: Data)
//    {
//        //parsing code
//    }
//}
//
//extension IPv6
//{
//    public init?()
//    {
//          //constructor code
//    }
//}
//
//extension IPv6: CustomStringConvertible
//{
//    public var description: String {
//        //return string code
//    }
//}

public struct TCP: Codable
{
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
        DatableConfig.endianess = .little
        
        var bits = Bits(data: data)
        
        DatableConfig.endianess = .big
        guard let sourcePort = bits.unpack(bytes: 2) else { return nil }
        guard let sourcePortUint16 = sourcePort.uint16 else { return nil }
        self.sourcePort = sourcePortUint16
        if debugPrint { print("・ sourcePort: 0x" + String(format: "%02x", self.sourcePort) + " - 0d" + String(format: "%u", self.sourcePort)) }
        
        guard let destinationPort = bits.unpack(bytes: 2) else { return nil }
        guard let destinationPortUint16 = destinationPort.uint16 else { return nil }
        self.destinationPort = destinationPortUint16
        if debugPrint { print("・ destPort: 0x" + String(format: "%02x", self.destinationPort) + " - 0d" + String(format: "%u", self.destinationPort)) }
        DatableConfig.endianess = .little
        
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
        
        DatableConfig.endianess = .big
        guard let offsetReservedFlags = bits.unpack(bytes: 2) else { return nil }
        var dataReservedFlagsBits = Bits(data: offsetReservedFlags)
        guard let offsetReservedFlagsUint16 = offsetReservedFlags.uint16 else { return nil }
        if debugPrint { print("・ offsetReservedFlags: 0x" + String(format: "%02x", offsetReservedFlagsUint16) + " - 0b" + String(offsetReservedFlagsUint16, radix: 2)) }
        DatableConfig.endianess = .little
        
        guard let offset = dataReservedFlagsBits.unpack(bits: 4) else { return nil }
        guard let offsetUint8 = offset.uint8 else { return nil }
        self.offset = offset
        if debugPrint { print("・ Offset: 0x" + String(format: "%02x", offsetUint8) + " - 0b" + String(offsetUint8, radix: 2)) }
        
        guard let reserved = dataReservedFlagsBits.unpack(bits: 3) else { return nil }
        guard let reservedUint8 = reserved.uint8 else { return nil }
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
        
        DatableConfig.endianess = .big
        guard let windowSize = bits.unpack(bytes: 2) else { return nil }
        guard let windowSizeUint16 = windowSize.uint16 else { return nil }
        self.windowSize = windowSizeUint16
        if debugPrint { print("・ windowSize: 0x" + String(format: "%02x", self.windowSize) + " - 0d" + String(format: "%u", self.windowSize)) }
        
        guard let checksum = bits.unpack(bytes: 2) else { return nil }
        guard let checksumUint16 = checksum.uint16 else { return nil }
        self.checksum = checksumUint16
        if debugPrint { print("・ checksum: 0x" + String(format: "%02x", self.checksum) + " - 0d" + String(format: "%u", self.checksum)) }
        
        guard let urgentPointer = bits.unpack(bytes: 2) else { return nil }
        guard let urgentPointerUint16 = urgentPointer.uint16 else { return nil }
        self.urgentPointer = urgentPointerUint16
        if debugPrint { print("・ urgentPointer: 0x" + String(format: "%02x", self.urgentPointer) + " - 0d" + String(format: "%u", self.urgentPointer)) }
        DatableConfig.endianess = .little
        
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
        DatableConfig.endianess = .big
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
        
        DatableConfig.endianess = .big
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
        
        guard let offsetUint8 = offset.uint8 else { return "Error converting offset" }
        returnString += "Offset: 0x" + String(format: "%02x", offsetUint8) + " - 0b" + String(offsetUint8, radix: 2) + "\n"
        
        guard let reservedUint8 = reserved.uint8 else { return "Error converting reserved" }
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
        DatableConfig.endianess = .little
        var bits = Bits(data: data)
        
        DatableConfig.endianess = .big
        guard let sourcePort = bits.unpack(bytes: 2) else { return nil }
        guard let sourcePortUint16 = sourcePort.uint16 else { return nil }
        self.sourcePort = sourcePortUint16
        if debugPrint { print("・ UDPsourcePort: 0x" + String(format: "%02x", self.sourcePort) + " - 0d" + String(format: "%u", self.sourcePort)) }
        
        guard let destinationPort = bits.unpack(bytes: 2) else { return nil }
        guard let destinationPortUint16 = destinationPort.uint16 else { return nil }
        self.destinationPort = destinationPortUint16
        if debugPrint { print("・ UDPdestinationPort: 0x" + String(format: "%02x", self.destinationPort) + " - 0d" + String(format: "%u", self.destinationPort)) }
        
        guard let length = bits.unpack(bytes: 2) else { return nil }
        guard let lengthUint16 = length.uint16 else { return nil }
        self.length = lengthUint16
        if debugPrint { print("・ Length: 0x" + String(format: "%02x", self.length) + " - 0d" + String(format: "%u", self.length)) }
        
        guard let checksum = bits.unpack(bytes: 2) else { return nil }
        guard let checksumUint16 = checksum.uint16 else { return nil }
        self.checksum = checksumUint16
        if debugPrint { print("・ checksum: 0x" + String(format: "%02x", self.checksum)) }
        DatableConfig.endianess = .little
        
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
        DatableConfig.endianess = .big
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
    public init?(sourcePort: UInt16, destinationPort: UInt16, length: UInt16, checksum: UInt16?, payload: Data?, IPv4: IPv4)
    {
        //FIX, add parameter validation code
        //write test functions for this initializer
        
        DatableConfig.endianess = .big
        
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
            var checksumData: Data = Data()
            
            let psuedoheader = IPv4.pseudoHeaderUDP
            
            checksumData.append(psuedoheader)
            checksumData.append(self.sourcePort.data)
            checksumData.append(self.destinationPort.data)
            checksumData.append(self.length.data)
            
            if let payloadData = self.payload
            {
                checksumData.append(payloadData)
            }
            
            if checksumData.count % 2 != 0
            {
                checksumData.append(0x00)
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

public enum EtherType: UInt16, Codable
{
    /*
     if the value is less than 1536 (0x600) are size and not ethertype
     values at or above 0x600 are ethertype
     */
    case sizeNotEtherType = 0x0000
    
    case IPv4 = 0x0800    //Internet Protocol version 4 (IPv4)
    case ARP = 0x0806    //Address Resolution Protocol (ARP)
    case IPv6 = 0x86DD    //Internet Protocol Version 6 (IPv6)
    case singleTagVLAN = 0x8100    //VLAN-tagged frame (IEEE 802.1Q)
    case doubleTagVLAN = 0x88A8 //VLAN-tagged (IEEE 802.1Q) frame with double tagging
    
    case WakeOnLan = 0x0842    //Wake-on-LAN[9]
    case AVTP = 0x22F0    //Audio Video Transport Protocol (AVTP)
    case IETF_TRILL = 0x22F3    //IETF TRILL Protocol
    case SRP = 0x22EA    //Stream Reservation Protocol
    case DEC_MOP_RC = 0x6002    //DEC MOP RC
    case DECnetPhase4 = 0x6003    //DECnet Phase IV, DNA Routing
    case DEC_LAT = 0x6004    //DEC LAT
    case RARP = 0x8035    //Reverse Address Resolution Protocol (RARP)
    case AppleEthertalk = 0x809B    //AppleTalk (Ethertalk)
    case AARP = 0x80F3    //AppleTalk Address Resolution Protocol (AARP)
    case SLPP = 0x8102    //Simple Loop Prevention Protocol (SLPP)
    case VLACP = 0x8103    //Virtual Link Aggregation Control Protocol (VLACP)
    case IPX = 0x8137    //IPX
    case QNX_Qnet = 0x8204    //QNX Qnet
    case EthFlowControl = 0x8808    //Ethernet flow control
    case EthSlowProtocols = 0x8809    //Ethernet Slow Protocols[11] such as the Link Aggregation Control Protocol (LACP)
    case CobraNet = 0x8819    //CobraNet
    case MPLSunicast = 0x8847    //MPLS unicast
    case MPLSmulticast = 0x8848    //MPLS multicast
    case PPPoEdiscovery = 0x8863    //PPPoE Discovery Stage
    case PPPoEsessionStage = 0x8864    //PPPoE Session Stage
    case HomePlug = 0x887B    //HomePlug 1.0 MME
    case EAPoverLAN = 0x888E    //EAP over LAN (IEEE 802.1X)
    case PROFINET = 0x8892    //PROFINET Protocol
    case HyperSCSI = 0x889A    //HyperSCSI (SCSI over Ethernet)
    case ATAoverEth = 0x88A2    //ATA over Ethernet
    case EtherCAT = 0x88A4    //EtherCAT Protocol
    case EthPowerlink = 0x88AB    //Ethernet Powerlink[citation needed]
    case GOOSE = 0x88B8    //GOOSE (Generic Object Oriented Substation event)
    case GSE = 0x88B9    //GSE (Generic Substation Events) Management Services
    case SV = 0x88BA    //SV (Sampled Value Transmission)
    case MikroTikRoMON = 0x88BF    //MikroTik RoMON (unofficial)
    case LLDP = 0x88CC    //Link Layer Discovery Protocol (LLDP)
    case SERCOS3 = 0x88CD    //SERCOS III
    case WSMP = 0x88DC    //WSMP, WAVE Short Message Protocol
    case MRP = 0x88E3    //Media Redundancy Protocol (IEC62439-2)
    case MACsecurity = 0x88E5    //MAC security (IEEE 802.1AE)
    case PBB = 0x88E7    //Provider Backbone Bridges (PBB) (IEEE 802.1ah)
    case PrecisionTime = 0x88F7    //Precision Time Protocol over IEEE 802.3 Ethernet
    case NC_SI = 0x88F8    //NC-SI
    case PRP = 0x88FB    //Parallel Redundancy Protocol (PRP)
    case CFM = 0x8902    //IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
    case FCoE = 0x8906    //Fibre Channel over Ethernet (FCoE)
    case FCoEinit = 0x8914    //FCoE Initialization Protocol
    case RoCE = 0x8915    //RDMA over Converged Ethernet (RoCE)
    case TTE = 0x891D    //TTEthernet Protocol Control Frame (TTE)
    case HSR = 0x892F    //High-availability Seamless Redundancy (HSR)
    case EthConfTest = 0x9000    //Ethernet Configuration Testing Protocol[12]
    case VLANdoubleTag802_1Q = 0x9100    //VLAN-tagged (IEEE 802.1Q) frame with double tagging
    case RedundancyTag = 0xF1C1    //Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)
}

public extension EtherType
{
    init?(data: UInt16)
    {
        //        DatableConfig.endianess = .big
        //        guard let x = data.uint16 else { return nil}
        self.init(rawValue: data)
    }
    
    var data: Data?
    {
        DatableConfig.endianess = .big
        let x = self.rawValue
        return Data(uint16: UInt16(x))
    }
}

public enum IPversion: Int, Codable
{
    case IPv4 = 4
    case IPv6 = 6
}

extension IPversion
{
    public init?(bits: Bits)
    {
        guard let x = bits.int else { return nil }
        self.init(rawValue: x)
    }
    
    public var bits: Bits?
    {
        let x = self.rawValue
        return Bits(int: x)
    }
    
}

public enum IPprotocolNumber: UInt8, Codable
{
    //https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    case ICMP = 0x01 //Internet Control Message Protocol - RFC 792
    case TCP = 0x06 //first //Transmission Control Protocol - RFC 793
    case UDP = 0x11 //second //User Datagram Protocol - RFC 768
    case RDP = 0x1B //Reliable Data Protocol - RFC 908
    case IPv6 = 0x29 //third //IPv6 Encapsulation - RFC 2473
    case L2TP = 0x73 //Layer Two Tunneling Protocol Version 3 - RFC 3931
    case SCTP = 0x84 //Stream Control Transmission Protocol - RFC 4960
    
    //IPv6 options:
    case HOPOPT = 0x00 //IPv6 Hop-by-Hop Option - RFC 8200
    case IPv6Route = 0x2B //Routing Header for IPv6 - RFC 8200
    case IPv6Frag = 0x2C //Fragment Header for IPv6 - RFC 8200
    case ESP = 0x32 //Encapsulating Security Payload - RFC 4303
    case AH = 0x33 //Authentication Header - RFC 4302
    case IPv6Opts = 0x3C//Destination Options for IPv6 - RFC 8200
    case MobilityHeader = 0x87 //Mobility Extension Header for IPv6 - RFC 6275
    case HIP = 0x8B //Host Identity Protocol - RFC 5201
    case Shim6 = 0x8C //Site Multihoming by IPv6 Intermediation - RFC 5533
    
    
    case IGMP = 0x02    //Internet Group Management Protocol - RFC 1112
    case GGP = 0x03    //Gateway-to-Gateway Protocol - RFC 823
    case IPinIP = 0x04    //IP in IP (encapsulation) - RFC 2003
    case ST = 0x05    //Internet Stream Protocol - RFC 1190, RFC 1819
    case CBT = 0x07    //Core-based trees - RFC 2189
    case EGP = 0x08    //Exterior Gateway Protocol - RFC 888
    case IGP = 0x09    //Interior Gateway Protocol (any private interior gateway (used by Cisco for their IGRP)) -
    case BBN_RCC_MON = 0x0A    //BBN RCC Monitoring -
    case NVP_I = 0x0B    //Network Voice Protocol - RFC 741
    case PUP = 0x0C    //Xerox PUP -
    case ARGUS = 0x0D    //ARGUS -
    case EMCON = 0x0E    //EMCON -
    case XNET = 0x0F    //Cross Net Debugger - IEN 158[2]
    case CHAOS = 0x10    //Chaos
    case MUX = 0x12    //Multiplexing - IEN 90[3]
    case DCN_MEAS = 0x13    //DCN Measurement Subsystems -
    case HMP = 0x14    //Host Monitoring Protocol - RFC 869
    case PRM = 0x15    //Packet Radio Measurement -
    case XNS_IDP = 0x16    //XEROX NS IDP -
    case TRUNK_1 = 0x17    //Trunk-1 -
    case TRUNK_2 = 0x18    //Trunk-2 -
    case LEAF_1 = 0x19    //Leaf-1 -
    case LEAF_2 = 0x1A    //Leaf-2 -
    case IRTP = 0x1C    //Internet Reliable Transaction Protocol - RFC 938
    case ISO_TP4 = 0x1D    //ISO Transport Protocol Class 4 - RFC 905
    case NETBLT = 0x1E    //Bulk Data Transfer Protocol - RFC 998
    case MFE_NSP = 0x1F    //MFE Network Services Protocol -
    case MERIT_INP = 0x20    //MERIT Internodal Protocol -
    case DCCP = 0x21    //Datagram Congestion Control Protocol - RFC 4340
    case ThirdPC = 0x22    //Third Party Connect Protocol -
    case IDPR = 0x23    //Inter-Domain Policy Routing Protocol - RFC 1479
    case XTP = 0x24    //Xpress Transport Protocol -
    case DDP = 0x25    //Datagram Delivery Protocol -
    case IDPR_CMTP = 0x26    //IDPR Control Message Transport Protocol -
    case TPpp = 0x27    //TP++ Transport Protocol -
    case IL = 0x28    //IL Transport Protocol -
    case SDRP = 0x2A    //Source Demand Routing Protocol - RFC 1940
    case IDRP = 0x2D    //Inter-Domain Routing Protocol -
    case RSVP = 0x2E    //Resource Reservation Protocol - RFC 2205
    case GREs = 0x2F    //Generic Routing Encapsulation - RFC 2784, RFC 2890
    case DSR = 0x30    //Dynamic Source Routing Protocol - RFC 4728
    case BNA = 0x31    //Burroughs Network Architecture -
    case I_NLSP = 0x34    //Integrated Net Layer Security Protocol - TUBA
    case SwIPe = 0x35    //SwIPe - RFC 5237
    case NARP = 0x36    //NBMA Address Resolution Protocol - RFC 1735
    case MOBILE = 0x37    //IP Mobility (Min Encap) - RFC 2004
    case TLSP = 0x38    //Transport Layer Security Protocol (using Kryptonet key management) -
    case SKIP = 0x39    //Simple Key-Management for Internet Protocol - RFC 2356
    case IPv6_ICMP = 0x3A    //ICMP for IPv6 - RFC 4443, RFC 4884
    case IPv6_NoNxt = 0x3B    //No Next Header for IPv6 - RFC 8200
    case AnyHostInternal = 0x3D    //Any host internal protocol -
    case CFTP = 0x3E    //CFTP -
    case AnyLocalNetwork = 0x3F    //Any local network -
    case SAT_EXPAK = 0x40    //SATNET and Backroom EXPAK -
    case KRYPTOLAN = 0x41    //Kryptolan -
    case RVD = 0x42    //MIT Remote Virtual Disk Protocol -
    case IPPC = 0x43    //Internet Pluribus Packet Core -
    case AnyDistributedFileSystem = 0x44    //Any distributed file system -
    case SAT_MON = 0x45    //SATNET Monitoring -
    case VISA = 0x46    //VISA Protocol -
    case IPCU = 0x47    //Internet Packet Core Utility -
    case CPNX = 0x48    //Computer Protocol Network Executive -
    case CPHB = 0x49    //Computer Protocol Heart Beat -
    case WSN = 0x4A    //Wang Span Network -
    case PVP = 0x4B    //Packet Video Protocol -
    case BR_SAT_MON = 0x4C    //Backroom SATNET Monitoring -
    case SUN_ND = 0x4D    //SUN ND PROTOCOL-Temporary -
    case WB_MON = 0x4E    //WIDEBAND Monitoring -
    case WB_EXPAK = 0x4F    //WIDEBAND EXPAK -
    case ISO_IP = 0x50    //International Organization for Standardization Internet Protocol -
    case VMTP = 0x51    //Versatile Message Transaction Protocol - RFC 1045
    case SECURE_VMTP = 0x52    //Secure Versatile Message Transaction Protocol - RFC 1045
    case VINES = 0x53    //VINES -
    case TTP_or_IPTM = 0x54    //Internet Protocol Traffic Manager -
    case NSFNET_IGP = 0x55    //NSFNET-IGP -
    case DGP = 0x56    //Dissimilar Gateway Protocol -
    case TCF = 0x57    //TCF -
    case EIGRP = 0x58    //EIGRP - Informational RFC 7868
    case OSPF = 0x59    //Open Shortest Path First - RFC 2328
    case Sprite_RPC = 0x5A    //Sprite RPC Protocol -
    case LARP = 0x5B    //Locus Address Resolution Protocol -
    case MTP = 0x5C    //Multicast Transport Protocol -
    case AX_25 = 0x5D    //AX.25 -
    case OS = 0x5E    //KA9Q NOS compatible IP over IP tunneling -
    case MICP = 0x5F    //Mobile Internetworking Control Protocol -
    case SCC_SP = 0x60    //Semaphore Communications Sec. Pro -
    case ETHERIP = 0x61    //Ethernet-within-IP Encapsulation - RFC 3378
    case ENCAP = 0x62    //Encapsulation Header - RFC 1241
    case AnyPrivateEncryptionScheme = 0x63    //Any private encryption scheme -
    case GMTP = 0x64    //GMTP -
    case IFMP = 0x65    //Ipsilon Flow Management Protocol -
    case PNNI = 0x66    //PNNI over IP -
    case PIM = 0x67    //Protocol Independent Multicast -
    case ARIS = 0x68    //IBM's ARIS (Aggregate Route IP Switching) Protocol -
    case SCPS = 0x69    //SCPS (Space Communications Protocol Standards) - SCPS-TP[4]
    case QNX = 0x6A    //QNX -
    case ActiveNetworks = 0x6B    //Active Networks -
    case IPComp = 0x6C    //IP Payload Compression Protocol - RFC 3173
    case SNP = 0x6D    //Sitara Networks Protocol -
    case Compaq_Peer = 0x6E    //Compaq Peer Protocol -
    case IPX_in_IP = 0x6F    //IPX in IP -
    case VRRP = 0x70    //Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANAassigned) - VRRP:RFC 3768
    case PGM = 0x71    //PGM Reliable Transport Protocol - RFC 3208
    case AnyZeroHopProtocol = 0x72    //Any 0-hop protocol -
    case DDX = 0x74    //D-II Data Exchange (DDX) -
    case IATP = 0x75    //Interactive Agent Transfer Protocol -
    case STP = 0x76    //Schedule Transfer Protocol -
    case SRP = 0x77    //SpectraLink Radio Protocol -
    case UTI = 0x78    //Universal Transport Interface Protocol -
    case SMP = 0x79    //Simple Message Protocol -
    case SM = 0x7A    //Simple Multicast Protocol - draft-perlman-simple-multicast-03
    case PTP = 0x7B    //Performance Transparency Protocol -
    case IS_IS = 0x7C    //Intermediate System to Intermediate System (IS-IS) Protocol over IPv4 - RFC 1142 and RFC 1195
    case FIRE = 0x7D    //Flexible Intra-AS Routing Environment -
    case CRTP = 0x7E    //Combat Radio Transport Protocol -
    case CRUDP = 0x7F    //Combat Radio User Datagram -
    case SSCOPMCE = 0x80    //Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment - ITU-T Q.2111 (1999)
    case IPLT = 0x81    // -
    case SPS = 0x82    //Secure Packet Shield -
    case PIPE = 0x83    //Private IP Encapsulation within IP - Expired I-D draft-petri-mobileip-pipe-00.txt
    case FC = 0x85    //Fibre Channel -
    case RSVP_E2E_IGNORE = 0x86    //Reservation Protocol (RSVP) End-to-End Ignore - RFC 3175
    case UDPLite = 0x88    //Lightweight User Datagram Protocol - RFC 3828
    case MPLS_in_IP = 0x89    //Multiprotocol Label Switching Encapsulated in IP - RFC 4023, RFC 5332
    case manet = 0x8A    //MANET Protocols - RFC 5498
    
    case WESP = 0x8D    //Wrapped Encapsulating Security Payload - RFC 5840
    case ROHC = 0x8E    //Robust Header Compression - RFC 5856
    case Ethernet = 0x8F    //IPv6 Segment Routing (TEMPORARY - registered 2020-01-31, expires 2021-01-31) -
    //case Unassigned = 0x90-0xFC    // -
    //case Use for experimentation and testing = 0xFD-0xFE    //RFC 3692 -
    case Reserved = 0xFF
}

extension IPprotocolNumber
{
    init?(data: Data)
    {
        guard let x = data.uint8 else { return nil }
        self.init(rawValue: x)
    }
    
    var data: Data?
    {
        let x = self.rawValue
        return Data(uint8: x)
    }
    
}


