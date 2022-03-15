//
//  File.swift
//  
//
//  Created by Joshua Clark on 3/11/22.
//

import Bits
import Datable
import Foundation

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
        
        guard var typeOrTagUInt16 = typeOrTagPrefix.maybeNetworkUint16 else
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
            guard let typeUInt16 = type.maybeNetworkUint16 else
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
