//
//  ParserTests.swift
//  
//
//  Created by Dr. Brandon Wiley on 4/2/20.
//

import Foundation
import XCTest
import Datable
import Bits
import SwiftPCAP
@testable import InternetProtocols


extension String {
    var isHex: Bool {
        guard self.count > 0 else { return false }
        let nums: Set<Character> = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "A", "B", "C", "D", "E", "F" ]
        return Set(self).isSubset(of: nums)
    }
}

func convertMACtoBytes (inputString: String) -> Data
{
    let bytesString = inputString.components(separatedBy:":")
    var MACData = Data()
    
    for byte in bytesString
    {
        if let byteUInt8 = UInt8(byte, radix:16)
        {
            MACData.append(byteUInt8)
        }
    }
    return MACData
}

func convertIPtoBytes (inputString: String) -> Data
{
    let intsString = inputString.components(separatedBy:".")
    var ipData = Data()
    
    for int in intsString
    {
        if let byteUInt8 = UInt8(int, radix:10)
        {
            ipData.append(byteUInt8)
        }
    }
    return ipData
}

func convertHexStringToBytes (inputString: String) -> Data?
{
    if inputString == ""
    {
        return nil
    }
    
    var bytes = Data()
    if inputString.count % 2 == 0 && inputString.isHex
    {
        var i: Int = 0
        while (i < inputString.count)
        {
            let substring: String = String(inputString.dropFirst(i).prefix(2))
            if let byteUInt8 = UInt8(substring, radix:16)
            {
                bytes.append(byteUInt8)
            }
            else
            {
                return nil
            }
            i+=2
        }
        return bytes
    }
    else
    {
        return nil
    }
}


struct tsharkTextFilePacket
{
    var frame_number: Int?
    var eth_dst: Data
    var eth_src: Data
    var eth_type: EtherType?
    var eth_padding: Data?
    
    var ip_version: UInt8?
    var ip_hdr_len: UInt8?
    var ip_dsfield_dscp: UInt8?
    var ip_dsfield_ecn: UInt8?
    var ip_len: UInt16?
    var ip_id: UInt16?
    var ip_flags_rb: Bool
    var ip_flags_df: Bool
    var ip_flags_mf: Bool
    var ip_frag_offset: UInt16?
    var ip_ttl: UInt8?
    var ip_proto: IPprotocolNumber?
    var ip_checksum: UInt16?
    var ip_src: Data
    var ip_dst: Data
    
    
    var tcp_srcport: UInt16?
    var tcp_dstport: UInt16?
    var tcp_hdr_len: UInt8? //String
    var tcp_flags_res: UInt8? //String
    var tcp_flags_ns: Bool
    var tcp_flags_cwr: Bool
    var tcp_flags_ecn: Bool
    var tcp_flags_urg: Bool
    var tcp_flags_ack: Bool
    var tcp_flags_push: Bool
    var tcp_flags_reset: Bool
    var tcp_flags_syn: Bool
    var tcp_flags_fin: Bool
    
    var tcp_window_size_value: UInt16?
    var tcp_checksum: UInt16?
    var tcp_urgent_pointer: UInt16?
    var tcp_options: Data?
    var tcp_payload: Data?
    
    
    
    var udp_srcport: UInt16?
    var udp_dstport: UInt16?
    var udp_length: UInt16?
    var udp_checksum: UInt16?
    
    init(lineToParse: String)
    {
        let values = lineToParse.components(separatedBy:"\t")
        if values.count == 42
        {
            self.frame_number = Int(string: values[0])
            self.eth_dst = convertMACtoBytes(inputString: values[1])
            self.eth_src = convertMACtoBytes(inputString: values[2])
            
            if values[3] != ""
            {
                if let value = UInt16(values[3].replacingOccurrences(of: "0x", with: ""), radix:16)
                {
                    self.eth_type = EtherType(rawValue: value)
                }
                else { self.eth_type = nil }
            }
            else { self.eth_type = nil }
            
            
            if values[4] != ""
            {
                self.ip_version = UInt8(string: values[4].components(separatedBy: ",")[0])
            }
            else { self.ip_version = nil }
            
            if values[5] != ""
            {
                self.ip_hdr_len = UInt8(string: values[5].components(separatedBy: ",")[0])/4
            }
            else { self.ip_hdr_len = nil }
            
            if values[6] != ""
            {
                self.ip_dsfield_dscp = UInt8(string: values[6].components(separatedBy: ",")[0])
            }
            else { self.ip_dsfield_dscp = nil }
            
            if values[7] != ""
            {
                self.ip_dsfield_ecn = UInt8(string: values[7].components(separatedBy: ",")[0])
            }
            else { self.ip_dsfield_ecn = nil }
            
            if values[8] != ""
            {
                self.ip_len = UInt16(string: values[8].components(separatedBy: ",")[0])
            }
            else { self.ip_len = nil }
            
            if values[9] != ""
            {
                self.ip_id = UInt16( values[9].components(separatedBy: ",")[0].replacingOccurrences(of: "0x", with: ""), radix:16 )!
            }
            else { self.ip_id = nil }
            
            if values[10].components(separatedBy: ",")[0] == "0"
            {
                self.ip_flags_rb = false
            }
            else { self.ip_flags_rb = true }
            
            if values[11].components(separatedBy: ",")[0] == "0"
            {
                self.ip_flags_df = false
            }
            else { self.ip_flags_df = true }
            
            if values[12].components(separatedBy: ",")[0] == "0"
            {
                self.ip_flags_mf = false
            }
            else { self.ip_flags_mf = true }
            
            if values[13] != ""
            {
                self.ip_frag_offset = UInt16(string: values[13].components(separatedBy: ",")[0])
            }
            else { self.ip_frag_offset = nil }
            
            if values[14] != ""
            {
                self.ip_ttl = UInt8(string: values[14].components(separatedBy: ",")[0])
            }
            else { self.ip_ttl = nil }
            
            if values[15] != ""
            {
                let number = UInt8(string: values[15].components(separatedBy: ",")[0])
                
                if let proto = IPprotocolNumber(data: number.data)
                {
                    self.ip_proto = proto
                }
                else
                {
                    self.ip_proto = nil
                    
                }
                
            }
            
            
            if values[16] != ""
            {
                self.ip_checksum = UInt16( values[16].components(separatedBy: ",")[0].replacingOccurrences(of: "0x", with: ""), radix:16 )!
            }
            else { self.ip_checksum = nil }
            
            self.ip_src = convertIPtoBytes (inputString: values[17].components(separatedBy: ",")[0])
            self.ip_dst = convertIPtoBytes (inputString: values[18].components(separatedBy: ",")[0])
            
            if values[19] != ""
            {
                self.tcp_srcport = UInt16(string: values[19].components(separatedBy: ",")[0])
            }
            else { self.tcp_srcport = nil }
            
            if values[20] != ""
            {
                self.tcp_dstport = UInt16(string: values[20].components(separatedBy: ",")[0])
            }
            else { self.tcp_dstport = nil }
            
            
            if values[21] != ""
            {
                self.tcp_hdr_len = UInt8(string: values[21].components(separatedBy: ",")[0]) / 4
            }
            else { self.tcp_hdr_len = nil }
            
            if values[22] != ""
            {
                self.tcp_flags_res = UInt8(string: values[22].components(separatedBy: ",")[0])
            }
            else { self.tcp_flags_res = nil }
            
            if values[23].components(separatedBy: ",")[0] == "0"
            {
                self.tcp_flags_ns = false
            }
            else { self.tcp_flags_ns = true }
            
            if values[24].components(separatedBy: ",")[0] == "0"
            {
                self.tcp_flags_cwr = false
            }
            else { self.tcp_flags_cwr = true }
            
            if values[25].components(separatedBy: ",")[0] == "0"
            {
                self.tcp_flags_ecn = false
            }
            else { self.tcp_flags_ecn = true }
            
            if values[26].components(separatedBy: ",")[0] == "0"
            {
                self.tcp_flags_urg = false
            }
            else { self.tcp_flags_urg = true }
            
            if values[27].components(separatedBy: ",")[0] == "0"
            {
                self.tcp_flags_ack = false
            }
            else { self.tcp_flags_ack = true }
            
            if values[28].components(separatedBy: ",")[0] == "0"
            {
                self.tcp_flags_push = false
            }
            else { self.tcp_flags_push = true }
            
            if values[29].components(separatedBy: ",")[0] == "0"
            {
                self.tcp_flags_reset = false
            }
            else { self.tcp_flags_reset = true }
            
            if values[30].components(separatedBy: ",")[0] == "0"
            {
                self.tcp_flags_syn = false
            }
            else { self.tcp_flags_syn = true }
            
            if values[31].components(separatedBy: ",")[0] == "0"
            {
                self.tcp_flags_fin = false
            }
            else { self.tcp_flags_fin = true }
            
            if values[32] != ""
            {
                self.tcp_window_size_value = UInt16(string: values[32].components(separatedBy: ",")[0])
            }
            else { self.tcp_window_size_value = nil }
            
            if values[33] != ""
            {
                self.tcp_checksum = UInt16(values[33].components(separatedBy: ",")[0].replacingOccurrences(of: "0x", with: ""), radix:16)!
            }
            else { self.tcp_checksum = nil }
            
            if values[34] != ""
            {
                self.tcp_urgent_pointer = UInt16(string: values[34].components(separatedBy: ",")[0])
            }
            else { self.tcp_urgent_pointer = nil }
            
            self.tcp_options = convertHexStringToBytes(inputString: values[35])
            self.tcp_payload = convertHexStringToBytes(inputString: values[36])
            
            
            if values[37] != ""
            {
                self.udp_srcport = UInt16(string: values[37].components(separatedBy: ",")[0])
            }
            else { self.udp_srcport = nil }
            
            if values[38] != ""
            {
                self.udp_dstport = UInt16(string: values[38].components(separatedBy: ",")[0])
            }
            else { self.udp_dstport = nil }
            
            if values[39] != ""
            {
                self.udp_length = UInt16(string: values[39].components(separatedBy: ",")[0])
            }
            else { self.udp_length = nil }
            
            if values[40] != ""
            {
                self.udp_checksum = UInt16(values[40].components(separatedBy: ",")[0].replacingOccurrences(of: "0x", with: ""), radix:16)!
            }
            else { self.udp_checksum = nil }
            
            
            self.eth_padding = convertHexStringToBytes(inputString: values[41])
        }
        else
        {
            print("‼️ Failed to parse line from text file, likely wrong column count or delimiters")
            self.frame_number = nil
            self.eth_dst = ""
            self.eth_src = ""
            self.eth_type = EtherType(rawValue: 0xFFFF)!
            self.eth_padding = nil
            
            self.ip_version = nil
            self.ip_hdr_len = nil
            self.ip_dsfield_dscp = nil
            self.ip_dsfield_ecn = nil
            self.ip_len = nil
            self.ip_id = nil
            self.ip_flags_rb = true
            self.ip_flags_df = true
            self.ip_flags_mf = true
            self.ip_frag_offset = nil
            self.ip_ttl = nil
            self.ip_proto = nil
            self.ip_checksum = nil
            self.ip_src = ""
            self.ip_dst = ""
            
            self.tcp_srcport = nil
            self.tcp_dstport = nil
            self.tcp_hdr_len = nil
            self.tcp_flags_res = nil
            self.tcp_flags_ns = true
            self.tcp_flags_cwr = true
            self.tcp_flags_ecn = true
            self.tcp_flags_urg = true
            self.tcp_flags_ack = true
            self.tcp_flags_push = true
            self.tcp_flags_reset = true
            self.tcp_flags_syn = true
            self.tcp_flags_fin = true
            self.tcp_window_size_value = nil
            self.tcp_checksum = nil
            self.tcp_urgent_pointer = nil
            self.tcp_options = nil
            self.tcp_payload = nil
            
            self.udp_srcport = nil
            self.udp_dstport = nil
            self.udp_length = nil
            self.udp_checksum = nil
        }
    }
}



final class ParserTests: XCTestCase
{
    func testDatable_endianness1()
    {
        DatableConfig.endianess = .little
        
        let correct = Int(0x08)
        
        let data = Data(array: [0x08])
        
        let result = data.int
        
        XCTAssertEqual(correct, result)
    }
    
    func testDatable_endianness2()
    {
        DatableConfig.endianess = .little
        
        let correct: Int = 0x08
        
        let data = Data(array: [0x08])
        
        let result = data.int
        
        XCTAssertEqual(correct, result)
    }
    
    func testDatable_endianness4()
    {
        DatableConfig.endianess = .big
        
        let correct: UInt16 = 0x0800
        
        let data = Data(array: [0x08, 0x00])
        
        let result = data.uint16
        
        XCTAssertEqual(correct, result)
    }
    
    func testDatable_endianness5()
    {
        DatableConfig.endianess = .big
        
        let correct: Int = 0x0800
        
        let data = Data(array: [0x08, 0x00])
        
        let uint16 = data.uint16
        XCTAssertNotNil(uint16)
        let result = Int(uint16!)
        
        XCTAssertEqual(correct, result)
    }
    
    // Test Ethertype parser
    func testEthertype_0x0800()
    {
        DatableConfig.endianess = .big
        
        let correct = EtherType(rawValue: 0x0800)
        
        let data = Data(array: [0x08, 0x00])
        
        guard let dataUInt16 = data.uint16 else
        {
            XCTFail()
            return
        }
        
        guard let result = EtherType(data: dataUInt16) else
        {
            XCTFail()
            return
        }
        
        XCTAssertEqual(correct, result)
    }
    
    func testEthertype_Data_getter()
    {
        let correct = Data(array: [0x08, 0x00])
        let ET = EtherType(rawValue: 0x0800)
        let result = ET?.data
        
        XCTAssertEqual(correct, result)
    }
    
    func testIPVersionInit()
    {
        var bits = Bits()
        let correct = IPversion(rawValue: 0x04)
        
        guard bits.pack(bit: 1) else
        {
            XCTFail()
            return
        }
        
        guard bits.pack(bit: 0) else
        {
            XCTFail()
            return
        }
        
        guard bits.pack(bit: 0) else
        {
            XCTFail()
            return
        }
        
        let result = IPversion(bits: bits)
        
        XCTAssertEqual(correct, result)
    }
    
    func testIPVersionBits()
    {
        var correct = Bits()
        
        guard correct.pack(bit: 1) else
        {
            XCTFail()
            return
        }
        
        guard correct.pack(bit: 0) else
        {
            XCTFail()
            return
        }
        
        guard correct.pack(bit: 0) else
        {
            XCTFail()
            return
        }
        
        let ipv = IPversion(rawValue: 0x04)
        let result = ipv?.bits?.uint
        
        XCTAssertEqual(correct.uint, result)
    }
    
    func testEthernetIPv4Init()
    {
        //sample source: https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=tcp-ethereal-file1.trace
        //packet #4
        debugPrint = true
        let packetBytes = Data(array: [
            0x00, 0x05, 0x9a, 0x3c, 0x78, 0x00, 0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5, 0x0c, 0x83, 0xd4,
            0x1f, 0xa7, 0x00, 0x50, 0x08, 0x30, 0x3d, 0xe4, 0xa9, 0x33, 0x99, 0x5f, 0xcf, 0x79, 0x70, 0x12,
            0x05, 0xb4, 0x0b, 0xeb, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02])
        
        let correctMACsource = Data(array: [0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d])
        let correctMACdestination = Data(array: [0x00, 0x05, 0x9a, 0x3c, 0x78, 0x00])
        let correctType = EtherType(rawValue: 0x0800) //IPv4
        //let correctTag1 = Data(array: [])
        //let correctTag2 = Data(array: [])
        let correctPayload = Data(array: [
            0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40, 0x00,
            0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5, 0x0c,
            0x83, 0xd4, 0x1f, 0xa7, 0x00, 0x50, 0x08, 0x30,
            0x3d, 0xe4, 0xa9, 0x33, 0x99, 0x5f, 0xcf, 0x79,
            0x70, 0x12, 0x05, 0xb4, 0x0b, 0xeb, 0x00, 0x00,
            0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02])
        
        let correctIPv4version: UInt8 = 0x04
        let correctIPv4IHL: UInt8 = 0x05
        let correctIPv4DSCP: UInt8 = 0x00
        let correctIPv4ECN: UInt8 = 0x00 //(48)
        let correctIPv4length: UInt16 = 0x0030
        let correctIPv4identification: UInt16 = 0x0000
        
        //let correctIPv4flags: UInt8 = 0b010 //UInt8 3 bits
        let correctIPv4reservedBit: Bool = false
        let correctIPv4dontFragment: Bool = true
        let correctIPv4moreFragments: Bool = false
        let correctIPv4fragmentOffset: UInt16 = 0x0000
        let correctIPv4ttl: UInt8 = 0x34 //(52)
        
        guard let correctIPv4protocolNumber = IPprotocolNumber(rawValue: 0x06) else { //0x06 = TCP
            XCTFail()
            return
        }
        
        let correctIPv4checksum: UInt16 = 0x2dc9
        let correctIPv4sourceAddress: Data = Data(array:[0x80, 0x77, 0xf5, 0x0c]) //128.119.245.12
        let correctIPv4destinationAddress: Data = Data(array:[0x83, 0xd4, 0x1f, 0xa7]) //131.212.31.167
        let correctIPv4options: Data? = nil
        let correctIPv4payload: Data = Data(array:[
            0x00, 0x50, 0x08, 0x30, 0x3d, 0xe4, 0xa9, 0x33,
            0x99, 0x5f, 0xcf, 0x79, 0x70, 0x12, 0x05, 0xb4,
            0x0b, 0xeb, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
            0x01, 0x01, 0x04, 0x02])
        
        
        if let epacket = Ethernet(data: packetBytes)
        {
            XCTAssertEqual(epacket.MACDestination, correctMACdestination)
            XCTAssertEqual(epacket.MACSource, correctMACsource)
            XCTAssertEqual(epacket.type, correctType)
            XCTAssertEqual(epacket.payload, correctPayload)
            XCTAssertNil(epacket.tag1)
            XCTAssertNil(epacket.tag2)
            
            let epacketData = epacket.data
            XCTAssertEqual(epacketData, packetBytes)
            
            if let IPv4part = IPv4(data: epacket.payload)
            {
                guard let IPv4partVersion = IPv4part.version.uint8 else { XCTFail(); return }
                XCTAssertEqual(IPv4partVersion, correctIPv4version)
                
                guard let IPv4partIHL = IPv4part.IHL.uint8 else { XCTFail(); return }
                XCTAssertEqual(IPv4partIHL, correctIPv4IHL)
                
                guard let IPv4partDSCP = IPv4part.DSCP.uint8 else { XCTFail(); return }
                XCTAssertEqual(IPv4partDSCP, correctIPv4DSCP)
                
                guard let IPv4partECN = IPv4part.ECN.uint8 else { XCTFail(); return }
                XCTAssertEqual(IPv4partECN, correctIPv4ECN)
                
                
                
                XCTAssertEqual(IPv4part.length, correctIPv4length)
                XCTAssertEqual(IPv4part.identification, correctIPv4identification)
                
                
                XCTAssertEqual(IPv4part.reservedBit, correctIPv4reservedBit)
                
                XCTAssertEqual(IPv4part.dontFragment, correctIPv4dontFragment)
                
                XCTAssertEqual(IPv4part.moreFragments, correctIPv4moreFragments)
                
                guard let IPv4partFragmentOffset = IPv4part.fragmentOffset.uint16 else { XCTFail(); return }
                XCTAssertEqual(IPv4partFragmentOffset, correctIPv4fragmentOffset)
                
                
                XCTAssertEqual(IPv4part.ttl, correctIPv4ttl)
                XCTAssertEqual(IPv4part.protocolNumber, correctIPv4protocolNumber)
                XCTAssertEqual(IPv4part.checksum, correctIPv4checksum)
                XCTAssertEqual(IPv4part.sourceAddress, correctIPv4sourceAddress)
                XCTAssertEqual(IPv4part.destinationAddress, correctIPv4destinationAddress)
                XCTAssertEqual(IPv4part.options, correctIPv4options)
                XCTAssertEqual(IPv4part.payload, correctIPv4payload)
                
                let IPV4partData = IPv4part.data
                XCTAssertEqual(IPV4partData, correctPayload)
            }
            else
            {
                XCTFail()
                return
            }
        }
        else
        {
            XCTFail()
            return
        }
    }
    
    func testTCPinitData()
    {
        //https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=telnet-raw.pcap
        //excerpt from packet #4
        
        let packetTCPBytes = Data(array: [
            0x04, 0xe6, 0x00, 0x17, 0x04, 0x53, 0xd8, 0x70, 0xc0, 0x40, 0x87, 0xcf, 0x80, 0x18, 0x7d, 0x78,
            0x79, 0x0a, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x16, 0x0a, 0x27, 0x00, 0x05, 0x4b, 0x63,
            0xff, 0xfd, 0x03, 0xff, 0xfb, 0x18, 0xff, 0xfb, 0x1f, 0xff, 0xfb, 0x20, 0xff, 0xfb, 0x21, 0xff,
            0xfb, 0x22, 0xff, 0xfb, 0x27, 0xff, 0xfd, 0x05, 0xff, 0xfb, 0x23
        ])
        
        let packetTCPBytesOptionsNil = Data(array: [ //first 4 bits of byte13
            0x04, 0xe6, 0x00, 0x17, 0x04, 0x53, 0xd8, 0x70,
            0xc0, 0x40, 0x87, 0xcf, 0x10, 0x18, 0x7d, 0x78,
            0x79, 0x0a, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
            0x00, 0x16, 0x0a, 0x27, 0x00, 0x05, 0x4b, 0x63,
            0xff, 0xfd, 0x03, 0xff, 0xfb, 0x18, 0xff, 0xfb,
            0x1f, 0xff, 0xfb, 0x20, 0xff, 0xfb, 0x21, 0xff,
            0xfb, 0x22, 0xff, 0xfb, 0x27, 0xff, 0xfd, 0x05,
            0xff, 0xfb, 0x23
        ])
        
        let packetTCPBytesPayloadNil  = Data(array:[
            0x04, 0xe6, 0x00, 0x17, 0x04, 0x53, 0xd8, 0x70,
            0xc0, 0x40, 0x87, 0xcf, 0x80, 0x18, 0x7d, 0x78,
            0x79, 0x0a, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
            0x00, 0x16, 0x0a, 0x27, 0x00, 0x05, 0x4b, 0x63])
        
        let correctSourcePort: UInt16 = 0x04e6
        let correctDestinationPort: UInt16 = 0x0017
        let correctSequenceNumber: Data = Data(array: [0x04, 0x53, 0xd8, 0x70])
        let correctAcknowledgementNumber: Data = Data(array: [0xc0, 0x40, 0x87, 0xcf])
        let correctOffset: UInt8 = 0x08
        let correctReserved: UInt8 = 0b000
        let correctNS: Bool = false //UInt8 = 0b0
        let correctCWR: Bool = false //UInt8 = 0b0
        let correctECE: Bool = false //UInt8 = 0b0
        let correctURG: Bool = false //UInt8 = 0b0
        let correctACK: Bool = true //UInt8 = 0b1
        let correctPSH: Bool = true //UInt8 = 0b1
        let correctRST: Bool = false //UInt8 = 0b0
        let correctSYN: Bool = false //UInt8 = 0b0
        let correctFIN: Bool = false //UInt8 = 0b0
        let correctWindowSize: UInt16 = 0x7d78
        let correctCheckSum: UInt16 = 0x790a
        let correctUrgentPointer: UInt16 = 0x0000
        let correctOptions: Data = Data(array: [0x01, 0x01, 0x08, 0x0a, 0x00, 0x16, 0x0a, 0x27, 0x00, 0x05, 0x4b, 0x63])
        let correctPayload: Data = Data(array:[
            0xff, 0xfd, 0x03, 0xff, 0xfb, 0x18, 0xff, 0xfb, 0x1f, 0xff, 0xfb, 0x20, 0xff, 0xfb, 0x21, 0xff,
            0xfb, 0x22, 0xff, 0xfb, 0x27, 0xff, 0xfd, 0x05, 0xff, 0xfb, 0x23])
        
        let correctDataBytes = Data(array:[
            0x04, 0xe6, //sourcce
            0x00, 0x17, //dest
            0x04, 0x53, 0xd8, 0x70, //seq#
            0xc0, 0x40, 0x87, 0xcf, //ack#
            0x08, //offset
            0x00, //reserved
            0x00, //ns
            0x00, //cwr
            0x00, //ece
            0x00, //urg
            0x01, //ack
            0x01, //psh
            0x00, //rst
            0x00, //syn
            0x00, //fin
            0x7d, 0x78, //windowsize
            0x79, 0x0a, //checksum
            0x00, 0x00, //urgent pointer
            //options
            0x01, 0x01, 0x08, 0x0a, 0x00, 0x16, 0x0a, 0x27, 0x00, 0x05, 0x4b, 0x63,
            //data
            0xff, 0xfd, 0x03, 0xff, 0xfb, 0x18, 0xff, 0xfb,
            0x1f, 0xff, 0xfb, 0x20, 0xff, 0xfb, 0x21, 0xff,
            0xfb, 0x22, 0xff, 0xfb, 0x27, 0xff, 0xfd, 0x05, 0xff, 0xfb, 0x23
        ])
        
        if let TCPsegment = TCP(data: packetTCPBytes)
        {
            XCTAssertEqual(TCPsegment.sourcePort, correctSourcePort)
            XCTAssertEqual(TCPsegment.destinationPort, correctDestinationPort)
            XCTAssertEqual(TCPsegment.sequenceNumber, correctSequenceNumber)
            XCTAssertEqual(TCPsegment.acknowledgementNumber, correctAcknowledgementNumber)
            
            guard let TCPsegmentOffset = TCPsegment.offset.uint8 else { XCTFail(); return }
            XCTAssertEqual(TCPsegmentOffset, correctOffset)
            
            guard let TCPsegmentReserved = TCPsegment.reserved.uint8 else { XCTFail(); return }
            XCTAssertEqual(TCPsegmentReserved, correctReserved)
            
            XCTAssertEqual(TCPsegment.ns, correctNS)
            XCTAssertEqual(TCPsegment.cwr, correctCWR)
            XCTAssertEqual(TCPsegment.ece, correctECE)
            XCTAssertEqual(TCPsegment.urg, correctURG)
            XCTAssertEqual(TCPsegment.ack, correctACK)
            XCTAssertEqual(TCPsegment.psh, correctPSH)
            XCTAssertEqual(TCPsegment.rst, correctRST)
            XCTAssertEqual(TCPsegment.syn, correctSYN)
            XCTAssertEqual(TCPsegment.fin, correctFIN)
            XCTAssertEqual(TCPsegment.windowSize, correctWindowSize)
            XCTAssertEqual(TCPsegment.checksum, correctCheckSum)
            XCTAssertEqual(TCPsegment.urgentPointer, correctUrgentPointer)
            XCTAssertEqual(TCPsegment.options, correctOptions)
            XCTAssertEqual(TCPsegment.payload, correctPayload)
            
            let TCPsegmentData = TCPsegment.data
            XCTAssertEqual(TCPsegmentData, packetTCPBytes)
        }
        else
        {
            XCTFail()
            return
        }
        
        if let TCPsegmentOpsNil = TCP(data: packetTCPBytesOptionsNil){
            XCTAssertNil(TCPsegmentOpsNil.options)
        }
        else
        {
            XCTFail()
            return
        }
        
        if let TCPsegmentPayloadNil = TCP(data: packetTCPBytesPayloadNil){
            XCTAssertNil(TCPsegmentPayloadNil.payload)
        }
        else
        {
            XCTFail()
            return
        }
    }
    
    func testEthernetInitData_VLANtag()
    {
        //https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=vlan.cap.gz
        //packet #6
        let packetVLANBytes = Data(array: [
            0x00, 0x40, 0x05, 0x40, 0xef, 0x24, 0x00, 0x60, 0x08, 0x9f, 0xb1, 0xf3, 0x81, 0x00, 0x00, 0x20,
            0x08, 0x00, 0x45, 0x00, 0x00, 0x34, 0x8a, 0x1b, 0x40, 0x00, 0x40, 0x06, 0x68, 0xe4, 0x83, 0x97,
            0x20, 0x15, 0x83, 0x97, 0x20, 0x81, 0x17, 0x70, 0x04, 0x8a, 0x4d, 0x3d, 0x54, 0xb9, 0x4e, 0x14,
            0xde, 0x3d, 0x80, 0x10, 0x7c, 0x70, 0x31, 0xed, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x01, 0x99,
            0xa3, 0xf3, 0x00, 0x04, 0xf0, 0xc7
        ])
        
        let correctMACdestination = Data(array: [0x00, 0x40, 0x05, 0x40, 0xef, 0x24])
        let correctMACsource = Data(array: [0x00, 0x60, 0x08, 0x9f, 0xb1, 0xf3])
        let correctType = EtherType(rawValue: 0x0800) //IPv4
        let correctTag1 = Data(array: [0x81, 0x00, 0x00, 0x20])
        //let correctTag2 = Data(array: [])
        let correctPayload = Data(array: [
            0x45, 0x00, 0x00, 0x34, 0x8a, 0x1b, 0x40, 0x00, 0x40, 0x06, 0x68, 0xe4, 0x83, 0x97,
            0x20, 0x15, 0x83, 0x97, 0x20, 0x81, 0x17, 0x70, 0x04, 0x8a, 0x4d, 0x3d, 0x54, 0xb9, 0x4e, 0x14,
            0xde, 0x3d, 0x80, 0x10, 0x7c, 0x70, 0x31, 0xed, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x01, 0x99,
            0xa3, 0xf3, 0x00, 0x04, 0xf0, 0xc7
        ])
        
        let correctDataBytes = Data(array: [
            0x00, 0x40, 0x05, 0x40, 0xef, 0x24, 0x00, 0x60, 0x08, 0x9f, 0xb1, 0xf3, 0x08, 0x00, 0x81, 0x00,
            0x00, 0x20, 0x45, 0x00, 0x00, 0x34, 0x8a, 0x1b, 0x40, 0x00, 0x40, 0x06, 0x68, 0xe4, 0x83, 0x97,
            0x20, 0x15, 0x83, 0x97, 0x20, 0x81, 0x17, 0x70, 0x04, 0x8a, 0x4d, 0x3d, 0x54, 0xb9, 0x4e, 0x14,
            0xde, 0x3d, 0x80, 0x10, 0x7c, 0x70, 0x31, 0xed, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x01, 0x99,
            0xa3, 0xf3, 0x00, 0x04, 0xf0, 0xc7
        ])
        
        if let epacket = Ethernet(data: packetVLANBytes)
        {
            XCTAssertEqual(epacket.MACDestination, correctMACdestination)
            XCTAssertEqual(epacket.MACSource, correctMACsource)
            XCTAssertEqual(epacket.type, correctType)
            XCTAssertEqual(epacket.payload, correctPayload)
            XCTAssertEqual(epacket.tag1, correctTag1)
            XCTAssertNil(epacket.tag2)
            
            let epacketData = epacket.data
            XCTAssertEqual(epacketData, correctDataBytes)
        }
        else
        {
            XCTFail()
            return
        }
    }
    
    //    func testEthernetInit_VLANdoubleTag(){
    //        //https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=hp-erm-2.cap
    //        //fix / verify
    //        //XCTFail()
    //    }
    
    //write test for synthetic packet construction, test to see if data out is as expected
    //let ethernet = Ethernet(MACDestination: <#T##Data#>, MACSource: <#T##Data#>, type: <#T##EtherType#>, tag1: <#T##Data?#>, tag2: <#T##Data?#>, payload: <#T##Data#>)
    
    
    func testEthernetInitFails()
    {
        //sample source: https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=tcp-ethereal-file1.trace
        //packet #4
        //and https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=vlan.cap.gz
        //packet #6
        
        let ethernetBytesMACsourceFail =  Data(array: [0x00, 0x0d, 0x88, 0x40, 0xdf])
        let ethernetBytesMACdestinationFail = Data(array: [0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d, 0x00, 0x05, 0x9a, 0x3c, 0x78])
        let ethernetBytesMACtypeFail1 = Data(array:[0x00, 0x05, 0x9a, 0x3c, 0x78, 0x00, 0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d, 0x08])
        let ethernetBytesMACtypeFail2 = Data(array:[0x00, 0x05, 0x9a, 0x3c, 0x78, 0x00, 0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d, 0x09, 0x00])
        let ethernetBytesVLANtag2Fail = Data(array:[0x00, 0x40, 0x05, 0x40, 0xef, 0x24, 0x00, 0x60, 0x08, 0x9f, 0xb1, 0xf3, 0x81, 0x00, 0x00])
        let ethernetBytesVLANtagTypeFail = Data(array:[0x00, 0x40, 0x05, 0x40, 0xef, 0x24, 0x00, 0x60, 0x08, 0x9f, 0xb1, 0xf3, 0x81, 0x00, 0x00, 0x20, 0x00])
        let ethernetBytesVLANtagEtherTypeConFail = Data(array:[0x00, 0x40, 0x05, 0x40, 0xef, 0x24,
                                                               0x00, 0x60, 0x08, 0x9f, 0xb1, 0xf3,
                                                               0x81, 0x00,
                                                               0x00, 0x20,
                                                               0xff, 0xff, 0xff])
        
        let ethernetBytesPayloadFail = Data(array:[0x00, 0x05, 0x9a, 0x3c, 0x78, 0x00, 0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d, 0x08, 0x00]) //no payload
        
        XCTAssertNil(Ethernet(data: ethernetBytesMACsourceFail))
        XCTAssertNil(Ethernet(data: ethernetBytesMACdestinationFail))
        XCTAssertNil(Ethernet(data: ethernetBytesMACtypeFail1))
        XCTAssertNil(Ethernet(data: ethernetBytesMACtypeFail2))
        XCTAssertNil(Ethernet(data: ethernetBytesVLANtag2Fail))
        XCTAssertNil(Ethernet(data: ethernetBytesVLANtagTypeFail))
        XCTAssertNil(Ethernet(data: ethernetBytesVLANtagEtherTypeConFail))
        XCTAssertNil(Ethernet(data: ethernetBytesPayloadFail))
    }
    
    func testIPv4initFails()
    {
        let IPv4IHLfail = Data(array: [])
        let IPv4DSCPECNfail = Data(array: [0x45])
        let IPv4LengthFail = Data(array: [0x45, 0x00, 0x00])
        let IPv4IdentificationFail = Data(array: [0x45, 0x00, 0x00, 0x30, 0x00])
        let IPv4flagsFragmentOffsetFail = Data(array: [0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40])
        let IPv4ttlFail = Data(array: [0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40, 0x00])
        let IPv4protocolNumberFail = Data(array: [0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0x34])
        let IPv4checksumFail = Data(array: [0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0x34, 0x06, 0x2d])
        let IPv4sourceAddressFail = Data(array: [
            0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40, 0x00,
            0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5])
        let IPv4destinationAddressFail = Data(array: [
            0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40, 0x00,
            0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5, 0x0c,
            0x83, 0xd4, 0x1f])
        let IPv4optionsFail = Data(array: [
            0x46, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40, 0x00,
            0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5, 0x0c,
            0x83, 0xd4, 0x1f, 0xa7, 0x00])
        let IPv4payloadFail = Data(array: [
            0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40, 0x00,
            0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5, 0x0c,
            0x83, 0xd4, 0x1f, 0xa7])
        
        XCTAssertNil(IPv4(data: IPv4IHLfail))
        XCTAssertNil(IPv4(data: IPv4DSCPECNfail))
        XCTAssertNil(IPv4(data: IPv4LengthFail))
        XCTAssertNil(IPv4(data: IPv4IdentificationFail))
        XCTAssertNil(IPv4(data: IPv4flagsFragmentOffsetFail))
        XCTAssertNil(IPv4(data: IPv4ttlFail))
        XCTAssertNil(IPv4(data: IPv4protocolNumberFail))
        XCTAssertNil(IPv4(data: IPv4checksumFail))
        XCTAssertNil(IPv4(data: IPv4sourceAddressFail))
        XCTAssertNil(IPv4(data: IPv4destinationAddressFail))
        XCTAssertNil(IPv4(data: IPv4optionsFail))
        XCTAssertNil(IPv4(data: IPv4payloadFail))
    }
    
    func testTCPinitFails()
    {
        //https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=telnet-raw.pcap
        //excerpt from packet #4
        
        let TCPsourcePortFail = Data(array:[0x04])
        let TCPdestinationPortFail = Data(array:[0x04, 0xe6, 0x00])
        let TCPsequenceNumberFail = Data(array:[0x04, 0xe6, 0x00, 0x17, 0x04, 0x53, 0xd8])
        let TCPacknowledgementNumberFail = Data(array:[
            0x04, 0xe6, 0x00, 0x17, 0x04, 0x53, 0xd8, 0x70,
            0xc0, 0x40, 0x87])
        let TCPoffsetReservedFlagsFail = Data(array:[
            0x04, 0xe6, 0x00, 0x17, 0x04, 0x53, 0xd8, 0x70,
            0xc0, 0x40, 0x87, 0xcf, 0x80])
        let TCPwindowSizeFail = Data(array:[
            0x04, 0xe6, 0x00, 0x17, 0x04, 0x53, 0xd8, 0x70,
            0xc0, 0x40, 0x87, 0xcf, 0x80, 0x18, 0x7d])
        let TCPchecksumFail = Data(array:[
            0x04, 0xe6, 0x00, 0x17, 0x04, 0x53, 0xd8, 0x70,
            0xc0, 0x40, 0x87, 0xcf, 0x80, 0x18, 0x7d, 0x78,
            0x79])
        let TCPurgentPointerFail = Data(array:[
            0x04, 0xe6, 0x00, 0x17, 0x04, 0x53, 0xd8, 0x70,
            0xc0, 0x40, 0x87, 0xcf, 0x80, 0x18, 0x7d, 0x78,
            0x79,0x0a, 0x00])
        let TCPoptionsFail = Data(array:[
            0x04, 0xe6, 0x00, 0x17, 0x04, 0x53, 0xd8, 0x70,
            0xc0, 0x40, 0x87, 0xcf, 0x80, 0x18, 0x7d, 0x78,
            0x79,0x0a, 0x00, 0x00])
        
        XCTAssertNil(TCP(data: TCPsourcePortFail))
        XCTAssertNil(TCP(data: TCPdestinationPortFail))
        XCTAssertNil(TCP(data: TCPsequenceNumberFail))
        XCTAssertNil(TCP(data: TCPacknowledgementNumberFail))
        XCTAssertNil(TCP(data: TCPoffsetReservedFlagsFail))
        XCTAssertNil(TCP(data: TCPwindowSizeFail))
        XCTAssertNil(TCP(data: TCPchecksumFail))
        XCTAssertNil(TCP(data: TCPurgentPointerFail))
        XCTAssertNil(TCP(data: TCPoptionsFail))
        //XCTAssertNil(TCP(data: TCPpayloadFail)) //unable to test this fail, has an if statement ahead that prevents typical fail
    }
    
    func testUDPInitData()
    {
        //https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=b6300a.cap
        //packet #2
        
        let packetUDPBytes = Data(array: [
            0x00, 0xa1, 0x3e, 0x2c, 0x00, 0x42, 0x7d, 0x6d, 0x30, 0x38, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
            0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x2b, 0x02, 0x01, 0x26, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x20, 0x30, 0x1e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00, 0x06, 0x12,
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x51, 0x01, 0x01, 0x01, 0x82, 0x29, 0x5d, 0x01, 0x1b, 0x02,
            0x02, 0x01
        ])
        
        let correctSourcePort: UInt16 = 0x00a1
        let correctDestinationPort: UInt16 = 0x3e2c
        let correctLength: UInt16 = 0x0042
        let correctChecksum: UInt16 = 0x7d6d
        let correctPayload: Data = Data(array:[
            0x30, 0x38, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x2b, 0x02,
            0x01, 0x26, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x20, 0x30, 0x1e, 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x02, 0x01, 0x01, 0x02, 0x00, 0x06, 0x12, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x51, 0x01,
            0x01, 0x01, 0x82, 0x29, 0x5d, 0x01, 0x1b, 0x02, 0x02, 0x01
        ])
        
        let correctUDPsegmentBytes = Data(array:[
            0x00, 0xa1, // source port
            0x3e, 0x2c, // dest port
            0x00, 0x42, // length
            0x7d, 0x6d, // checksum
            0x30, 0x38, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
            0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x2b, 0x02, 0x01, 0x26, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x20, 0x30, 0x1e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00, 0x06, 0x12,
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x51, 0x01, 0x01, 0x01, 0x82, 0x29, 0x5d, 0x01, 0x1b, 0x02,
            0x02, 0x01
        ])
        
        if let udpSegment = UDP(data: packetUDPBytes)
        {
            XCTAssertEqual(udpSegment.sourcePort, correctSourcePort)
            XCTAssertEqual(udpSegment.destinationPort, correctDestinationPort)
            XCTAssertEqual(udpSegment.length, correctLength)
            XCTAssertEqual(udpSegment.checksum, correctChecksum)
            XCTAssertEqual(udpSegment.payload, correctPayload)
            
            let udpSegmentData = udpSegment.data
            XCTAssertEqual(udpSegmentData, correctUDPsegmentBytes)
        }
        else
        {
            XCTFail()
            return
        }
    }
    
    func testUDPInitFails()
    {
        //https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=b6300a.cap
        //packet #2
        
        let packetUDPBytesSourcePortFail = Data(array: [0x00])
        let packetUDPBytesDestinationFail = Data(array: [0x00, 0xa1, 0x3e])
        let packetUDPBytesLengthFail = Data(array: [0x00, 0xa1, 0x3e, 0x2c, 0x00])
        let packetUDPBytesChecksumFail = Data(array: [0x00, 0xa1, 0x3e, 0x2c, 0x00, 0x42, 0x7d])
        let packetUDPBytesPayloadFail = Data(array: [0x00, 0xa1, 0x3e, 0x2c, 0x00, 0x42, 0x7d, 0x6d])
        
        XCTAssertNil(UDP(data: packetUDPBytesSourcePortFail))
        XCTAssertNil(UDP(data: packetUDPBytesDestinationFail))
        XCTAssertNil(UDP(data: packetUDPBytesLengthFail))
        XCTAssertNil(UDP(data: packetUDPBytesChecksumFail))
        XCTAssertNil(UDP(data: packetUDPBytesPayloadFail)!.payload)
    }
    
    func testIPprotocolNumber_init()
    {
        if let ICMPtest = IPprotocolNumber(data: Data(array: [0x01]))
        {
            XCTAssertEqual(ICMPtest, .ICMP)
        }
        else
        {
            XCTFail()
            return
        }
    }
    
    func testIPprotocolNumber_data()
    {
        let ICMPcorrect = Data(array: [0x01])
        let ICMP = IPprotocolNumber.ICMP
        
        if let ICMPtest = ICMP.data
        {
            
            XCTAssertEqual(ICMPtest, ICMPcorrect)
        }
        else
        {
            XCTFail()
            return
        }
    }
    
    func testSong()
    {
        //fix / verify
        //sample source: https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=tcp-ethereal-file1.trace
        //packet #4
        let packetBytes = Data(array: [
            0x00, 0x05, 0x9a, 0x3c, 0x78, 0x00, 0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5, 0x0c, 0x83, 0xd4,
            0x1f, 0xa7, 0x00, 0x50, 0x08, 0x30, 0x3d, 0xe4, 0xa9, 0x33, 0x99, 0x5f, 0xcf, 0x79, 0x70, 0x12,
            0x05, 0xb4, 0x0b, 0xeb, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02])
        
        let correctMACsource = Data(array: [0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d])
        let correctMACdestination = Data(array: [0x00, 0x05, 0x9a, 0x3c, 0x78, 0x00])
        let correctType = EtherType(rawValue: 0x0800) //IPv4
        //let correctTag1 = Data(array: [])
        //let correctTag2 = Data(array: [])
        let correctPayload = Data(array: [
            0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40, 0x00,
            0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5, 0x0c,
            0x83, 0xd4, 0x1f, 0xa7, 0x00, 0x50, 0x08, 0x30,
            0x3d, 0xe4, 0xa9, 0x33, 0x99, 0x5f, 0xcf, 0x79,
            0x70, 0x12, 0x05, 0xb4, 0x0b, 0xeb, 0x00, 0x00,
            0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02])
        
        let correctIPv4version: UInt8 = 0x04
        let correctIPv4IHL: UInt8 = 0x05
        let correctIPv4DSCP: UInt8 = 0x00
        let correctIPv4ECN: UInt8 = 0x00 //(48)
        let correctIPv4length: UInt16 = 0x0030
        let correctIPv4identification: UInt16 = 0x0000
        //let correctIPv4flags: UInt8 = 0b010 //UInt8 3 bits
        let correctIPv4reservedBit: UInt8 = 0b0
        let correctIPv4dontFragment: UInt8 = 0b1
        let correctIPv4moreFragments: UInt8 = 0b0
        let correctIPv4fragmentOffset: UInt16 = 0x0000
        let correctIPv4ttl: UInt8 = 0x34 //(52)
        let correctIPv4protocolNumber: UInt8 = 0x06 //tcp
        let correctIPv4checksum: UInt16 = 0x2dc9
        let correctIPv4sourceAddress: Data = Data(array:[0x80, 0x77, 0xf5, 0x0c]) //128.119.245.12
        let correctIPv4destinationAddress: Data = Data(array:[0x83, 0xd4, 0x1f, 0xa7]) //131.212.31.167
        let correctIPv4options: Data? = nil
        let correctIPv4payload: Data = Data(array:[
            0x00, 0x50, 0x08, 0x30, 0x3d, 0xe4, 0xa9, 0x33,
            0x99, 0x5f, 0xcf, 0x79, 0x70, 0x12, 0x05, 0xb4,
            0x0b, 0xeb, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
            0x01, 0x01, 0x04, 0x02])
    }
    
    
    func testWithPCAPs()
    {
        /*
         This test function loads a pcap and a text file created by tshark with as many parsed fields as possible. The test then compares the results of InternetProtocols' parsing against Tshark's parsing.
         Any pcap can be used, just place a copy of the pcap in "TestResources" and rerun  processPCAPsWithTshark.sh to generate the tshark parsed text file.
         
         Note, this function uses a bundle to access pcap files used for testing
         These are located in the directory "TestResources"
         file name requirements:
         <name>.pcap - pcap file to test against
         <name>.pcap.txt - tshark pcap parsing results. note these are not the complete packet dissection results but it has most fields and is easy to handle. JSON is a more complete tshark result, but the parsing seems much more involved
         
         In xcode, to get this to work:
         swift package update
         swift package generate-xcodeproj
         open the xcode project
         select InternetProtocolsTests under Targets
         click +, to add a new build phase, select New Copy Bundle Resources Phase
         expand Copy Bundle Resources
         under the new phase, click +, to add items to the phase, select TestResources folder and click Add
         now when the tests are run, they will have access to the files in the TestResources folder.
         
         Notes on adding a bundle using SPM - not currently working for tests, but will in Swift 5.3, https://github.com/apple/swift-evolution/blob/master/proposals/0271-package-manager-resources.md
         
         https://medium.com/better-programming/how-to-add-resources-in-swift-package-manager-c437d44ec593
         https://developer.apple.com/documentation/foundation/bundle
         
         */
        
        print("👋")
        let bundleDoingTest = Bundle(for: type(of: self ))
        print("👉 bundleDoingTest.bundlePath : \(bundleDoingTest.bundlePath)") // …/PATH/TO/Debug/ExampleTests.xctest
        print("👉 bundleDoingTest = " + bundleDoingTest.description) // Test Case Bundle
        
        guard let pcapFileList = bundleDoingTest.urls(forResourcesWithExtension: "pcap", subdirectory: "TestResources") else
        {
            XCTFail()
            return
        }
        print("👉 PCAP file count: \(pcapFileList.count)")
        
        if pcapFileList.count == 0
        {
            //PCAPs not in bundle.
            XCTFail()
            return
        }
        
        guard let pcapTextFileList = bundleDoingTest.urls(forResourcesWithExtension: "txt", subdirectory: "TestResources") else
        {
            XCTFail()
            return
        }
        print("👉 Text file count: \(pcapFileList.count)\n")
        
        if pcapFileList.count != pcapFileList.count
        {
            //PCAP and text file count mismatch, there should be 1 txt per PCAP
            XCTFail()
            return
        }
        
        
        var processingFile: Bool = true
        var packetCount: Int
        var fileCount: Int = 0
        
        for pcapFile in pcapFileList
        {
            packetCount = 0
            fileCount += 1
            print("📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦📦")
            print("► Processing PCAP \(fileCount): \(pcapFile.absoluteURL)")
            
            guard let packetSource = try? SwiftPCAP.Offline(path: pcapFile.path ) else
            {
                print("‼️ Error opening pcap file")
                XCTFail()
                return
            }
            
            let pcapTextFilePath = pcapFile.path + ".txt"
            print ("► Text file: \(pcapTextFilePath)")
            
            let textFileURL = URL(fileURLWithPath:pcapTextFilePath)
            var contents: String = ""
            print("► Loading \(pcapTextFilePath)...")
            do
            {
                contents = try String(contentsOf: textFileURL)
                print("► File loaded...")
            }
            catch
            {
                print("‼️ Failed to load text file due to error \(error).")
                XCTFail()
                return
            }
            
            let textFileLines = contents.components(separatedBy:"\n")
            
            processingFile = true
            
            print("👉 reading packets")
            while processingFile
            {
                let bytes = packetSource.nextPacket()
                let timestamp = packetSource.currentHeader.ts
                
                if bytes.count == 0
                {
                    print("👉 done with pcap # \(fileCount)")
                    processingFile = false
                }
                else
                {
                    packetCount += 1
                    print("📁 \(fileCount) ► Packet \(packetCount) - bytes \(bytes.count)")
                    
                    let thisTsharkPacket = tsharkTextFilePacket(lineToParse: textFileLines[packetCount])
                    
                    XCTAssertEqual(thisTsharkPacket.frame_number, packetCount)
                    
                    var hasVLAN: Bool = false
                    
                    var debugprint: Bool = false
                    if fileCount == 9000 && packetCount == 1
                    {
                        print("🎯 debug target")
                        debugprint = true
                    }
                    
                    let thisPacket = Packet(rawBytes: Data(bytes), timestamp: timestamp, debugPrints: debugprint) //parse the packet
                    
                    if thisPacket.ethernet != nil
                    {
                        print("➢ checking ethernet")//, terminator:"")
                        XCTAssertEqual(thisTsharkPacket.eth_src, thisPacket.ethernet!.MACSource)
                        XCTAssertEqual(thisTsharkPacket.eth_dst, thisPacket.ethernet!.MACDestination)
                        
                        if thisPacket.ethernet!.tag1 == nil && thisPacket.ethernet!.type != .sizeNotEtherType
                            //fix, when parsing vlan packets the type field is set to the inner ethernet type, and not the VLAN type - tshark views VLAN to be the ehternet type and not ipv4. so if it's a VLAN packet we skip the following test
                        {
                            XCTAssertEqual(thisTsharkPacket.eth_type, thisPacket.ethernet!.type)
                        }
                        else
                        {
                            print("⚠️ Packet has VLAN, which is not currently handled fully")
                            hasVLAN = true
                        }
                    }
                    
                    if thisPacket.ipv4 != nil
                    {
                        print("➢ checking IP")//, terminator:"")
                        XCTAssertEqual(thisTsharkPacket.ip_version, thisPacket.ipv4!.version.uint8)
                        XCTAssertEqual(thisTsharkPacket.ip_hdr_len, thisPacket.ipv4!.IHL.uint8)
                        XCTAssertEqual(thisTsharkPacket.ip_dsfield_dscp, thisPacket.ipv4!.DSCP.uint8)
                        XCTAssertEqual(thisTsharkPacket.ip_dsfield_ecn, thisPacket.ipv4!.ECN.uint8)
                        XCTAssertEqual(thisTsharkPacket.ip_len, thisPacket.ipv4!.length)
                        XCTAssertEqual(thisTsharkPacket.ip_id, thisPacket.ipv4!.identification)
                        XCTAssertEqual(thisTsharkPacket.ip_flags_rb, thisPacket.ipv4!.reservedBit)
                        XCTAssertEqual(thisTsharkPacket.ip_flags_df, thisPacket.ipv4!.dontFragment)
                        XCTAssertEqual(thisTsharkPacket.ip_flags_mf, thisPacket.ipv4!.moreFragments)
                        
                        DatableConfig.endianess = .big
                        let thisPacketFragOffset = thisPacket.ipv4!.fragmentOffset.uint16
                        DatableConfig.endianess = .little
                        
                        XCTAssertEqual(thisTsharkPacket.ip_frag_offset, thisPacketFragOffset)
                        XCTAssertEqual(thisTsharkPacket.ip_ttl, thisPacket.ipv4!.ttl)
                        XCTAssertEqual(thisTsharkPacket.ip_proto, thisPacket.ipv4!.protocolNumber)
                        XCTAssertEqual(thisTsharkPacket.ip_checksum, thisPacket.ipv4!.checksum)
                        XCTAssertEqual(thisTsharkPacket.ip_src, thisPacket.ipv4!.sourceAddress)
                        XCTAssertEqual(thisTsharkPacket.ip_dst, thisPacket.ipv4!.destinationAddress)
                        XCTAssertEqual(thisTsharkPacket.eth_padding, thisPacket.ipv4!.ethernetPadding)
                    }
                    
                    if thisPacket.tcp != nil //capture tcp packet
                    {
                        print("➢ checking TCP")//, terminator:"")
                        XCTAssertEqual(thisTsharkPacket.tcp_srcport, thisPacket.tcp!.sourcePort)
                        XCTAssertEqual(thisTsharkPacket.tcp_dstport, thisPacket.tcp!.destinationPort)
                        XCTAssertEqual(thisTsharkPacket.tcp_hdr_len, thisPacket.tcp!.offset.uint8 )
                        XCTAssertEqual(thisTsharkPacket.tcp_flags_res, thisPacket.tcp!.reserved.uint8)
                        XCTAssertEqual(thisTsharkPacket.tcp_flags_ns, thisPacket.tcp!.ns)
                        XCTAssertEqual(thisTsharkPacket.tcp_flags_cwr, thisPacket.tcp!.cwr)
                        XCTAssertEqual(thisTsharkPacket.tcp_flags_ecn, thisPacket.tcp!.ece)
                        XCTAssertEqual(thisTsharkPacket.tcp_flags_urg, thisPacket.tcp!.urg)
                        XCTAssertEqual(thisTsharkPacket.tcp_flags_ack, thisPacket.tcp!.ack)
                        XCTAssertEqual(thisTsharkPacket.tcp_flags_push, thisPacket.tcp!.psh)
                        XCTAssertEqual(thisTsharkPacket.tcp_flags_reset, thisPacket.tcp!.rst)
                        XCTAssertEqual(thisTsharkPacket.tcp_flags_syn, thisPacket.tcp!.syn)
                        XCTAssertEqual(thisTsharkPacket.tcp_flags_fin, thisPacket.tcp!.fin)
                        XCTAssertEqual(thisTsharkPacket.tcp_window_size_value, thisPacket.tcp!.windowSize)
                        XCTAssertEqual(thisTsharkPacket.tcp_checksum, thisPacket.tcp!.checksum)
                        XCTAssertEqual(thisTsharkPacket.tcp_urgent_pointer, thisPacket.tcp!.urgentPointer)
                        XCTAssertEqual(thisTsharkPacket.tcp_options, thisPacket.tcp!.options)
                        XCTAssertEqual(thisTsharkPacket.tcp_payload, thisPacket.tcp!.payload)
                    }
                    
                    if thisPacket.udp != nil //capture udp packet
                    {
                        print("➢ checking UDP")//, terminator:"")
                        XCTAssertEqual(thisTsharkPacket.udp_srcport, thisPacket.udp!.sourcePort)
                        XCTAssertEqual(thisTsharkPacket.udp_dstport, thisPacket.udp!.destinationPort)
                        XCTAssertEqual(thisTsharkPacket.udp_length, thisPacket.udp!.length)
                        XCTAssertEqual(thisTsharkPacket.udp_checksum, thisPacket.udp!.checksum)
                    }
                    
                    if thisPacket.ethernet == nil && thisPacket.ipv4 == nil && thisPacket.tcp == nil && thisPacket.udp == nil
                    {
                        print("‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️")
                        print("‼️ Packet not parsed, result has no Ethernet, IPv4, TCP or UDP")
                        print("‼️ Parsing debug prints:")
                        _ = Packet(rawBytes: Data(bytes), timestamp: timestamp, debugPrints: true)
                        XCTFail()
                    }
                    
                    if thisPacket.ipv4 == nil && thisPacket.tcp == nil && thisPacket.udp == nil && thisPacket.ethernet!.type != .IPv4
                    {
                        print("⚠️ Packet not parsed beyond ethernet, ethertype not handled")
                        print("⚠️ ethertype: \(thisPacket.ethernet!.type)")
                        
                        if thisPacket.ethernet!.type == nil && hasVLAN != true {
                            print("‼️ ethertype is nil and doesn't seem to be a VLAN issue")
                            _ = Packet(rawBytes: Data(bytes), timestamp: timestamp, debugPrints: true)
                            XCTFail()
                        }
                    }
                    
                    if thisPacket.ipv4 == nil && thisPacket.ethernet!.type == .IPv4
                    {
                        if thisPacket.ethernet!.type! == .IPv4
                        {
                            print("‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️")
                            print("‼️ Packet not parsed correctly, type is IPv4 but no IPv4 results returned")
                            print("‼️ Parsing debug prints:")
                            _ = Packet(rawBytes: Data(bytes), timestamp: timestamp, debugPrints: true)
                            XCTFail()
                        }
                    }
                    
                    if thisPacket.ipv4 != nil && thisPacket.tcp == nil && thisPacket.ipv4!.protocolNumber == .TCP
                    {
                        print("‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️")
                        print("‼️ Packet not parsed correctly, type is IPv4 but no IPv4 results returned")
                        print("‼️ Parsing debug prints:")
                        _ = Packet(rawBytes: Data(bytes), timestamp: timestamp, debugPrints: true)
                        XCTFail()
                    }
                }
            }
        }
        print("✌️")
    }
    
    
    func testChecksum()
    {
        //sample source: https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=tcp-ethereal-file1.trace
        //packet #4
        //let packetBytes = Data(array: [
        //    0x00, 0x05, 0x9a, 0x3c, 0x78, 0x00, 0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d, 0x08, 0x00, 0x45, 0x00,
        //    0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5, 0x0c, 0x83, 0xd4,
        //    0x1f, 0xa7, 0x00, 0x50, 0x08, 0x30, 0x3d, 0xe4, 0xa9, 0x33, 0x99, 0x5f, 0xcf, 0x79, 0x70, 0x12,
        //    0x05, 0xb4, 0x0b, 0xeb, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02])
        
        let packetBytesToVerify = Data(array: [
            0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0x34, 0x06,
            0x2d, 0xc9, // <- the checksum bytes in the ip header
            0x80, 0x77, 0xf5, 0x0c, 0x83, 0xd4, 0x1f, 0xa7])
        
        let packetBytesToGenChecksum = Data(array: [
            0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0x34, 0x06,
            0x00, 0x00, // <- set checksum bytes to zero to compute the checksum for the ip header
            0x80, 0x77, 0xf5, 0x0c, 0x83, 0xd4, 0x1f, 0xa7])
        
        //calculating the checksum on the entire ip header should give a checksum of zero.
        guard let verificationResults = calculateChecksum(bytes: packetBytesToVerify) else
        {
            XCTFail()
            return
        }
        print("verification results: \(verificationResults)")
        printDataBytes(bytes: Data(uint16: verificationResults)!, hexDumpFormat: true, seperator: " ", decimal: false)
        XCTAssertEqual(verificationResults, 0)
        
        //setting the checksum bytes to 0x0000 before calculating should give the checksum of the ip header
        guard let generationResults = calculateChecksum(bytes: packetBytesToGenChecksum) else
        {
            XCTFail()
            return
        }
        print("checksum generation results: \(generationResults)")
        printDataBytes(bytes: Data(uint16: generationResults)!, hexDumpFormat: true, seperator: " ", decimal: false)
        XCTAssertEqual(generationResults, 0x2dc9)
    }
    
    func testEthernetConstructor()
    {
        //packet #4
        let packetBytes = Data(array: [
            0x00, 0x05, 0x9a, 0x3c, 0x78, 0x00, 0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5, 0x0c, 0x83, 0xd4,
            0x1f, 0xa7, 0x00, 0x50, 0x08, 0x30, 0x3d, 0xe4, 0xa9, 0x33, 0x99, 0x5f, 0xcf, 0x79, 0x70, 0x12,
            0x05, 0xb4, 0x0b, 0xeb, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02])
        
        let ourTime: timeval = timeval()
        
        let ourPacket = Packet(rawBytes: packetBytes, timestamp: ourTime, debugPrints: false)
        
        guard let ourEthernet = ourPacket.ethernet else
        {
            XCTFail()
            return
        }
        
        guard let constructedEthernet = Ethernet(
            MACDestination: ourEthernet.MACDestination,
            MACSource: ourEthernet.MACSource,
            type: ourEthernet.type,
            tag1: ourEthernet.tag1,
            tag2: ourEthernet.tag2,
            payload: ourEthernet.payload,
            ethernetSize: ourEthernet.size
            ) else
        {
            XCTFail()
            return
        }
        
        print("constructedEthernet:")
        print(constructedEthernet.description)
        
        XCTAssertEqual(constructedEthernet.MACDestination, ourEthernet.MACDestination)
        XCTAssertEqual(constructedEthernet.MACSource, ourEthernet.MACSource)
        XCTAssertEqual(constructedEthernet.type, ourEthernet.type)
        XCTAssertEqual(constructedEthernet.tag1, ourEthernet.tag1)
        XCTAssertEqual(constructedEthernet.tag2, ourEthernet.tag2)
        XCTAssertEqual(constructedEthernet.size, ourEthernet.size)
        XCTAssertEqual(constructedEthernet.payload, ourEthernet.payload)
        
        
    }
    
    
    func testIPv4constructor()
    {
        //sample source: https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=tcp-ethereal-file1.trace
        //packet #4
        let packetBytes = Data(array: [
            0x00, 0x05, 0x9a, 0x3c, 0x78, 0x00, 0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5, 0x0c, 0x83, 0xd4,
            0x1f, 0xa7, 0x00, 0x50, 0x08, 0x30, 0x3d, 0xe4, 0xa9, 0x33, 0x99, 0x5f, 0xcf, 0x79, 0x70, 0x12,
            0x05, 0xb4, 0x0b, 0xeb, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02])
        
        let ourTime: timeval = timeval()
        
        let ourPacket = Packet(rawBytes: packetBytes, timestamp: ourTime, debugPrints: false)
        
        guard let ourIP = ourPacket.ipv4 else
        {
            XCTFail()
            return
        }
        
        guard let constructedIPv4 = IPv4(
            version: ourIP.version,
            IHL: ourIP.IHL,
            DSCP: ourIP.DSCP,
            ECN: ourIP.ECN,
            length: ourIP.length,
            identification: ourIP.identification,
            reservedBit: ourIP.reservedBit,
            dontFragment: ourIP.dontFragment,
            moreFragments: ourIP.moreFragments,
            fragmentOffset: ourIP.fragmentOffset,
            ttl: ourIP.ttl,
            protocolNumber: ourIP.protocolNumber,
            checksum: nil, //pass nil to test calculating the IPv4 checksum
            sourceAddress: ourIP.sourceAddress,
            destinationAddress: ourIP.destinationAddress,
            options: ourIP.options,
            payload: ourIP.payload,
            ethernetPadding: ourIP.ethernetPadding
            ) else
        {
            XCTFail()
            return
        }
        
        print("constructedIPv4:")
        print(constructedIPv4.description)
        
        XCTAssertEqual(constructedIPv4.version.data, ourIP.version.data)
        XCTAssertEqual(constructedIPv4.IHL.data, ourIP.IHL.data)
        XCTAssertEqual(constructedIPv4.DSCP.data, ourIP.DSCP.data)
        XCTAssertEqual(constructedIPv4.ECN.data, ourIP.ECN.data)
        XCTAssertEqual(constructedIPv4.length, ourIP.length)
        XCTAssertEqual(constructedIPv4.identification, ourIP.identification)
        XCTAssertEqual(constructedIPv4.reservedBit, ourIP.reservedBit)
        XCTAssertEqual(constructedIPv4.dontFragment, ourIP.dontFragment)
        XCTAssertEqual(constructedIPv4.moreFragments, ourIP.moreFragments)
        XCTAssertEqual(constructedIPv4.fragmentOffset.data, ourIP.fragmentOffset.data)
        XCTAssertEqual(constructedIPv4.ttl, ourIP.ttl)
        XCTAssertEqual(constructedIPv4.protocolNumber, ourIP.protocolNumber)
        XCTAssertEqual(constructedIPv4.checksum, ourIP.checksum)
        XCTAssertEqual(constructedIPv4.sourceAddress, ourIP.sourceAddress)
        XCTAssertEqual(constructedIPv4.destinationAddress, ourIP.destinationAddress)
        XCTAssertEqual(constructedIPv4.options, ourIP.options)
        XCTAssertEqual(constructedIPv4.payload, ourIP.payload)
        XCTAssertEqual(constructedIPv4.ethernetPadding, ourIP.ethernetPadding)
    }
    
    func testTCPconstructor()
    {
        //sample source: https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=tcp-ethereal-file1.trace
        //packet #4
        let packetBytes = Data(array: [
            0x00, 0x05, 0x9a, 0x3c, 0x78, 0x00, 0x00, 0x0d, 0x88, 0x40, 0xdf, 0x1d, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0x34, 0x06, 0x2d, 0xc9, 0x80, 0x77, 0xf5, 0x0c, 0x83, 0xd4,
            0x1f, 0xa7, 0x00, 0x50, 0x08, 0x30, 0x3d, 0xe4, 0xa9, 0x33, 0x99, 0x5f, 0xcf, 0x79, 0x70, 0x12,
            0x05, 0xb4, 0x0b, 0xeb, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02])
        
        let ourTime: timeval = timeval()
        
        let ourPacket = Packet(rawBytes: packetBytes, timestamp: ourTime, debugPrints: false)
        
        guard let ourIP = ourPacket.ipv4 else
        {
            XCTFail()
            return
        }
        
        guard let ourTCP = ourPacket.tcp else
        {
            XCTFail()
            return
        }
        
        print("ourTCP:")
        print(ourTCP.description)
        
        guard let constructedTCP = TCP(
            sourcePort: ourTCP.sourcePort,
            destinationPort: ourTCP.destinationPort,
            sequenceNumber: ourTCP.sequenceNumber,
            acknowledgementNumber: ourTCP.acknowledgementNumber,
            offset: ourTCP.offset,
            reserved: ourTCP.reserved,
            ns: ourTCP.ns,
            cwr: ourTCP.cwr,
            ece: ourTCP.ece,
            urg: ourTCP.urg,
            ack: ourTCP.ack,
            psh: ourTCP.psh,
            rst: ourTCP.rst,
            syn: ourTCP.syn,
            fin: ourTCP.fin,
            windowSize: ourTCP.windowSize,
            checksum: nil, //pass nil to test calculating the TCP checksum
            urgentPointer: ourTCP.urgentPointer,
            options: ourTCP.options,
            payload: ourTCP.payload,
            IPv4: ourIP
            ) else
        {
            XCTFail()
            return
        }
        
        print("constructedTCP:")
        print(constructedTCP.description)
        
        
        XCTAssertEqual(constructedTCP.checksum, ourTCP.checksum)
        XCTAssertEqual(constructedTCP.sourcePort, ourTCP.sourcePort)
        XCTAssertEqual(constructedTCP.destinationPort, ourTCP.destinationPort)
        XCTAssertEqual(constructedTCP.sequenceNumber, ourTCP.sequenceNumber)
        XCTAssertEqual(constructedTCP.acknowledgementNumber, ourTCP.acknowledgementNumber)
        XCTAssertEqual(constructedTCP.offset.data, ourTCP.offset.data)
        XCTAssertEqual(constructedTCP.reserved.data, ourTCP.reserved.data)
        XCTAssertEqual(constructedTCP.ns, ourTCP.ns)
        XCTAssertEqual(constructedTCP.cwr, ourTCP.cwr)
        XCTAssertEqual(constructedTCP.ece, ourTCP.ece)
        XCTAssertEqual(constructedTCP.urg, ourTCP.urg)
        XCTAssertEqual(constructedTCP.ack, ourTCP.ack)
        XCTAssertEqual(constructedTCP.psh, ourTCP.psh)
        XCTAssertEqual(constructedTCP.rst, ourTCP.rst)
        XCTAssertEqual(constructedTCP.syn, ourTCP.syn)
        XCTAssertEqual(constructedTCP.fin, ourTCP.fin)
        XCTAssertEqual(constructedTCP.windowSize, ourTCP.windowSize)
        XCTAssertEqual(constructedTCP.urgentPointer, ourTCP.urgentPointer)
        XCTAssertEqual(constructedTCP.options, ourTCP.options)
        XCTAssertEqual(constructedTCP.payload, ourTCP.payload)
    }
    
    
    func testUDPconstructor()
    {
        //https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=b6300a.cap
        //packet #2
        
        let packetBytes = Data(array: [
            0x00, 0x12, 0x3f, 0x4a, 0x33, 0xd2, 0x08, 0x00, 0x37, 0x15, 0xe6, 0xbc, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x56, 0x1a, 0x1b, 0x00, 0x00, 0x40, 0x11, 0xe1, 0xbe, 0xac, 0x1f, 0x13, 0x49, 0xac, 0x1f,
            0x13, 0x36, 0x00, 0xa1, 0x3e, 0x2c, 0x00, 0x42, 0x7d, 0x6d, 0x30, 0x38, 0x02, 0x01, 0x00, 0x04,
            0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x2b, 0x02, 0x01, 0x26, 0x02, 0x01, 0x00, 0x02,
            0x01, 0x00, 0x30, 0x20, 0x30, 0x1e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00,
            0x06, 0x12, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x51, 0x01, 0x01, 0x01, 0x82, 0x29, 0x5d, 0x01,
            0x1b, 0x02, 0x02, 0x01
        ])
        
        let ourTime: timeval = timeval()
        
        let ourPacket = Packet(rawBytes: packetBytes, timestamp: ourTime, debugPrints: false)
        
        guard let ourIP = ourPacket.ipv4 else
        {
            XCTFail()
            return
        }
        
        guard let ourUDP = ourPacket.udp else
        {
            XCTFail()
            return
        }
        
        guard let constructedUDP = UDP(
            sourcePort: ourUDP.sourcePort,
            destinationPort: ourUDP.destinationPort,
            length: ourUDP.length,
            checksum: nil, //pass nil to test calculating the UDP checksum
            payload: ourUDP.payload,
            IPv4: ourIP
            ) else
        {
            XCTFail()
            return
        }
        
        print("constructedUDP:")
        print(constructedUDP.description)
        
        XCTAssertEqual(constructedUDP.sourcePort, ourUDP.sourcePort)
        XCTAssertEqual(constructedUDP.destinationPort, ourUDP.destinationPort)
        XCTAssertEqual(constructedUDP.length, ourUDP.length)
        XCTAssertEqual(constructedUDP.checksum, ourUDP.checksum)
        XCTAssertEqual(constructedUDP.payload, ourUDP.payload)
    }
    
    
}
