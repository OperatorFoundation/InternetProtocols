//
//  Parser.swift
//
//
//  Created by Dr. Brandon Wiley on 3/9/20.
//

import Foundation

import Bits
import Datable
import Net
import SwiftHexTools

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

    print("calculateChecksum(\(bytes.hex))")
    print("pseudoheader size: \(bytes.count)")
    
    var sum: UInt32 = 0 //0xFFFF + 0xFFFF = 0x1FFFE which is more than a UInt16 can hold
    
    var ourBytes = bytes
    
    if ourBytes.count % 2 != 0 //make sure we have an even number of bytes
    {
        ourBytes.append(0x00) //per RFCs append a 0x00 byte to the end to make it even, then calc checksum
    }
    
    for i in 0..<(ourBytes.count/2) //2 bytes at a time
    {
        let twoBytes = ourBytes.subdata( in: (i*2)..<(i*2+2) )

        print("Adding \(twoBytes.hex)")
        
        guard let value = twoBytes.maybeNetworkUint16 else { return nil } //convert bytes to number value
        
        sum += UInt32(value) //add number value to sum
    }

    print("sum: \(sum.maybeNetworkData!.hex)")

    var left = (sum >> 16) & 0xFFFF
    var right = sum & 0xFFFF

    print("left: \(left.maybeNetworkData!.hex)")
    print("right: \(right.maybeNetworkData!.hex)")

    let partialResult = left + right
    left = (partialResult >> 16) & 0xFFFF
    right = partialResult & 0xFFFF

    print("partialResult: \(partialResult.maybeNetworkData!.hex)")
    print("left: \(left.maybeNetworkData!.hex)")
    print("right: \(right.maybeNetworkData!.hex)")

    let result = UInt16(left) + UInt16(right)

    print("result: \(result.maybeNetworkData!.hex) \((~result).maybeNetworkData!.hex)")

    return ~result // one's complement
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

    // Takes an IPv4 packet
    public init(ipv4Bytes: Data, timestamp: Date, debugPrints: Bool = false)
    {
        debugPrint = debugPrints

        self.rawBytes = ipv4Bytes

        // Multiply time interval by 1,000,000 before converting to an int to retain microseconds precision
        self.timestamp = Int(timestamp.timeIntervalSince1970 * 1000000)

        if debugPrint
        {
            print("・ timestamp (in microseconds): \(self.timestamp)")
        }

        if let IPv4Packet = IPv4(data: ipv4Bytes)
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

    // Takes an Ethernet packet.
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

public enum EtherType: UInt16, Codable
{
    /*
     values less than 1536 (0x600) are size and not ethertype,
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
        self.init(rawValue: data)
    }
    
    var data: Data?
    {
        let x = self.rawValue
        return Data(maybeNetworkUint16: UInt16(x))
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
        guard let x = bits.maybeNetworkInt else { return nil }
        self.init(rawValue: x)
    }
    
    public var bits: Bits?
    {
        let x = self.rawValue
        return Bits(maybeNetworkInt: x)
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
        guard let x = data.maybeNetworkUint8 else { return nil }
        self.init(rawValue: x)
    }
    
    var data: Data?
    {
        let x = self.rawValue
        return Data(maybeNetworkUint8: x)
    }
    
}

public enum InternetProtocolsError: Error
{
    case FIXME
}
