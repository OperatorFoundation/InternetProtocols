//
//  File.swift
//  
//
//  Created by Joshua Clark on 3/11/22.
//

import Bits
import Foundation

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
