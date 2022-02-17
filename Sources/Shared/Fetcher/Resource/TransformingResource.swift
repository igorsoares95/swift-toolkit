//
//  TransformingResource.swift
//  r2-shared-swift
//
//  Created by Mickaël Menu on 09/08/2020.
//
//  Copyright 2020 Readium Foundation. All rights reserved.
//  Use of this source code is governed by a BSD-style license which is detailed
//  in the LICENSE file present in the project repository where this source code is maintained.
//

import Foundation

/// Transforms the bytes of `resource` on-the-fly.
///
/// **Warning**: The transformation runs on the full content of `resource`, so it's not appropriate
/// for large resources which can't be held in memory. Also, wrapping a `TransformingResource` in a
/// `CachingResource` can be a good idea to cache the result of the transformation in case multiple
/// ranges will be read.
///
/// You can either provide a `transform` closure during construction, or extend
/// `TransformingResource` and override `transform()`.
open class TransformingResource: ProxyResource {
  
  private let transformClosure: ((ResourceResult<Data>) -> ResourceResult<Data>)?
  
  public init(_ resource: Resource, transform: ((ResourceResult<Data>) -> ResourceResult<Data>)? = nil) {
    self.transformClosure = transform
    super.init(resource)
  }
  
  private lazy var data: ResourceResult<Data> = transform(resource.read())
  
  open func transform(_ data: ResourceResult<Data>) -> ResourceResult<Data> {
    return transformClosure?(data) ?? data
  }
  
  open override var length: ResourceResult<UInt64> {
    data.map { UInt64($0.count) }
  }
  
  open override func read(range: Range<UInt64>?) -> ResourceResult<Data> {
    return data.map { data in
      if let range = range?.clamped(to: 0..<UInt64(data.count)) {
        return data[range]
      } else {
        return data
      }
    }
  }
  
}

/// Convenient shortcuts to create a `TransformingResource`.
public extension Resource {
  
  func map(transform: @escaping (Data) -> Data) -> Resource {
    return TransformingResource(self, transform: { $0.map(transform) })
  }
  
  func mapAsString(encoding: String.Encoding? = nil, transform: @escaping (String) -> String) -> Resource {
    let encoding = encoding ?? link.mediaType.encoding ?? .utf8
    return TransformingResource(self) {
      return $0.map { data in
        let string = String(data: data, encoding: encoding) ?? ""
        
        if string.contains("xml version") {
          return transform(string).data(using: .utf8) ?? Data()
        }
        
        let stringDecrypted = EncryptionReadium.decrypt(data: Data(base64Encoded: string)) ?? ""
        return transform(stringDecrypted).data(using: .utf8) ?? Data()
      }
    }
  }
  
}

import CommonCrypto

struct AESReadium {
  private let key: Data
  private let iv: Data
  
  init?(key: String, iv: String) {
    guard key.count == kCCKeySizeAES128 || key.count == kCCKeySizeAES256, let keyData = key.data(using: .utf8) else {
      debugPrint("Error: Failed to set a key.")
      return nil
    }
    
    guard iv.count == kCCBlockSizeAES128, let ivData = iv.data(using: .utf8) else {
      debugPrint("Error: Failed to set an initial vector.")
      return nil
    }
    
    self.key = keyData
    self.iv  = ivData
  }
  
  func encrypt(string: String) -> Data? {
    return crypt(data: string.data(using: .utf8), option: CCOperation(kCCEncrypt))
  }
  
  func decrypt(data: Data?) -> String? {
    guard let decryptedData = crypt(data: data, option: CCOperation(kCCDecrypt)) else { return nil }
    return String(bytes: decryptedData, encoding: .utf8)
  }
  
  func crypt(data: Data?, option: CCOperation) -> Data? {
    guard let data = data else { return nil }
    
    let cryptLength = data.count + kCCBlockSizeAES128
    var cryptData   = Data(count: cryptLength)
    
    let keyLength = key.count
    let options   = CCOptions(kCCOptionPKCS7Padding)
    
    var bytesLength = Int(0)
    
    let status = cryptData.withUnsafeMutableBytes { cryptBytes in
      data.withUnsafeBytes { dataBytes in
        iv.withUnsafeBytes { ivBytes in
          key.withUnsafeBytes { keyBytes in
            CCCrypt(option,
                    CCAlgorithm(kCCAlgorithmAES),
                    options,
                    keyBytes.baseAddress,
                    keyLength,
                    ivBytes.baseAddress,
                    dataBytes.baseAddress,
                    data.count,
                    cryptBytes.baseAddress,
                    cryptLength,
                    &bytesLength)
          }
        }
      }
    }
    
    guard UInt32(status) == UInt32(kCCSuccess) else {
      debugPrint("Error: Failed to crypt data. Status \(status)")
      return nil
    }
    
    cryptData.removeSubrange(bytesLength..<cryptData.count)
    return cryptData
  }
}

public final class ReadiumConstants {
  public static let shared = ReadiumConstants()
  public var key: String = ""
  public var iv: String = ""
  
  private init() {}
}

final class EncryptionReadium {
  private static let aes256 = AESReadium(
    key: ReadiumConstants.shared.key,
    iv: ReadiumConstants.shared.iv
  )
  
  static func encrypt(text: String) -> Data? {
    return aes256?.encrypt(string: text)
  }
  
  static func decrypt(data: Data?) -> String? {
    return aes256?.decrypt(data: data)
  }
}
