import EcliptixProtocolC
import EcliptixFailures

public enum ShamirSecretSharing {
    private static let authKeySize = 32
    
    public static func split(
        secret: [UInt8],
        threshold: UInt8,
        shareCount: UInt8,
        authKey: [UInt8]? = nil
    ) throws -> [[UInt8]] {
        if secret.isEmpty {
            throw EcliptixProtocolFailure.invalidInput("Secret must not be empty")
        }
        
        if threshold < 2 {
            throw EcliptixProtocolFailure.invalidInput("Threshold must be at least 2")
        }
        
        if shareCount < threshold {
            throw EcliptixProtocolFailure.invalidInput("Share count must be >= threshold")
        }
        
        if let authKey, authKey.count != authKeySize {
            throw EcliptixProtocolFailure.invalidInput("Auth key must be 32 bytes")
        }
        
        let authKeyBytes = authKey ?? []
        var buffer = EppBuffer()
        var outShareLength: Int = 0
        var nativeError = EppError()
        
        let resultCode = epp_shamir_split(
            secret,
            secret.count,
            threshold,
            shareCount,
            authKeyBytes,
            authKeyBytes.count,
            &buffer,
            &outShareLength,
            &nativeError
        )
        
        guard resultCode == EPP_SUCCESS else {
            let errorMessage = nativeError.getMessage()
            epp_error_free(&nativeError)
            throw InteropHelpers.convertError(resultCode, message: errorMessage)
        }
        
        var sharesBuffer = try InteropHelpers.copyBuffer(&buffer, label: "Shares")
        defer {
            secureWipe(&sharesBuffer)
        }
        
        guard let shareLength = Int(exactly: outShareLength),
              shareLength > 0,
              sharesBuffer.count % shareLength == 0 else {
            throw EcliptixProtocolFailure.invalidInput("Invalid share buffer length")
        }
        
        let actualShareCount = sharesBuffer.count / shareLength
        guard actualShareCount == Int(shareCount) else {
            throw EcliptixProtocolFailure.invalidInput("Share count mismatch")
        }
        
        var shares: [[UInt8]] = []
        shares.reserveCapacity(actualShareCount)
        for index in 0..<actualShareCount {
            let start = index * shareLength
            let end = start + shareLength
            shares.append(Array(sharesBuffer[start..<end]))
        }
        
        return shares
    }
    
    public static func reconstruct(
        shares: [[UInt8]],
        authKey: [UInt8]? = nil
    ) throws -> [UInt8] {
        if shares.isEmpty {
            throw EcliptixProtocolFailure.invalidInput("Shares are missing")
        }
        
        if let authKey, authKey.count != authKeySize {
            throw EcliptixProtocolFailure.invalidInput("Auth key must be 32 bytes")
        }
        
        let shareLength = shares.first?.count ?? 0
        if shareLength == 0 {
            throw EcliptixProtocolFailure.invalidInput("Share length is invalid")
        }
        
        if shares.contains(where: { $0.count != shareLength }) {
            throw EcliptixProtocolFailure.invalidInput("Share length mismatch")
        }
        
        let (totalLength, overflow) = shareLength.multipliedReportingOverflow(by: shares.count)
        if overflow {
            throw EcliptixProtocolFailure.invalidInput("Share length is invalid")
        }
        
        var concatenated = [UInt8](repeating: 0, count: totalLength)
        defer {
            secureWipe(&concatenated)
        }
        
        for index in 0..<shares.count {
            let start = index * shareLength
            let end = start + shareLength
            concatenated.replaceSubrange(start..<end, with: shares[index])
        }
        
        let authKeyBytes = authKey ?? []
        var buffer = EppBuffer()
        var nativeError = EppError()
        
        let resultCode = epp_shamir_reconstruct(
            concatenated,
            concatenated.count,
            shareLength,
            shares.count,
            authKeyBytes,
            authKeyBytes.count,
            &buffer,
            &nativeError
        )
        
        if resultCode == EPP_SUCCESS {
            return try InteropHelpers.copyBuffer(&buffer, label: "Secret")
        }
        
        let errorMessage = nativeError.getMessage()
        epp_error_free(&nativeError)
        throw InteropHelpers.convertError(resultCode, message: errorMessage)
    }
    
    private static func secureWipe(_ bytes: inout [UInt8]) {
        bytes.withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            _ = epp_secure_wipe(baseAddress.assumingMemoryBound(to: UInt8.self), rawBuffer.count)
        }
    }
}
