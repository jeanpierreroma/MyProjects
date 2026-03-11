import EcliptixCertificatePinningC
import Foundation

enum CertificatePinningNativeLibrary {
    
    // MARK: Initialize
    
    @inlinable
    static func initialize() -> CertificatePinningNativeResult {
        let rawValue = Int(ecliptix_client_init())

        return CertificatePinningNativeResult(rawValue: rawValue) ?? .errorVerificationFailed
    }
    
    // MARK: Cleanup
    
    @inlinable
    static func cleanup() {
        ecliptix_client_cleanup()
    }
    
    // MARK: Verify Signature
    
    @inlinable
    static func verifySignature(
        data: Data,
        signature: Data
    ) -> CertificatePinningNativeResult {
        return data.withUnsafeBytes { dataBuffer in
            return signature.withUnsafeBytes { signatureBuffer in
                let dataPointer = dataBuffer.bindMemory(to: UInt8.self).baseAddress
                let signaturePointer = signatureBuffer.bindMemory(to: UInt8.self).baseAddress

                return verifySignature(
                    dataPointer: dataPointer,
                    dataLength: dataBuffer.count,
                    signaturePointer: signaturePointer,
                    signatureLength: signatureBuffer.count
                )
            }
        }
    }
    
    @inlinable
    static func verifySignature(
        dataPointer: UnsafePointer<UInt8>?,
        dataLength: Int,
        signaturePointer: UnsafePointer<UInt8>?,
        signatureLength: Int
    ) -> CertificatePinningNativeResult {
        let nativeResult: ecliptix_result_t = ecliptix_client_verify(
            dataPointer,
            numericCast(dataLength),
            signaturePointer,
            numericCast(signatureLength)
        )

        let rawResultValue = Int(nativeResult.rawValue)

        return CertificatePinningNativeResult(rawValue: rawResultValue) ?? .errorVerificationFailed
    }
    
    // MARK: Encrypt
    
    @inlinable
    static func encrypt(
        plaintextPointer: UnsafePointer<UInt8>?,
        plaintextLength: Int,
        ciphertextPointer: UnsafeMutablePointer<UInt8>?,
        ciphertextLengthPointer: UnsafeMutablePointer<Int>?
    ) -> CertificatePinningNativeResult {
        let nativeResult: ecliptix_result_t = ecliptix_client_encrypt(
            plaintextPointer,
            numericCast(plaintextLength),
            ciphertextPointer,
            ciphertextLengthPointer
        )

        let rawResultValue = Int(nativeResult.rawValue)

        return CertificatePinningNativeResult(rawValue: rawResultValue) ?? .errorVerificationFailed
    }
    
    @inlinable
    static func encrypt(
        plaintext: Data,
        ciphertextBuffer: UnsafeMutablePointer<UInt8>,
        ciphertextBufferCapacity: Int,
        ciphertextActualLength: inout Int
    ) -> CertificatePinningNativeResult {
        return plaintext.withUnsafeBytes { plaintextBuffer in
            let plaintextPointer = plaintextBuffer.bindMemory(to: UInt8.self).baseAddress

            ciphertextActualLength = ciphertextBufferCapacity

            return encrypt(
                plaintextPointer: plaintextPointer,
                plaintextLength: plaintextBuffer.count,
                ciphertextPointer: ciphertextBuffer,
                ciphertextLengthPointer: &ciphertextActualLength
            )
        }
    }

    // MARK: Decrypt
    
    @inlinable
    static func decrypt(
        ciphertextPointer: UnsafePointer<UInt8>?,
        ciphertextLength: Int,
        plaintextPointer: UnsafeMutablePointer<UInt8>?,
        plaintextLengthPointer: UnsafeMutablePointer<Int>?
    ) -> CertificatePinningNativeResult {
        let nativeResult: ecliptix_result_t = ecliptix_client_decrypt(
            ciphertextPointer,
            numericCast(ciphertextLength),
            plaintextPointer,
            plaintextLengthPointer
        )

        let rawResultValue = Int(nativeResult.rawValue)

        return CertificatePinningNativeResult(rawValue: rawResultValue) ?? .errorVerificationFailed
    }

    @inlinable
    static func decrypt(
        ciphertext: Data,
        plaintextBuffer: UnsafeMutablePointer<UInt8>,
        plaintextBufferCapacity: Int,
        plaintextActualLength: inout Int
    ) -> CertificatePinningNativeResult {
        return ciphertext.withUnsafeBytes { ciphertextBuffer in
            let ciphertextPointer = ciphertextBuffer.bindMemory(to: UInt8.self).baseAddress

            plaintextActualLength = plaintextBufferCapacity

            return decrypt(
                ciphertextPointer: ciphertextPointer,
                ciphertextLength: ciphertextBuffer.count,
                plaintextPointer: plaintextBuffer,
                plaintextLengthPointer: &plaintextActualLength
            )
        }
    }

    // MARK: Get Public Key
    
    @inlinable
    static func getPublicKey(
        publicKeyDerPointer: UnsafeMutablePointer<UInt8>?,
        publicKeyLengthPointer: UnsafeMutablePointer<Int>?
    ) -> CertificatePinningNativeResult {
        let nativeResult: ecliptix_result_t = ecliptix_client_get_public_key(
            publicKeyDerPointer,
            publicKeyLengthPointer
        )

        let rawResultValue = Int(nativeResult.rawValue)

        return CertificatePinningNativeResult(rawValue: rawResultValue) ?? .errorVerificationFailed
    }

    
    // MARK: Get Error Message
    
    @inlinable
    static func getErrorMessage() -> String? {
        guard let errorPointer = ecliptix_client_get_error() else {
            return nil
        }

        let charPointer = UnsafeRawPointer(errorPointer).assumingMemoryBound(to: CChar.self)

        return String(validatingCString: charPointer)
    }
}
