import Foundation
import EcliptixProtocolC
import EcliptixFailures
import EcliptixProtobufs

public final class NativeProtocolSession {
    private let handleLock = NSLock()
    private var handle: OpaquePointer?
    
    package init(handle: OpaquePointer? = nil) {
        self.handle = handle
    }

    deinit {
        dispose()
    }
    
    public func importState(stateBytes: [UInt8]) throws -> NativeProtocolSession {
        var importStateHandle: OpaquePointer? = nil
        var nativeError = EppError()
        
        let resultCode: EppErrorCode = stateBytes.withUnsafeBytes { rawBuffer in
            let statePointer = rawBuffer.bindMemory(to: UInt8.self).baseAddress

            return epp_session_deserialize(
                statePointer,
                stateBytes.count,
                &importStateHandle,
                &nativeError
            )
        }
        
        guard resultCode == EPP_SUCCESS else {
            let errorMessage = nativeError.getMessage()
            epp_error_free(&nativeError)
            throw InteropHelpers.convertError(resultCode, message: errorMessage)
        }
        
        return NativeProtocolSession(handle: importStateHandle)
    }
    
    public func exportState() throws -> [UInt8] {
        try withHandle { handle in
            var buffer = EppBuffer()
            var nativeError = EppError()

            let resultCode = epp_session_serialize(
                handle,
                &buffer,
                &nativeError
            )

            guard resultCode == EPP_SUCCESS else {
                let errorMessage = nativeError.getMessage()
                epp_error_free(&nativeError)
                throw InteropHelpers.convertError(resultCode, message: errorMessage)
            }

            return try InteropHelpers.copyBuffer(&buffer, label: "Session state")
        }
    }
    
    public func encrypt(
        plaintext: [UInt8],
        envelopeType: ProtocolEnvelopeType,
        envelopeId: UInt,
        correlationId: String? = nil
    ) throws -> [UInt8] {
        try withHandle { handle in
            var correlationIdUtf8Bytes: [UInt8]? = nil
            if let correlationId, !correlationId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                correlationIdUtf8Bytes = Array(correlationId.utf8)
            }

            var encryptedEnvelopeBuffer = EppBuffer()
            var nativeError = EppError()

            let resultCode: EppErrorCode = plaintext.withUnsafeBytes { plaintextRawBuffer in
                let plaintextPointer = plaintextRawBuffer.bindMemory(to: UInt8.self).baseAddress

                if let correlationIdUtf8Bytes {
                    return correlationIdUtf8Bytes.withUnsafeBytes { correlationRawBuffer in
                        let correlationPointer = correlationRawBuffer.bindMemory(to: UInt8.self).baseAddress

                        return epp_session_encrypt(
                            handle,
                            plaintextPointer,
                            plaintext.count,
                            NativeProtocolSession.mapEnvelopeType(envelopeType),
                            UInt32(envelopeId),
                            correlationPointer,
                            correlationIdUtf8Bytes.count,
                            &encryptedEnvelopeBuffer,
                            &nativeError
                        )
                    }
                } else {
                    return epp_session_encrypt(
                        handle,
                        plaintextPointer,
                        plaintext.count,
                        NativeProtocolSession.mapEnvelopeType(envelopeType),
                        UInt32(envelopeId),
                        nil,
                        0,
                        &encryptedEnvelopeBuffer,
                        &nativeError
                    )
                }
            }

            guard resultCode == EPP_SUCCESS else {
                let errorMessage = nativeError.getMessage()
                epp_error_free(&nativeError)
                throw InteropHelpers.convertError(resultCode, message: errorMessage)
            }

            return try InteropHelpers.copyBuffer(&encryptedEnvelopeBuffer, label: "Encrypted envelope")
        }
    }
    
    public func decrypt(encryptedEnvelope: [UInt8]) throws -> ProtocolDecryptResult {
        try withHandle { handle in
            var plaintextBuffer = EppBuffer()
            var metadataBuffer = EppBuffer()
            var nativeError = EppError()

            let resultCode = epp_session_decrypt(
                handle,
                encryptedEnvelope,
                encryptedEnvelope.count,
                &plaintextBuffer,
                &metadataBuffer,
                &nativeError
            )

            guard resultCode == EPP_SUCCESS else {
                let errorMessage = nativeError.getMessage()
                epp_error_free(&nativeError)
                throw InteropHelpers.convertError(resultCode, message: errorMessage)
            }

            do {
                let plaintext = try InteropHelpers.copyBuffer(&plaintextBuffer, label: "Plaintext")
                let metadata = try InteropHelpers.copyBuffer(&metadataBuffer, label: "Metadata")
                return ProtocolDecryptResult(plaintext: plaintext, metadata: metadata)
            } catch {
                epp_buffer_release(&metadataBuffer)
                throw error
            }
        }
    }
    
    public static func validateEnvelope(_ encryptedEnvelope: [UInt8]) throws {
        var nativeError = EppError()
        
        let resultCode = epp_envelope_validate(
            encryptedEnvelope,
            encryptedEnvelope.count,
            &nativeError
        )
        
        guard resultCode == EPP_SUCCESS else {
            let errorMessage = nativeError.getMessage()
            epp_error_free(&nativeError)
            throw InteropHelpers.convertError(resultCode, message: errorMessage)
        }
        
        return
    }
    
    private static func mapEnvelopeType(_ envelopeType: ProtocolEnvelopeType) -> EppEnvelopeType {
        switch envelopeType {
            
        case .request:
            return EPP_ENVELOPE_REQUEST
        case .response:
            return EPP_ENVELOPE_RESPONSE
        case .notification:
            return EPP_ENVELOPE_NOTIFICATION
        case .heartbeat:
            return EPP_ENVELOPE_HEARTBEAT
        case .errorResponse:
            return EPP_ENVELOPE_ERROR_RESPONSE

        default:
            return EPP_ENVELOPE_REQUEST
        }
    }

    private func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        try handleLock.withLock {
            guard let handle else {
                throw EcliptixProtocolFailure.objectDisposed(resourceName: "NativeProtocolSession")
            }

            return try body(handle)
        }
    }

    private func dispose() {
        let handleToDestroy = handleLock.withLock { () -> OpaquePointer? in
            defer { handle = nil }
            return handle
        }

        if let handleToDestroy {
            epp_session_destroy(handleToDestroy)
        }
    }
}

public final class ProtocolDecryptResult {
    public let plaintext: [UInt8]
    public let metadata: [UInt8]
    
    package init(plaintext: [UInt8], metadata: [UInt8]) {
        self.plaintext = plaintext
        self.metadata = metadata
    }
}
