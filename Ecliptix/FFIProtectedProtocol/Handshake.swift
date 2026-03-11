import EcliptixProtocolC
import EcliptixFailures

public final class NativeHandshakeInitiator {
    public private(set) var handle: OpaquePointer?
    
    private init(handle: OpaquePointer? = nil) {
        self.handle = handle
    }
    
    deinit {
        dispose()
    }
    
    public static func start(
        identityKeys: EcliptixIdentityKeysWrapper,
        peerPreKeyBundle: [UInt8],
        maxMessagesPerChain: UInt
    ) throws -> NativeHandshakeInitiatorStart {
        if identityKeys.handle == nil {
            throw EcliptixProtocolFailure.invalidInput("Identity keys are nill")
        }
        
        if maxMessagesPerChain == 0 {
            throw EcliptixProtocolFailure.invalidInput("Max messages per chain must be greater than zero")
        }
        
        var config = EppSessionConfig(max_messages_per_chain: UInt32(maxMessagesPerChain))
        
        var handshakeInitiatorHandle: OpaquePointer? = nil
        var handshakeInitBuffer = EppBuffer()
        var nativeError = EppError()

        let resultCode = epp_handshake_initiator_start(
            identityKeys.handle,
            peerPreKeyBundle,
            peerPreKeyBundle.count,
            &config,
            &handshakeInitiatorHandle,
            &handshakeInitBuffer,
            &nativeError
        )
        
        guard resultCode == EPP_SUCCESS else {
            let errorMessage = nativeError.getMessage()
            epp_error_free(&nativeError)
            throw InteropHelpers.convertError(resultCode, message: errorMessage)
        }
        
        do {
            let message = try InteropHelpers.copyBuffer(&handshakeInitBuffer, label: "Handshake init")
            let initiator = NativeHandshakeInitiator(handle: handshakeInitiatorHandle)
            
            return NativeHandshakeInitiatorStart(initiator: initiator, handshakeInit: message)
        } catch {
            epp_handshake_initiator_destroy(handshakeInitiatorHandle)
            throw error
        }
    }
    
    public func finish(handshakeAck: [UInt8]) throws -> NativeProtocolSession {
        if handle == nil {
            throw EcliptixProtocolFailure.objectDisposed(resourceName: "NativeHandshakeInitiator")
        }
        
        var sessionHandle: OpaquePointer? = nil
        var nativeError = EppError()
        
        let resultCode = epp_handshake_initiator_finish(
            handle,
            handshakeAck,
            handshakeAck.count,
            &sessionHandle,
            &nativeError
        )
        
        guard resultCode == EPP_SUCCESS else {
            let errorMessage = nativeError.getMessage()
            epp_error_free(&nativeError)
            throw InteropHelpers.convertError(resultCode, message: errorMessage)
        }
        
        dispose()
        return NativeProtocolSession(handle: sessionHandle)
    }
    
    private func dispose() {
        if let handle {
            epp_handshake_initiator_destroy(handle)
            self.handle = nil
        }
    }
}

public final class NativeHandshakeInitiatorStart {
    public let initiator: NativeHandshakeInitiator
    public let handshakeInit: [UInt8]
    
    package init(initiator: NativeHandshakeInitiator, handshakeInit: [UInt8]) {
        self.initiator = initiator
        self.handshakeInit = handshakeInit
    }
}
