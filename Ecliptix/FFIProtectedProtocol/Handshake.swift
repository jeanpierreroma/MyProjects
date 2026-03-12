import Foundation
import EcliptixProtocolC
import EcliptixFailures

public final class NativeHandshakeInitiator {
    private let handleLock = NSLock()
    private var handle: OpaquePointer?
    
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
        if maxMessagesPerChain == 0 {
            throw EcliptixProtocolFailure.invalidInput("Max messages per chain must be greater than zero")
        }
        
        var config = EppSessionConfig(max_messages_per_chain: UInt32(maxMessagesPerChain))
        
        var handshakeInitiatorHandle: OpaquePointer? = nil
        var handshakeInitBuffer = EppBuffer()
        var nativeError = EppError()

        let resultCode = try identityKeys.withHandle { identityHandle in
            epp_handshake_initiator_start(
                identityHandle,
                peerPreKeyBundle,
                peerPreKeyBundle.count,
                &config,
                &handshakeInitiatorHandle,
                &handshakeInitBuffer,
                &nativeError
            )
        }
        
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
        var sessionHandle: OpaquePointer? = nil
        var nativeError = EppError()

        let (resultCode, handleToDestroy) = try handleLock.withLock { () throws -> (EppErrorCode, OpaquePointer?) in
            guard let handle else {
                throw EcliptixProtocolFailure.objectDisposed(resourceName: "NativeHandshakeInitiator")
            }

            let resultCode = epp_handshake_initiator_finish(
                handle,
                handshakeAck,
                handshakeAck.count,
                &sessionHandle,
                &nativeError
            )

            if resultCode == EPP_SUCCESS {
                self.handle = nil
                return (resultCode, handle)
            }

            return (resultCode, nil)
        }
        
        guard resultCode == EPP_SUCCESS else {
            let errorMessage = nativeError.getMessage()
            epp_error_free(&nativeError)
            throw InteropHelpers.convertError(resultCode, message: errorMessage)
        }

        if let handleToDestroy {
            epp_handshake_initiator_destroy(handleToDestroy)
        }

        return NativeProtocolSession(handle: sessionHandle)
    }
    
    private func dispose() {
        let handleToDestroy = handleLock.withLock { () -> OpaquePointer? in
            defer { handle = nil }
            return handle
        }

        if let handleToDestroy {
            epp_handshake_initiator_destroy(handleToDestroy)
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
