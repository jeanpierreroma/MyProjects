import Foundation
import EcliptixProtocolC
import EcliptixFailures

public final class EcliptixIdentityKeysWrapper {
    
    private let handleLock = NSLock()
    private var handle: OpaquePointer?
    
    private init(handle: OpaquePointer? = nil) {
        self.handle = handle
    }
    
    deinit {
        let handleToDestroy = handleLock.withLock { () -> OpaquePointer? in
            defer { handle = nil }
            return handle
        }

        if let handleToDestroy {
            epp_identity_destroy(handleToDestroy)
        }
    }
    
    public static func create() throws -> EcliptixIdentityKeysWrapper {
        var nativeError = EppError()              // zero-init C struct
        var nativeHandle: OpaquePointer? = nil    // out handle
        
        let resultCode = epp_identity_create(&nativeHandle, &nativeError)

        guard resultCode == EPP_SUCCESS, let unwrappedHandle = nativeHandle else {
            let errorMessage = nativeError.getMessage()
            epp_error_free(&nativeError)
            throw EcliptixProtocolFailure.keyGenerationFailed(errorMessage)
        }

        return EcliptixIdentityKeysWrapper(handle: unwrappedHandle)
    }
    
    public static func create(from seed: [UInt8], accountId: String) throws -> EcliptixIdentityKeysWrapper {
        if accountId.isEmpty {
            throw EcliptixProtocolFailure.invalidInput("Account is missing")
        }
        
        var nativeError = EppError()              // zero-init C struct
        var nativeHandle: OpaquePointer? = nil    // out handle
        
        let resultCode = epp_identity_create_with_context(
            seed,
            seed.count,
            accountId,
            accountId.count,
            &nativeHandle,
            &nativeError
        )
        
        guard resultCode == EPP_SUCCESS, let unwrappedHandle = nativeHandle else {
            let errorMessage = nativeError.getMessage()
            epp_error_free(&nativeError)
            throw EcliptixProtocolFailure.keyGenerationFailed(errorMessage)
        }
        
        return EcliptixIdentityKeysWrapper(handle: unwrappedHandle)
    }

    func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        try handleLock.withLock {
            guard let handle else {
                throw EcliptixProtocolFailure.objectDisposed(resourceName: "EcliptixIdentityKeysWrapper")
            }

            return try body(handle)
        }
    }
}
