import EcliptixProtocolC
import Clibsodium
import EcliptixFailures

package final class SodiumInterop {
    
    public static let isInitialized: Bool = {
        do {
            try initializeSodium()
            return true
        } catch {
            return false
        }
    }()

    private static func initializeSodium() throws {
        let resultCode = sodium_init()
        let libInitSuccess = ProtocolSystemConstants.Numeric.dllImportSuccess

        if resultCode < libInitSuccess {
            throw SodiumFailure.initializationFailed(SodiumFailureMessages.sodiumInitFailed.description)
        }
    }
}

extension SodiumInterop {
    // MARK: - Guarded heap allocations
    
    @inlinable
    static func sodiumMalloc(byteCount: Int) throws -> UnsafeMutableRawPointer? {
        if byteCount < 0 {
            throw SodiumFailure.invalidOperation(
                SodiumFailureMessages.negativeAllocationLength(requestedLength: byteCount).description
            )
        }

        if byteCount == 0 {
            return nil
        }

        guard isInitialized else {
            throw SodiumFailure.invalidOperation(
                SodiumFailureMessages.sodiumNotInitialized.description
            )
        }

        errno = 0
        let allocatedPointer = sodium_malloc(byteCount)

        guard let unwrappedAllocatedPointer = allocatedPointer else {
            switch errno {
            case ENOMEM:
                throw SodiumFailure.initializationFailed(
                    SodiumFailureMessages.allocationFailed(byteCount: byteCount).description
                )
            default:
                throw SodiumFailure.initializationFailed(
                    SodiumFailureMessages.unexpectedAllocationError(byteCount: byteCount).description
                )
            }
        }

        return unwrappedAllocatedPointer
    }
    
    @inlinable
    static func sodiumFree(pointer: UnsafeMutableRawPointer?) {
        guard let pointer else { return }
        sodium_free(pointer)
    }
    
    // MARK: - Locking memory
    
    @inlinable
    static func sodiumMlock(pointer: UnsafeMutableRawPointer, byteCount: Int) throws {
        if byteCount < 0 {
            throw SodiumFailure.invalidOperation(
                SodiumFailureMessages.negativeAllocationLength(requestedLength: byteCount).description
            )
        }

        if byteCount == 0 {
            return
        }

        guard isInitialized else {
            throw SodiumFailure.invalidOperation(
                SodiumFailureMessages.sodiumNotInitialized.description
            )
        }

        errno = 0
        let result = sodium_mlock(pointer, byteCount)
        guard result == 0 else {
            throw makeSodiumErrnoFailure(
                functionName: "sodium_mlock",
                byteCount: byteCount,
                errnoValue: errno
            )
        }
    }

    @inlinable
    static func sodiumMunlock(pointer: UnsafeMutableRawPointer, byteCount: Int) throws {
        if byteCount < 0 {
            throw SodiumFailure.invalidOperation(
                SodiumFailureMessages.negativeAllocationLength(requestedLength: byteCount).description
            )
        }
        
        if byteCount == 0 {
            return
        }
        
        guard isInitialized else {
            throw SodiumFailure.invalidOperation(
                SodiumFailureMessages.sodiumNotInitialized.description
            )
        }
        
        errno = 0
        let result = sodium_munlock(pointer, byteCount)
        guard result == 0 else {
            throw makeSodiumErrnoFailure(
                functionName: "sodium_munlock",
                byteCount: byteCount,
                errnoValue: errno
            )
        }
    }
    
    @inlinable
    static func sodiumLockMemoryIfPossible(pointer: UnsafeMutableRawPointer?, byteCount: Int) -> Bool {
        guard let pointer, byteCount > 0 else { return false }
        do {
            try sodiumMlock(pointer: pointer, byteCount: byteCount)
            return true
        } catch {
            return false
        }
    }

    @inlinable
    static func sodiumUnlockMemoryIfPossible(pointer: UnsafeMutableRawPointer?, byteCount: Int) -> Bool {
        guard let pointer, byteCount > 0 else { return false }
        do {
            try sodiumMunlock(pointer: pointer, byteCount: byteCount)
            return true
        } catch {
            return false
        }
    }
    
    // MARK: - Secure wipe
    
    @inlinable
    static func sodiumMemzero(pointer: UnsafeMutableRawPointer, byteCount: Int) throws {
        if byteCount < 0 {
            throw SodiumFailure.invalidOperation(
                SodiumFailureMessages.negativeAllocationLength(requestedLength: byteCount).description
            )
        }

        if byteCount == 0 {
            return
        }

        guard isInitialized else {
            throw SodiumFailure.invalidOperation(
                SodiumFailureMessages.sodiumNotInitialized.description
            )
        }

        sodium_memzero(pointer, byteCount)
    }
        
    // MARK: - Private helpers

    private static func makeSodiumErrnoFailure(functionName: String, byteCount: Int, errnoValue: Int32) -> SodiumFailure {
        let errnoMessage = String(cString: strerror(errnoValue))

        switch errnoValue {
        case ENOMEM:
            return SodiumFailure.invalidOperation(
                "\(functionName) failed (ENOMEM) for \(byteCount) bytes: \(errnoMessage)"
            )
        case EPERM:
            return SodiumFailure.invalidOperation(
                "\(functionName) failed (EPERM) for \(byteCount) bytes: \(errnoMessage)"
            )
        case EINVAL:
            return SodiumFailure.invalidOperation(
                "\(functionName) failed (EINVAL) for \(byteCount) bytes: \(errnoMessage)"
            )
        default:
            return SodiumFailure.invalidOperation(
                "\(functionName) failed (errno=\(errnoValue)) for \(byteCount) bytes: \(errnoMessage)"
            )
        }
    }
}
