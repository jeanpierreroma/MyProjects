import EcliptixOPAQUE

public final class OpaqueClient {
    private var clientHandle: UnsafeMutableRawPointer?
    private var isDisposed = false

    public init(serverPublicKey: [UInt8]) throws {
        if serverPublicKey.count != 32 {
            throw OpaqueError(message: "Server public key must be exactly \(OpaqueConstants.publicKeyLength) bytes")
        }

        var handle: UnsafeMutableRawPointer?
        let resultCode = serverPublicKey.withUnsafeBytes { buffer in
            opaque_client_create(
                buffer.bindMemory(to: UInt8.self).baseAddress,
                serverPublicKey.count,
                &handle
            )
        }

        if resultCode != 0 || handle == nil {
            throw OpaqueError(
                resultCode: Self.mapResultCode(resultCode),
                message: "Failed to create OPAQUE client"
            )
        }

        self.clientHandle = handle
    }

    public func createRegistrationRequest(secureKey: inout [UInt8]) throws -> RegistrationResult {
        let handle = try requireHandle()
        guard !secureKey.isEmpty else {
            throw OpaqueError(message: "SecureKey cannot be null or empty")
        }

        defer { Self.clearSecureKey(&secureKey) }

        var requestData = [UInt8](repeating: 0, count: Self.registrationRequestLength)
        var stateHandle: UnsafeMutableRawPointer?
        let stateResult = opaque_client_state_create(&stateHandle)
        if stateResult != 0 || stateHandle == nil {
            throw OpaqueError(
                resultCode: Self.mapResultCode(stateResult),
                message: "Failed to create state"
            )
        }

        let secureKeyCount = secureKey.count
        let requestResult = secureKey.withUnsafeBytes { keyBuffer in
            requestData.withUnsafeMutableBytes { requestBuffer in
                opaque_client_create_registration_request(
                    handle,
                    keyBuffer.bindMemory(to: UInt8.self).baseAddress,
                    secureKeyCount,
                    stateHandle,
                    requestBuffer.bindMemory(to: UInt8.self).baseAddress,
                    requestBuffer.count
                )
            }
        }

        if requestResult == 0 {
            return RegistrationResult(request: requestData, stateHandle: stateHandle!)
        }

        opaque_client_state_destroy(stateHandle)
        throw OpaqueError(
            resultCode: Self.mapResultCode(requestResult),
            message: "Failed to create registration request"
        )
    }

    public func finalizeRegistration(
        serverResponse: [UInt8]?,
        registrationState: RegistrationResult
    ) throws -> [UInt8] {
        defer { registrationState.dispose() }
        let handle = try requireHandle()

        guard let serverResponse, serverResponse.count == Self.registrationResponseLength else {
            throw OpaqueError(
                message: "Server response must be exactly \(Self.registrationResponseLength) bytes"
            )
        }

        var recordData = [UInt8](repeating: 0, count: OpaqueConstants.registrationRecordLength)
        let resultCode = serverResponse.withUnsafeBytes { responseBuffer in
            recordData.withUnsafeMutableBytes { recordBuffer in
                opaque_client_finalize_registration(
                    handle,
                    responseBuffer.bindMemory(to: UInt8.self).baseAddress,
                    responseBuffer.count,
                    registrationState.stateHandle,
                    recordBuffer.bindMemory(to: UInt8.self).baseAddress,
                    recordBuffer.count
                )
            }
        }

        if resultCode == 0 {
            return recordData
        }

        throw OpaqueError(
            resultCode: Self.mapResultCode(resultCode),
            message: "Failed to finalize registration"
        )
    }

    public func generateKe1(secureKey: inout [UInt8]) throws -> KeyExchangeResult {
        let handle = try requireHandle()
        guard !secureKey.isEmpty else {
            throw OpaqueError(message: "SecureKey cannot be null or empty")
        }

        defer { Self.clearSecureKey(&secureKey) }

        var ke1Data = [UInt8](repeating: 0, count: Self.ke1Length)
        var stateHandle: UnsafeMutableRawPointer?
        let stateResult = opaque_client_state_create(&stateHandle)
        if stateResult != 0 || stateHandle == nil {
            throw OpaqueError(
                resultCode: Self.mapResultCode(stateResult),
                message: "Failed to create state"
            )
        }

        let secureKeyCount = secureKey.count
        let ke1Result = secureKey.withUnsafeBytes { keyBuffer in
            ke1Data.withUnsafeMutableBytes { ke1Buffer in
                opaque_client_generate_ke1(
                    handle,
                    keyBuffer.bindMemory(to: UInt8.self).baseAddress,
                    secureKeyCount,
                    stateHandle,
                    ke1Buffer.bindMemory(to: UInt8.self).baseAddress,
                    ke1Buffer.count
                )
            }
        }

        if ke1Result == 0 {
            return KeyExchangeResult(keyExchangeData: ke1Data, stateHandle: stateHandle!)
        }

        opaque_client_state_destroy(stateHandle)
        throw OpaqueError(
            resultCode: Self.mapResultCode(ke1Result),
            message: "Failed to generate KE1"
        )
    }

    public func generateKe3(
        ke2: [UInt8],
        keyExchangeState: KeyExchangeResult
    ) throws -> [UInt8] {
        let handle = try requireHandle()

        guard ke2.count == Self.ke2Length else {
            throw OpaqueError(message: "KE2 must be exactly \(Self.ke2Length) bytes")
        }

        var ke3Data = [UInt8](repeating: 0, count: Self.ke3Length)
        let ke3Result = ke2.withUnsafeBytes { ke2Buffer in
            ke3Data.withUnsafeMutableBytes { ke3Buffer in
                opaque_client_generate_ke3(
                    handle,
                    ke2Buffer.bindMemory(to: UInt8.self).baseAddress,
                    ke2Buffer.count,
                    keyExchangeState.stateHandle,
                    ke3Buffer.bindMemory(to: UInt8.self).baseAddress,
                    ke3Buffer.count
                )
            }
        }

        if ke3Result != 0 {
            throw OpaqueError(
                resultCode: Self.mapResultCode(ke3Result),
                message: "Failed to generate KE3"
            )
        }

        return ke3Data
    }

    public func deriveBaseMasterKey(
        keyExchangeState: KeyExchangeResult
    ) throws -> (sessionKey: [UInt8], masterKey: [UInt8]) {
        let handle = try requireHandle()

        var sessionKey = [UInt8](repeating: 0, count: Self.sessionKeyLength)
        var masterKey = [UInt8](repeating: 0, count: Self.masterKeyLength)

        let resultCode = sessionKey.withUnsafeMutableBytes { sessionBuffer in
            masterKey.withUnsafeMutableBytes { masterBuffer in
                opaque_client_finish(
                    handle,
                    keyExchangeState.stateHandle,
                    sessionBuffer.bindMemory(to: UInt8.self).baseAddress,
                    sessionBuffer.count,
                    masterBuffer.bindMemory(to: UInt8.self).baseAddress,
                    masterBuffer.count
                )
            }
        }

        if resultCode != 0 {
            throw OpaqueError(
                resultCode: Self.mapResultCode(resultCode),
                message: "Failed to derive session key"
            )
        }

        return (sessionKey, masterKey)
    }

    public func dispose() {
        dispose(disposing: true)
    }

    private func dispose(disposing _: Bool) {
        if isDisposed {
            return
        }
        if let handle = clientHandle {
            opaque_client_destroy(handle)
            clientHandle = nil
        }
        isDisposed = true
    }

    deinit {
        dispose(disposing: false)
    }

    private func requireHandle() throws -> UnsafeMutableRawPointer {
        if isDisposed {
            throw OpaqueError(message: "OpaqueClient has been disposed.")
        }
        guard let handle = clientHandle else {
            throw OpaqueError(message: "OpaqueClient handle is nil.")
        }
        return handle
    }

    private static func clearSecureKey(_ secureKey: inout [UInt8]) {
        secureKey.withUnsafeMutableBytes { buffer in
            buffer.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }

    private static func mapResultCode(_ code: Int32) -> OpaqueResult {
        OpaqueResult(rawValue: code) ?? .invalidInput
    }

    private static let registrationRequestLength = OpaqueConstants.registrationRequestLength
    private static let registrationResponseLength = OpaqueConstants.registrationResponseLength
    private static let ke1Length = OpaqueConstants.ke1Length
    private static let ke2Length = OpaqueConstants.ke2Length
    private static let ke3Length = OpaqueConstants.ke3Length
    private static let sessionKeyLength = OpaqueConstants.hashLength
    private static let masterKeyLength = OpaqueConstants.masterKeyLength
}
