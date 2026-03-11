import Foundation

@_silgen_name("sodium_init")
internal func sodium_init() -> Int32



@_silgen_name("opaque_client_destroy")
internal func opaque_client_destroy(_ handle: UnsafeMutableRawPointer?)

@_silgen_name("opaque_client_state_create")
internal func opaque_client_state_create(
    _ handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32

@_silgen_name("opaque_client_state_destroy")
internal func opaque_client_state_destroy(_ handle: UnsafeMutableRawPointer?)

@_silgen_name("opaque_client_create_registration_request")
internal func opaque_client_create_registration_request(
    _ client_handle: UnsafeMutableRawPointer?,
    _ secure_key: UnsafePointer<UInt8>?,
    _ secure_key_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ request_out: UnsafeMutablePointer<UInt8>?,
    _ request_length: Int
) -> Int32

@_silgen_name("opaque_client_finalize_registration")
internal func opaque_client_finalize_registration(
    _ client_handle: UnsafeMutableRawPointer?,
    _ response: UnsafePointer<UInt8>?,
    _ response_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ record_out: UnsafeMutablePointer<UInt8>?,
    _ record_length: Int
) -> Int32

@_silgen_name("opaque_client_generate_ke1")
internal func opaque_client_generate_ke1(
    _ client_handle: UnsafeMutableRawPointer?,
    _ secure_key: UnsafePointer<UInt8>?,
    _ secure_key_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ ke1_out: UnsafeMutablePointer<UInt8>?,
    _ ke1_length: Int
) -> Int32

@_silgen_name("opaque_client_generate_ke3")
internal func opaque_client_generate_ke3(
    _ client_handle: UnsafeMutableRawPointer?,
    _ ke2: UnsafePointer<UInt8>?,
    _ ke2_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ ke3_out: UnsafeMutablePointer<UInt8>?,
    _ ke3_length: Int
) -> Int32

@_silgen_name("opaque_client_finish")
internal func opaque_client_finish(
    _ client_handle: UnsafeMutableRawPointer?,
    _ state_handle: UnsafeMutableRawPointer?,
    _ session_key_out: UnsafeMutablePointer<UInt8>?,
    _ session_key_length: Int,
    _ master_key_out: UnsafeMutablePointer<UInt8>?,
    _ master_key_length: Int
) -> Int32

@_silgen_name("opaque_client_get_version")
internal func opaque_client_get_version() -> UnsafePointer<CChar>?

@_silgen_name("opaque_get_ke1_length")
internal func opaque_get_ke1_length() -> Int

@_silgen_name("opaque_get_ke2_length")
internal func opaque_get_ke2_length() -> Int

@_silgen_name("opaque_get_ke3_length")
internal func opaque_get_ke3_length() -> Int

@_silgen_name("opaque_get_registration_record_length")
internal func opaque_get_registration_record_length() -> Int
