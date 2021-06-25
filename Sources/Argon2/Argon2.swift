
import Foundation
import CArgon2

public struct Argon2 {
    
    public enum Argon2Type: UInt32 {
        /**
         * Uses data-depending memory access
         */
        case d = 0
        
        /**
         * Uses data-independent memory access
         */
        case i = 1
        
        /**
         * Uses a combination of data-depending and data-independent memory acess
         */
        case id = 2
        
        var argon2type: Argon2_type {
            return Argon2_type(rawValue: rawValue)
        }
    }
    
    public enum Version: UInt32 {
        case v10 = 0x10
        case v13 = 0x13
        
        public static let latest = Version(rawValue: ARGON2_VERSION_NUMBER.rawValue)!
    }
    
    public enum Error: LocalizedError, Equatable {
        case assertion(rawError: Int32)
        
        case lengthTooShort
        case lengthTooLong
        
        case passwordTooShort
        case passwordTooLong
        
        case saltTooShort
        case saltTooLong
        
        case iterationsTooSmall
        case iterationsTooLarge
        
        case memoryTooLittle
        case memoryTooMuch
        
        case threadsTooFew
        case threadsTooMany
        
        case lanesTooFew
        case lanesTooMany
        
        case encodingFailed
        case decodingFailed
        
        init(_ argonError: Argon2_ErrorCodes) {
            switch argonError {
            case ARGON2_OUTPUT_TOO_SHORT:
                self = .lengthTooShort
            case ARGON2_OUTPUT_TOO_LONG:
                self = .lengthTooLong
            case ARGON2_PWD_TOO_SHORT:
                self = .passwordTooShort
            case ARGON2_PWD_TOO_LONG:
                self = .passwordTooLong
            case ARGON2_SALT_TOO_SHORT:
                self = .saltTooShort
            case ARGON2_SALT_TOO_LONG:
                self = .saltTooLong
            case ARGON2_TIME_TOO_SMALL:
                self = .iterationsTooSmall
            case ARGON2_TIME_TOO_LARGE:
                self = .iterationsTooLarge
            case ARGON2_MEMORY_TOO_LITTLE:
                self = .memoryTooLittle
            case ARGON2_MEMORY_TOO_MUCH:
                self = .memoryTooMuch
            case ARGON2_LANES_TOO_FEW:
                self = .lanesTooFew
            case ARGON2_LANES_TOO_MANY:
                self = .lanesTooMany
            case ARGON2_THREADS_TOO_FEW:
                self = .threadsTooFew
            case ARGON2_THREADS_TOO_MANY:
                self = .threadsTooMany
            case ARGON2_ENCODING_FAIL:
                self = .encodingFailed
            case ARGON2_DECODING_FAIL:
                self = .decodingFailed
            default:
                self = .assertion(rawError: argonError.rawValue)
            }
        }
        
        var argon2error: Argon2_ErrorCodes {
            switch self {
            case .assertion(let rawError):
                return Argon2_ErrorCodes(rawError)
                
            case .lengthTooShort:
                return ARGON2_OUTPUT_TOO_SHORT
            case .lengthTooLong:
                return ARGON2_OUTPUT_TOO_LONG
                
            case .passwordTooShort:
                return ARGON2_PWD_TOO_SHORT
            case .passwordTooLong:
                return ARGON2_PWD_TOO_LONG
                
            case .saltTooShort:
                return ARGON2_SALT_TOO_SHORT
            case .saltTooLong:
                return ARGON2_SALT_TOO_LONG
                
            case .iterationsTooSmall:
                return ARGON2_TIME_TOO_SMALL
            case .iterationsTooLarge:
                return ARGON2_TIME_TOO_LARGE
                
            case .memoryTooLittle:
                return ARGON2_MEMORY_TOO_LITTLE
            case .memoryTooMuch:
                return ARGON2_MEMORY_TOO_MUCH
                
            case .threadsTooFew:
                return ARGON2_THREADS_TOO_FEW
            case .threadsTooMany:
                return ARGON2_THREADS_TOO_MANY
                
            case .lanesTooFew:
                return ARGON2_LANES_TOO_FEW
            case .lanesTooMany:
                return ARGON2_LANES_TOO_MANY
                
            case .encodingFailed:
                return ARGON2_ENCODING_FAIL
            case .decodingFailed:
                return ARGON2_DECODING_FAIL
            }
        }
        
        public var localizedDescription: String {
            return String(cString: argon2_error_message(argon2error.rawValue))
        }
    }
    
    
    /**
     * Hashes a password with Argon2
     * - Parameters:
     *   - password: the password to hash
     *   - salt: the salt to use for hashing
     *   - iterations: number of iterations
     *   - memory: memory to use in kibibytes
     *   - threads: number of threads and compute lanes to use
     *   - length: the desired length of the resulting hash
     *   - type: the argon2 type to use
     *   - version: the argon2 version to use
     * - Throws: `Argon2.Error` if the input parameters are invalid or hashing fails.
     * - Returns: A tuple containing the raw hash value and encoded hash for the given input parameters.
     */
    public static func hash(
        password: String,
        salt: Data,
        iterations: Int,
        memory: Int,
        threads: Int,
        length: Int = 32,
        type: Argon2Type,
        version: Version
    ) throws -> (raw: Data, encoded: String) {
        let passwordData = Data(password.utf8)
        
        return try passwordData.withUnsafeBytes{ passwordBytes in
            return try salt.withUnsafeBytes { saltBytes in
                
                let encodedLength = argon2_encodedlen(
                    UInt32(iterations),
                    UInt32(memory),
                    UInt32(threads),
                    UInt32(saltBytes.count),
                    UInt32(length),
                    type.argon2type
                )
                
                var hashData = Data(count: length)
                var encodedBytes = [Int8](repeating: 0, count: encodedLength)
                
                let result = hashData.withUnsafeMutableBytes { hashBytes in
                    argon2_hash(
                        UInt32(iterations),
                        UInt32(memory),
                        UInt32(threads),
                        passwordBytes.baseAddress,
                        passwordBytes.count,
                        saltBytes.baseAddress,
                        saltBytes.count,
                        hashBytes.baseAddress,
                        hashBytes.count,
                        &encodedBytes,
                        encodedBytes.count,
                        type.argon2type,
                        version.rawValue
                    )
                }
                
                let argonError = Argon2_ErrorCodes(rawValue: result)
                switch argonError {
                case ARGON2_OK:
                    return (raw: hashData, encoded: String(cString: encodedBytes))
                default:
                    throw Error(argonError)
                }
            }
        }
    }
    
    
    /**
     * Verifies a password based on the parameters defined in an encoded hash string
     * - Parameters:
     *   - encoded: the encoded string representing the hash and its generating parameters
     *   - password: the password data to verify
     *   - type: the argon2 type to use
     * - Throws: `Argon2.Error` if the input parameters are invalid or verification fails.
     * - Returns: `true` if the password is valid.
     */
    public static func verify(encoded: String, password: String, type: Argon2Type) throws -> Bool {
        
        let passwordData = Data(password.utf8)
        let result = passwordData.withUnsafeBytes { passwordBytes in
            argon2_verify(encoded, passwordBytes.baseAddress, passwordBytes.count, type.argon2type)
        }
        
        let argonError = Argon2_ErrorCodes(rawValue: result)
        switch argonError {
        case ARGON2_OK: return true
        case ARGON2_VERIFY_MISMATCH: return false
        default: throw Error(argonError)
        }
    }
}
