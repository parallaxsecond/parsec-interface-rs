// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use log::{error, warn};
use num_derive::FromPrimitive;
use std::convert::TryFrom;
use std::error::Error as ErrorTrait;
use std::fmt;

/// C-like enum mapping response status options to their code.
///
/// See the [status
/// code](https://parallaxsecond.github.io/parsec-book/parsec_client/status_codes.html) page for a
/// broader description of these codes.
#[derive(Copy, Clone, Debug, PartialEq, FromPrimitive)]
#[repr(u16)]
pub enum ResponseStatus {
    /// Successful operation
    Success = 0,
    /// Requested provider ID does not match that of the backend
    WrongProviderID = 1,
    /// Requested content type is not supported by the backend
    ContentTypeNotSupported = 2,
    /// Requested accept type is not supported by the backend
    AcceptTypeNotSupported = 3,
    /// Requested version is not supported by the backend
    WireProtocolVersionNotSupported = 4,
    /// No provider registered for the requested provider ID
    ProviderNotRegistered = 5,
    /// No provider defined for requested provider ID
    ProviderDoesNotExist = 6,
    /// Failed to deserialize the body of the message
    DeserializingBodyFailed = 7,
    /// Failed to serialize the body of the message
    SerializingBodyFailed = 8,
    /// Requested operation is not defined
    OpcodeDoesNotExist = 9,
    /// Response size exceeds allowed limits
    ResponseTooLarge = 10,
    /// Authentication failed
    AuthenticationError = 11,
    /// Authenticator not supported
    AuthenticatorDoesNotExist = 12,
    /// Authenticator not supported
    AuthenticatorNotRegistered = 13,
    /// Internal error in the Key Info Manager
    KeyInfoManagerError = 14,
    /// Generic input/output error
    ConnectionError = 15,
    /// Invalid value for this data type
    InvalidEncoding = 16,
    /// Constant fields in header are invalid
    InvalidHeader = 17,
    /// The UUID vector needs to only contain 16 bytes
    WrongProviderUuid = 18,
    /// Request did not provide a required authentication
    NotAuthenticated = 19,
    /// Request length specified in the header is above defined limit
    BodySizeExceedsLimit = 20,
    /// The operation requires admin privilege
    AdminOperation = 21,
    /// An error occurred that does not correspond to any defined failure cause
    PsaErrorGenericError = 1132,
    /// The requested operation or a parameter is not supported by this implementation
    PsaErrorNotSupported = 1134,
    /// The requested action is denied by a policy
    PsaErrorNotPermitted = 1133,
    /// An output buffer is too small
    PsaErrorBufferTooSmall = 1138,
    /// Asking for an item that already exists
    PsaErrorAlreadyExists = 1139,
    /// Asking for an item that doesn't exist
    PsaErrorDoesNotExist = 1140,
    /// The requested action cannot be performed in the current state
    PsaErrorBadState = 1137,
    /// The parameters passed to the function are invalid
    PsaErrorInvalidArgument = 1135,
    /// There is not enough runtime memory
    PsaErrorInsufficientMemory = 1141,
    /// There is not enough persistent storage
    PsaErrorInsufficientStorage = 1142,
    /// There was a communication failure inside the implementation
    PsaErrorCommunicationFailure = 1145,
    /// There was a storage failure that may have led to data loss
    PsaErrorStorageFailure = 1146,
    /// Stored data has been corrupted
    PsaErrorDataCorrupt = 1152,
    /// Data read from storage is not valid for the implementation
    PsaErrorDataInvalid = 1153,
    /// A hardware failure was detected
    PsaErrorHardwareFailure = 1147,
    /// A tampering attempt was detected
    PsaErrorCorruptionDetected = 1151,
    /// There is not enough entropy to generate random data needed for the requested action
    PsaErrorInsufficientEntropy = 1148,
    /// The signature, MAC or hash is incorrect
    PsaErrorInvalidSignature = 1149,
    /// The decrypted padding is incorrect
    PsaErrorInvalidPadding = 1150,
    /// Insufficient data when attempting to read from a resource
    PsaErrorInsufficientData = 1143,
    /// The key handle is not valid
    PsaErrorInvalidHandle = 1136,
}

impl TryFrom<u16> for ResponseStatus {
    type Error = ResponseStatus;

    fn try_from(value: u16) -> Result<Self> {
        num::FromPrimitive::from_u16(value).ok_or_else(|| {
            error!(
                "Value {} does not correspond to a valid ResponseStatus.",
                value
            );
            ResponseStatus::InvalidEncoding
        })
    }
}

impl fmt::Display for ResponseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseStatus::Success => write!(f, "successful operation"),
            ResponseStatus::WrongProviderID => write!(
                f,
                "requested provider ID does not match that of the backend"
            ),
            ResponseStatus::ContentTypeNotSupported => {
                write!(f, "requested content type is not supported by the backend")
            }
            ResponseStatus::AcceptTypeNotSupported => {
                write!(f, "requested accept type is not supported by the backend")
            }
            ResponseStatus::WireProtocolVersionNotSupported => {
                write!(f, "requested version is not supported by the backend")
            }
            ResponseStatus::ProviderNotRegistered => {
                write!(f, "no provider registered for the requested provider ID")
            }
            ResponseStatus::ProviderDoesNotExist => {
                write!(f, "no provider defined for requested provider ID")
            }
            ResponseStatus::DeserializingBodyFailed => {
                write!(f, "failed to deserialize the body of the message")
            }
            ResponseStatus::SerializingBodyFailed => {
                write!(f, "failed to serialize the body of the message")
            }
            ResponseStatus::OpcodeDoesNotExist => write!(f, "requested operation is not defined"),
            ResponseStatus::ResponseTooLarge => write!(f, "response size exceeds allowed limits"),
            ResponseStatus::AuthenticationError => {
                write!(f, "authentication failed")
            }
            ResponseStatus::AuthenticatorDoesNotExist => {
                write!(f, "authenticator not supported")
            }
            ResponseStatus::AuthenticatorNotRegistered => {
                write!(f, "authenticator not supported")
            }
            ResponseStatus::KeyInfoManagerError => {
                write!(f, "internal error in the Key Info Manager")
            }
            ResponseStatus::ConnectionError => {
                write!(f, "generic input/output error")
            }
            ResponseStatus::InvalidEncoding => {
                write!(f, "invalid value for this data type")
            }
            ResponseStatus::InvalidHeader => {
                write!(f, "constant fields in header are invalid")
            }
            ResponseStatus::WrongProviderUuid => {
                write!(f, "the UUID vector needs to only contain 16 bytes")
            }
            ResponseStatus::NotAuthenticated => {
                write!(f, "request did not provide a required authentication")
            }
            ResponseStatus::BodySizeExceedsLimit => {
                write!(
                    f,
                    "request length specified in the header is above defined limit"
                )
            }
            ResponseStatus::AdminOperation => {
                write!(f, "the operation requires admin privilege")
            }
            ResponseStatus::PsaErrorGenericError => {
                write!(
                    f,
                    "an error occurred that does not correspond to any defined failure cause"
                )
            }
            ResponseStatus::PsaErrorNotPermitted => {
                write!(f, "the requested action is denied by a policy")
            }
            ResponseStatus::PsaErrorNotSupported => {
                write!(f, "the requested operation or a parameter is not supported by this implementation")
            }
            ResponseStatus::PsaErrorInvalidArgument => {
                write!(f, "the parameters passed to the function are invalid")
            }
            ResponseStatus::PsaErrorInvalidHandle => {
                write!(f, "the key handle is not valid")
            }
            ResponseStatus::PsaErrorBadState => {
                write!(
                    f,
                    "the requested action cannot be performed in the current state"
                )
            }
            ResponseStatus::PsaErrorBufferTooSmall => {
                write!(f, "an output buffer is too small")
            }
            ResponseStatus::PsaErrorAlreadyExists => {
                write!(f, "asking for an item that already exists")
            }
            ResponseStatus::PsaErrorDoesNotExist => {
                write!(f, "asking for an item that doesn't exist")
            }
            ResponseStatus::PsaErrorInsufficientMemory => {
                write!(f, "there is not enough runtime memory")
            }
            ResponseStatus::PsaErrorInsufficientStorage => {
                write!(f, "there is not enough persistent storage")
            }
            ResponseStatus::PsaErrorInsufficientData => {
                write!(
                    f,
                    "insufficient data when attempting to read from a resource"
                )
            }
            ResponseStatus::PsaErrorCommunicationFailure => {
                write!(
                    f,
                    "there was a communication failure inside the implementation"
                )
            }
            ResponseStatus::PsaErrorStorageFailure => {
                write!(
                    f,
                    "there was a storage failure that may have led to data loss"
                )
            }
            ResponseStatus::PsaErrorDataCorrupt => {
                write!(f, "stored data has been corrupted")
            }
            ResponseStatus::PsaErrorDataInvalid => {
                write!(
                    f,
                    "data read from storage is not valid for the implementation"
                )
            }
            ResponseStatus::PsaErrorHardwareFailure => {
                write!(f, "a hardware failure was detected")
            }
            ResponseStatus::PsaErrorCorruptionDetected => {
                write!(f, "a tampering attempt was detected")
            }
            ResponseStatus::PsaErrorInsufficientEntropy => {
                write!(f, "there is not enough entropy to generate random data needed for the requested action")
            }
            ResponseStatus::PsaErrorInvalidSignature => {
                write!(f, "the signature, MAC or hash is incorrect")
            }
            ResponseStatus::PsaErrorInvalidPadding => {
                write!(f, "the decrypted padding is incorrect")
            }
        }
    }
}

impl ErrorTrait for ResponseStatus {}

/// Conversion from a std::io::Error to a ResponseStatus
///
/// It allows to easily return a ResponseStatus in case of error when using functions from the
/// standard library.
impl From<std::io::Error> for ResponseStatus {
    fn from(err: std::io::Error) -> Self {
        warn!(
            "Conversion from {:?} to ResponseStatus::ConnectionError.",
            err
        );
        if err.kind() == std::io::ErrorKind::WouldBlock {
            warn!("The WouldBlock error might mean that the connection timed out. Try in increase the timeout length.");
        }
        ResponseStatus::ConnectionError
    }
}

impl From<bincode::Error> for ResponseStatus {
    fn from(err: bincode::Error) -> Self {
        warn!(
            "Conversion from {} to ResponseStatus::InvalidEncoding.",
            err
        );
        ResponseStatus::InvalidEncoding
    }
}

impl From<uuid::Error> for ResponseStatus {
    fn from(err: uuid::Error) -> Self {
        warn!(
            "Conversion from {} to ResponseStatus::InvalidEncoding.",
            err
        );
        ResponseStatus::InvalidEncoding
    }
}

impl From<std::num::TryFromIntError> for ResponseStatus {
    fn from(err: std::num::TryFromIntError) -> Self {
        warn!(
            "Conversion from {} to ResponseStatus::InvalidEncoding.",
            err
        );
        ResponseStatus::InvalidEncoding
    }
}

impl From<std::array::TryFromSliceError> for ResponseStatus {
    fn from(err: std::array::TryFromSliceError) -> Self {
        warn!(
            "Conversion from {} to ResponseStatus::InvalidEncoding.",
            err
        );
        ResponseStatus::InvalidEncoding
    }
}

impl From<std::ffi::NulError> for ResponseStatus {
    fn from(err: std::ffi::NulError) -> Self {
        warn!(
            "Conversion from {} to ResponseStatus::InvalidEncoding.",
            err
        );
        ResponseStatus::InvalidEncoding
    }
}

impl From<std::convert::Infallible> for ResponseStatus {
    fn from(_err: std::convert::Infallible) -> Self {
        unreachable!();
    }
}

use psa_crypto::types::status::Error;

impl From<Error> for ResponseStatus {
    fn from(err: Error) -> ResponseStatus {
        match err {
            Error::GenericError => ResponseStatus::PsaErrorGenericError,
            Error::NotSupported => ResponseStatus::PsaErrorNotSupported,
            Error::NotPermitted => ResponseStatus::PsaErrorNotPermitted,
            Error::BufferTooSmall => ResponseStatus::PsaErrorBufferTooSmall,
            Error::AlreadyExists => ResponseStatus::PsaErrorAlreadyExists,
            Error::DoesNotExist => ResponseStatus::PsaErrorDoesNotExist,
            Error::BadState => ResponseStatus::PsaErrorBadState,
            Error::InvalidArgument => ResponseStatus::PsaErrorInvalidArgument,
            Error::InsufficientMemory => ResponseStatus::PsaErrorInsufficientMemory,
            Error::InsufficientStorage => ResponseStatus::PsaErrorInsufficientStorage,
            Error::CommunicationFailure => ResponseStatus::PsaErrorCommunicationFailure,
            Error::StorageFailure => ResponseStatus::PsaErrorStorageFailure,
            Error::DataCorrupt => ResponseStatus::PsaErrorDataCorrupt,
            Error::DataInvalid => ResponseStatus::PsaErrorDataInvalid,
            Error::HardwareFailure => ResponseStatus::PsaErrorHardwareFailure,
            Error::CorruptionDetected => ResponseStatus::PsaErrorCorruptionDetected,
            Error::InsufficientEntropy => ResponseStatus::PsaErrorInsufficientEntropy,
            Error::InvalidSignature => ResponseStatus::PsaErrorInvalidSignature,
            Error::InvalidPadding => ResponseStatus::PsaErrorInvalidPadding,
            Error::InsufficientData => ResponseStatus::PsaErrorInsufficientData,
            Error::InvalidHandle => ResponseStatus::PsaErrorInvalidHandle,
        }
    }
}

/// A Result type with the Err variant set as a ResponseStatus
pub type Result<T> = std::result::Result<T, ResponseStatus>;
