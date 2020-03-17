// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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
    Success = 0,
    WrongProviderID = 1,
    ContentTypeNotSupported = 2,
    AcceptTypeNotSupported = 3,
    WireProtocolVersionNotSupported = 4,
    ProviderNotRegistered = 5,
    ProviderDoesNotExist = 6,
    DeserializingBodyFailed = 7,
    SerializingBodyFailed = 8,
    OpcodeDoesNotExist = 9,
    ResponseTooLarge = 10,
    AuthenticationError = 11,
    AuthenticatorDoesNotExist = 12,
    AuthenticatorNotRegistered = 13,
    KeyIDManagerError = 14,
    ConnectionError = 15,
    InvalidEncoding = 16,
    InvalidHeader = 17,
    WrongProviderUuid = 18,
    NotAuthenticated = 19,
    BodySizeExceedsLimit = 20,
    PsaErrorGenericError = 1132,
    PsaErrorNotSupported = 1134,
    PsaErrorNotPermitted = 1133,
    PsaErrorBufferTooSmall = 1138,
    PsaErrorAlreadyExists = 1139,
    PsaErrorDoesNotExist = 1140,
    PsaErrorBadState = 1137,
    PsaErrorInvalidArgument = 1135,
    PsaErrorInsufficientMemory = 1141,
    PsaErrorInsufficientStorage = 1142,
    PsaErrorCommunicationFailure = 1145,
    PsaErrorStorageFailure = 1146,
    PsaErrorDataCorrupt = 1152,
    PsaErrorDataInvalid = 1153,
    PsaErrorHardwareFailure = 1147,
    PsaErrorCorruptionDetected = 1151,
    PsaErrorInsufficientEntropy = 1148,
    PsaErrorInvalidSignature = 1149,
    PsaErrorInvalidPadding = 1150,
    PsaErrorInssuficientData = 1143,
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
            ResponseStatus::KeyIDManagerError => {
                write!(f, "internal error in the Key ID Manager")
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
                write!(f, "request length specified in the header is above defined limit")
            }
            ResponseStatus::PsaErrorGenericError => {
                write!(f, "an error occurred that does not correspond to any defined failure cause")
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
                write!(f, "the requested action cannot be performed in the current state")
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
            ResponseStatus::PsaErrorInssuficientData => {
                write!(f, "insufficient data when attempting to read from a resource")
            }
            ResponseStatus::PsaErrorCommunicationFailure => {
                write!(f, "there was a communication failure inside the implementation")
            }
            ResponseStatus::PsaErrorStorageFailure => {
                write!(f, "there was a storage failure that may have led to data loss")
            }
            ResponseStatus::PsaErrorDataCorrupt => {
                write!(f, "stored data has been corrupted")
            }
            ResponseStatus::PsaErrorDataInvalid => {
                write!(f, "data read from storage is not valid for the implementation")
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
            "Conversion from {} to ResponseStatus::ConnectionError.",
            err
        );
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

impl From<std::num::TryFromIntError> for ResponseStatus {
    fn from(err: std::num::TryFromIntError) -> Self {
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

/// A Result type with the Err variant set as a ResponseStatus
pub type Result<T> = std::result::Result<T, ResponseStatus>;
