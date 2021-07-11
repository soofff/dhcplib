use std::fmt::{Display, Formatter};
use std::error::Error;

#[cfg(feature = "with_serde")]
use serde::{Serialize, Deserialize};

/// Result with DhcpError or any type
pub type DhcpResult<T> = Result<T, DhcpError>;

/// Contains all DHCP errors
#[derive(Debug, Clone)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub enum DhcpError {
    MessageOperationInvalid,
    HardwareAddressTypeParseError,
    HardwareAddressParseError,
    TransactionIdParseError,
    SecondsParseError,
    ClientAddressParseError,
    YourAddressParseError,
    ServerAddressParseError,
    GatewayAddressParseError,
    CookieParseError,
    InvalidFlag,
    OptionParseError(u8),
    OptionInvalidValueError(u8),
    DhcpMessagePacketError,
    ConversionError(u8),
    OptionNotExist(u8),
    InvalidPacketLength(u8),
}

impl Display for DhcpError {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Error for DhcpError { fn source(&self) -> Option<&(dyn Error + 'static)> { None } }
