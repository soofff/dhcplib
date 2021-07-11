use std::net::Ipv4Addr;
use macaddr::{MacAddr, MacAddr6, MacAddr8};
use std::convert::{TryInto, TryFrom};
use std::fmt::Debug;
use std::ops::{Deref, Range, RangeFrom};
use crate::error::{DhcpError, DhcpResult};
use crate::option::{DhcpOptions, DhcpOption,
                    PARAMETER_REQUEST_LIST,
                    IP_ADDRESS_LEASE_TIME,
                    REQUESTED_IP_ADDRESS,
                    MESSAGE_TYPE,
                    SERVER_IDENTIFIER,
                    MESSAGE
};

#[cfg(feature = "with_serde")]
use serde::{Serialize, Deserialize, Deserializer, Serializer};
use ascii::{AsciiString, AsciiChar};
use std::collections::HashMap;

pub const DHCP_COOKIE: &[u8] = &[0x63, 0x82, 0x53, 0x63];

const MAC_V6_SIZE: u8 = 6;
const MAC_V8_SIZE: u8 = 8;

pub const MESSAGE_OPERATION_BOOT_REQUEST: u8 = 1;
pub const MESSAGE_OPERATION_BOOT_REPLY: u8 = 2;

pub const HARDWARE_ADDRESS_TYPE_ETHERNET: u8 = 1;

const OP: usize = 0;
const HARDWARE_TYPE: usize = 1;
const HOPS: usize = 3;
const XID: Range<usize> = 4..8;
const SECONDS: Range<usize> = 8..10;
const FLAGS: Range<usize> = 10..12;
const CLIENT_IP: Range<usize> = 12..16;
const YOUR_IP: Range<usize> = 16..20;
const SERVER_IP: Range<usize> = 20..24;
const GATEWAY_IP: Range<usize> = 24..28;
const CLIENT_HARDWARE_6: Range<usize> = 28..34;
const CLIENT_HARDWARE_8: Range<usize> = 28..36;
const SERVER_HOSTNAME: Range<usize> = 44..108;
const FILENAME: Range<usize> = 108..236;
const COOKIE: Range<usize> = 236..240;
const OPTIONS: RangeFrom<usize> = 240..;

fn ipv4_from_bytes(data: &[u8], error: DhcpError) -> DhcpResult<Ipv4Addr> {
    let fixed: [u8; 4] = data[0..4].try_into().map_err(|_| error)?;
    Ok(Ipv4Addr::from(fixed))
}

fn byte_to_char(byte: &u8) -> Option<AsciiChar> {
    if byte != &0 {
        AsciiChar::from_ascii(*byte).ok()
    } else {
        None
    }
}

#[allow(clippy::same_item_push)]
fn bytes_fill_zeroes(bytes: &[u8], length: u8) -> Vec<u8> {
    let mut filled = bytes.to_vec();
    for _ in 0..length - filled.len() as u8 {
        filled.push(0);
    }

    filled
}

/// Wrapper over [`MacAddr`] to support serde
///
/// `<https://github.com/svartalf/rust-macaddr/pull/3>`
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct MacAddress {
    #[cfg_attr(feature = "with_serde",
    serde(serialize_with = "MacAddress::serialize_with",
    deserialize_with = "MacAddress::deserialize_with"))]
    mac: MacAddr
}

#[cfg(feature = "with_serde")]
impl MacAddress {
    pub fn serialize_with<S>(mac: &MacAddr, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        match mac {
            MacAddr::V6(m) => m.serialize(s),
            MacAddr::V8(m) => m.serialize(s)
        }
    }

    fn deserialize_with<'de, D>(deserializer: D) -> Result<MacAddr, D::Error>
        where
            D: Deserializer<'de>,
    {
        let m: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if m.len() == 6 {
            let a: [u8; 6] = m.try_into().map_err(|_| serde::de::Error::custom("expect 6 bytes mac address"))?;
            Ok(MacAddr::from(a))
        } else {
            let a: [u8; 8] = m.try_into().map_err(|_| serde::de::Error::custom("expect 8 bytes mac address"))?;
            Ok(MacAddr::from(a))
        }
    }
}

impl From<MacAddr> for MacAddress {
    fn from(mac: MacAddr) -> Self {
        Self {
            mac
        }
    }
}

impl From<MacAddr6> for MacAddress {
    fn from(mac: MacAddr6) -> Self {
        Self {
            mac: mac.into()
        }
    }
}

impl From<MacAddr8> for MacAddress {
    fn from(mac: MacAddr8) -> Self {
        Self {
            mac: mac.into()
        }
    }
}

impl Deref for MacAddress {
    type Target = MacAddr;

    fn deref(&self) -> &Self::Target {
        &self.mac
    }
}

pub(crate) trait MacAddrSize {
    fn size(&self) -> u8;
}

impl MacAddrSize for MacAddr {
    fn size(&self) -> u8 {
        match self {
            MacAddr::V6(_) => MAC_V6_SIZE,
            MacAddr::V8(_) => MAC_V8_SIZE,
        }
    }
}



/// Hardware Address type
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub enum HardwareAddressType {
    Ethernet
}

impl TryFrom<&u8> for HardwareAddressType {
    type Error = DhcpError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        match *value {
            HARDWARE_ADDRESS_TYPE_ETHERNET => Ok(HardwareAddressType::Ethernet),
            _ => Err(DhcpError::HardwareAddressTypeParseError)
        }
    }
}

impl From<HardwareAddressType> for u8 {
    fn from(t: HardwareAddressType) -> Self {
        match t {
            HardwareAddressType::Ethernet => 1,
        }
    }
}

/// Message Operation
///
/// Describes `op` field in dhcp packet.
///
/// Client uses [`MessageOperation::BootRequest`] and Server uses [`MessageOperation::BootReply`]
#[derive(Debug)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub enum MessageOperation {
    BootRequest,
    BootReply,
}

impl From<MessageOperation> for u8 {
    fn from(o: MessageOperation) -> Self {
        match o {
            MessageOperation::BootRequest => MESSAGE_OPERATION_BOOT_REQUEST,
            MessageOperation::BootReply => MESSAGE_OPERATION_BOOT_REPLY,
        }
    }
}

impl TryFrom<&u8> for MessageOperation {
    type Error = DhcpError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        match *value {
            MESSAGE_OPERATION_BOOT_REQUEST => Ok(MessageOperation::BootRequest),
            MESSAGE_OPERATION_BOOT_REPLY => Ok(MessageOperation::BootReply),
            _ => Err(DhcpError::MessageOperationInvalid)
        }
    }
}

/// Transmission behaviour during dhcp communication.
///
/// Client uses broadcast until network configuration is done.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub enum Flags {
    Unicast,
    Broadcast,
}

impl TryFrom<&[u8]> for Flags {
    type Error = DhcpError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match *value {
            [0, 0] => Ok(Self::Unicast),
            [0, 1] => Ok(Self::Broadcast),
            _ => Err(DhcpError::InvalidFlag)
        }
    }
}

impl From<Flags> for &[u8] {
    fn from(f: Flags) -> Self {
        match f {
            Flags::Unicast => &[0, 0],
            Flags::Broadcast => &[0, 1],
        }
    }
}


/// Dhcp uses always `Dhcp` cookie.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub enum Cookie {
    Dhcp
}

impl TryFrom<&[u8]> for Cookie {
    type Error = DhcpError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value {
            DHCP_COOKIE => Ok(Self::Dhcp),
            _ => Err(DhcpError::CookieParseError)
        }
    }
}

impl From<Cookie> for &[u8] {
    fn from(c: Cookie) -> Self {
        match c {
            Cookie::Dhcp => DHCP_COOKIE
        }
    }
}
/// Represents a complete DHCP packet.
///
/// Use `try_from` to parse from UDP packet or `into` to serialize into bytes.
///
/// Construct a new packet from scratch with [`DhcpPacket::new`]
#[derive(Debug)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct DhcpPacket {
    pub(crate) operation: MessageOperation,
    pub(crate) hardware_type: HardwareAddressType,
    pub(crate) hops: u8,
    pub(crate) transaction_id: u32,
    pub(crate) seconds: u16,
    pub(crate) flags: Flags,
    pub(crate) client: Ipv4Addr,
    pub(crate) your: Ipv4Addr,
    pub(crate) server: Ipv4Addr,
    pub(crate) gateway: Ipv4Addr,
    pub(crate) client_hardware: MacAddress,
    pub(crate) server_hostname: AsciiString,
    pub(crate) filename: AsciiString,
    pub(crate) cookie: Cookie,
    pub(crate) options: DhcpOptions,
}

#[cfg_attr(feature = "cargo-clippy", allow(clippy::too_many_arguments))]
impl DhcpPacket {
    pub fn new<I, C, S, O>(
        operation: MessageOperation,
        hardware_type: HardwareAddressType,
        hops: u8,
        transaction_id: u32,
        seconds: u16,
        flags: Flags,
        client: I,
        your: I,
        server: I,
        gateway: I,
        client_hardware: C,
        server_hostname: S,
        filename: S,
        options: O,
    ) -> Self
        where
            I: Into<Ipv4Addr>,
            C: Into<MacAddress>,
            S: Into<AsciiString>,
            O: Into<DhcpOptions>, {
        Self {
            operation,
            hardware_type,
            hops,
            transaction_id,
            seconds,
            flags,
            client: client.into(),
            your: your.into(),
            server: server.into(),
            gateway: gateway.into(),
            client_hardware: client_hardware.into(),
            server_hostname: server_hostname.into(),
            filename: filename.into(),
            cookie: Cookie::Dhcp,
            options: options.into(),
        }
    }

    /* dhcp packet fields */

    pub fn operation(&self) -> &MessageOperation {
        &self.operation
    }
    pub fn hardware_type(&self) -> &HardwareAddressType {
        &self.hardware_type
    }
    pub fn hops(&self) -> &MessageOperation {
        &self.operation
    }
    pub fn transaction_id(&self) -> &MessageOperation {
        &self.operation
    }
    pub fn seconds(&self) -> &MessageOperation {
        &self.operation
    }
    pub fn flags(&self) -> &MessageOperation {
        &self.operation
    }
    pub fn client(&self) -> &Ipv4Addr {
        &self.client
    }
    pub fn your(&self) -> &Ipv4Addr {
        &self.your
    }
    pub fn server(&self) -> &Ipv4Addr {
        &self.server
    }
    pub fn gateway(&self) -> &Ipv4Addr {
        &self.gateway
    }
    pub fn client_hardware(&self) -> &MacAddr {
        &*self.client_hardware
    }
    pub fn hostname(&self) -> &str {
        self.server_hostname.as_str()
    }
    pub fn filename(&self) -> &str {
        self.filename.as_str()
    }
    pub fn cookie(&self) -> &Cookie {
        &self.cookie
    }

    pub fn option(&self, tag: u8) -> Option<&DhcpOption> {
        self.options.option(tag)
    }
    pub fn options(&self) -> &DhcpOptions {
        &self.options
    }
    pub fn options_mut(&mut self) -> &mut DhcpOptions {
        &mut self.options
    }

    /* dhcp control options */

    pub fn client_requested_ip(&self) -> Option<&DhcpOption> {
        self.option(REQUESTED_IP_ADDRESS)
    }
    pub fn client_lease_time(&self) -> Option<&DhcpOption> {
        self.option(IP_ADDRESS_LEASE_TIME)
    }
    pub fn message_type(&self) -> Option<&DhcpOption> {
        self.option(MESSAGE_TYPE)
    }
    pub fn server_identifier(&self) -> Option<&DhcpOption> {
        self.option(SERVER_IDENTIFIER)
    }
    pub fn client_parameter_request_list(&self) -> Option<&DhcpOption> {
        self.option(PARAMETER_REQUEST_LIST)
    }
    pub fn message(&self) -> Option<&DhcpOption> {
        self.option(MESSAGE)
    }

    pub fn into_bytes_with_server_ips(self, ips: Vec<Ipv4Addr>) -> HashMap<Ipv4Addr, Vec<u8>> {
        let mut bytes:Vec<u8> = self.into();
        ips.into_iter().map(|ip|{
            bytes.splice(SERVER_IP, ip.octets());
            (ip, bytes.clone())
        }).collect()
    }
}


impl From<DhcpPacket> for Vec<u8> {
    fn from(p: DhcpPacket) -> Self {
        let mut bytes = vec![p.operation.into(),
                             p.hardware_type.into(),
                             p.client_hardware.size(),
                             p.hops];

        bytes.extend_from_slice(&p.transaction_id.to_be_bytes());
        bytes.extend_from_slice(&p.seconds.to_be_bytes());
        bytes.extend_from_slice(p.flags.into());

        bytes.extend_from_slice(&p.client.octets());
        bytes.extend_from_slice(&p.your.octets());
        bytes.extend_from_slice(&p.server.octets());
        bytes.extend_from_slice(&p.gateway.octets());

        bytes.extend_from_slice(&p.client_hardware.as_bytes());

        // mac padding
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        if p.client_hardware.is_v6() {
            bytes.extend_from_slice(&[0, 0]);
        }

        bytes.extend_from_slice(bytes_fill_zeroes(p.server_hostname.as_bytes(), 64).as_slice());
        bytes.extend_from_slice(bytes_fill_zeroes(p.filename.as_bytes(), 128).as_slice());
        bytes.extend_from_slice(p.cookie.into());
        bytes.extend_from_slice(&p.options.to_bytes());
        bytes
    }
}


impl TryFrom<&[u8]> for DhcpPacket {
    type Error = DhcpError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let packet_length = value.len();
        if packet_length < OPTIONS.start {
            return Err(DhcpError::InvalidPacketLength(packet_length as u8));
        }

        Ok(DhcpPacket {
            operation: MessageOperation::try_from(&value[OP])?,
            hardware_type: HardwareAddressType::try_from(&value[HARDWARE_TYPE])?,
            hops: value[HOPS],
            transaction_id: u32::from_be_bytes(value[XID].try_into().map_err(|_| DhcpError::TransactionIdParseError)?),
            seconds: u16::from_be_bytes(value[SECONDS].try_into().map_err(|_| DhcpError::SecondsParseError)?),
            flags: Flags::try_from(&value[FLAGS])?,
            client: ipv4_from_bytes(&value[CLIENT_IP], DhcpError::ClientAddressParseError)?,
            your: ipv4_from_bytes(&value[YOUR_IP], DhcpError::YourAddressParseError)?,
            server: ipv4_from_bytes(&value[SERVER_IP], DhcpError::ServerAddressParseError)?,
            gateway: ipv4_from_bytes(&value[GATEWAY_IP], DhcpError::GatewayAddressParseError)?,
            client_hardware: match value[2] {
                6 => {
                    let bytes: [u8; 6] = value[CLIENT_HARDWARE_6].try_into().map_err(|_| DhcpError::HardwareAddressParseError)?;
                    MacAddr::from(bytes).into()
                }
                8 => {
                    let bytes: [u8; 8] = value[CLIENT_HARDWARE_8].try_into().map_err(|_| DhcpError::HardwareAddressParseError)?;
                    MacAddr::from(bytes).into()
                }
                _ => return Err(DhcpError::HardwareAddressParseError)
            },
            server_hostname: value[SERVER_HOSTNAME].iter().filter_map(byte_to_char).collect::<AsciiString>(),
            filename: value[FILENAME].iter().filter_map(byte_to_char).collect::<AsciiString>(),
            cookie: value[COOKIE].try_into()?,
            options: DhcpOptions::from_bytes(&value[OPTIONS])?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::dhcp::{DhcpPacket, HardwareAddressType, Flags, Cookie};
    use std::convert::{TryFrom, TryInto};
    use std::net::Ipv4Addr;
    use macaddr::MacAddr;
    use std::str::FromStr;

    #[test]
    fn test_without_options() {
        let from_bytes: &[u8] = include_bytes!("../client_request.bin");
        let packet = DhcpPacket::try_from(from_bytes).unwrap();

        assert_eq!(packet.hardware_type, HardwareAddressType::Ethernet);
        assert_eq!(packet.hops, 0);
        assert_eq!(packet.transaction_id, 0x0003d1d);
        assert_eq!(packet.seconds, 0);
        assert_eq!(packet.flags, Flags::Unicast);
        assert_eq!(packet.client, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(packet.your, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(packet.server, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(packet.gateway, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(packet.client_hardware, MacAddr::from_str("00:0b:82:01:fc:42").unwrap().into());
        assert_eq!(packet.server_hostname, String::new());
        assert_eq!(packet.filename, String::new());
        assert_eq!(packet.cookie, Cookie::Dhcp);
        assert_eq!(packet.options.options().len(), 5);

        let to_bytes: Vec<u8> = packet.try_into().unwrap();
        assert_eq!(to_bytes[..240], from_bytes[..240]);
    }
}
