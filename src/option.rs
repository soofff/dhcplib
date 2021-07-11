use std::net::Ipv4Addr;
use ascii::AsciiString;
use crate::error::{DhcpResult, DhcpError};
use crate::convert::{TryToOption, ToOptionBytes, TryIntoOptionMinBytes};


#[cfg(feature = "with_serde")]
use serde::{Serialize, Deserialize};

#[cfg(feature = "with_serde")]
use serde::{Serializer, Deserializer};
use std::collections::HashMap;

const OPTIONS_SIZE: usize = 256;

// RFC 2132
pub const PAD: u8 = 0;
pub const SUBNET_MASK: u8 = 1;
pub const TIME_OFFSET: u8 = 2;
pub const ROUTER: u8 = 3;
pub const TIME_SERVER: u8 = 4;
pub const NAME_SERVER: u8 = 5;
pub const DOMAIN_NAME_SERVER: u8 = 6;
pub const LOG_SERVER: u8 = 7;
pub const COOKIE_SERVER: u8 = 8;
pub const LPR_SERVER: u8 = 9;
pub const IMPRESS_SERVER: u8 = 10;
pub const RESOURCE_LOCATION_SERVER: u8 = 11;
pub const HOST_NAME: u8 = 12;
pub const BOOT_FILE_SIZE: u8 = 13;
pub const MERIT_DUMP_FILE: u8 = 14;
pub const DOMAIN_NAME: u8 = 15;
pub const SWAP_SERVER: u8 = 16;
pub const ROOT_PATH: u8 = 17;
pub const EXTENSION_PATH: u8 = 18;
pub const IP_FORWARDING: u8 = 19;
pub const NON_LOCAL_SOURCE_ROUTING: u8 = 20;
pub const POLICY_FILTER: u8 = 21;
pub const MAXIMUM_DATAGRAM_REASSEMBLY_SIZE: u8 = 22;
pub const DEFAULT_IP_TTL: u8 = 23;
pub const PATH_MTU_AGING_TIMEOUT: u8 = 24;
pub const PATH_MTU_PLATEAU_TABLE: u8 = 25;
pub const INTERFACE_MTU: u8 = 26;
pub const ALL_SUBNETS_LOCAL: u8 = 27;
pub const BROADCAST_ADDRESS: u8 = 28;
pub const PERFORM_MASK_DISCOVERY: u8 = 29;
pub const MASK_SUPPLIER: u8 = 30;
pub const PERFORM_ROUTER_DISCOVERY: u8 = 31;
pub const ROUTER_SOLICITATION_ADDRESS: u8 = 32;
pub const STATIC_ROUTE: u8 = 33;
pub const TRAILER_ENCAPSULATION: u8 = 34;
pub const ARP_CACHE_TIMEOUT: u8 = 35;
pub const ETHERNET_ENCAPSULATION: u8 = 36;
pub const TCP_DEFAULT_TTL: u8 = 37;
pub const TCP_KEEPALIVE_INTERVAL: u8 = 38;
pub const TCP_KEEPALIVE_GARGABE: u8 = 39;
pub const NETWORK_INFORMATION_SERVICE_DOMAIN: u8 = 40;
pub const NETWORK_INFORMATION_SERVERS: u8 = 41;
pub const NETWORK_TIME_PROTOCOL_SERVERS: u8 = 42;
pub const VENDOR_SPECIFIC: u8 = 43;
pub const NETBIOS_OVER_TCP_IP_NAME_SERVER: u8 = 44;
pub const NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER: u8 = 45;
pub const NETBIOS_OVER_TCP_IP_NODE_TYPE: u8 = 46;
pub const NETBIOS_OVER_TCP_IP_SCOPE: u8 = 47;
pub const X_WINDOW_SYSTEM_FONT_SERVER: u8 = 48;
pub const X_WINDOW_SYSTEM_DISPLAY_MANAGER: u8 = 49;
pub const REQUESTED_IP_ADDRESS: u8 = 50;
pub const IP_ADDRESS_LEASE_TIME: u8 = 51;
pub const OPTION_OVERLOAD: u8 = 52;
pub const MESSAGE_TYPE: u8 = 53;
pub const SERVER_IDENTIFIER: u8 = 54;
pub const PARAMETER_REQUEST_LIST: u8 = 55;
pub const MESSAGE: u8 = 56;
pub const MAXIMUM_DHCP_MESSAGE_SIZE: u8 = 57;
pub const RENEWAL_TIME_VALUE: u8 = 58;
pub const REBINDING_TIME_VALUE: u8 = 59;
pub const VENDOR_CLASS_IDENTIFIER: u8 = 60;
pub const CLIENT_IDENTIFIER: u8 = 61;
pub const NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN: u8 = 64;
pub const NETWORK_INFORMATION_SERVICE_PLUS_SERVERS: u8 = 65;
pub const TFTP_SERVER_NAME: u8 = 66;
pub const BOOT_FILE_NAME: u8 = 67;
pub const MOBILE_IP_HOME_AGENT: u8 = 68;
pub const SMTP_SERVER: u8 = 69;
pub const POP3_SERVER: u8 = 70;
pub const NNTP_SERVER: u8 = 71;
pub const WWW_SERVER: u8 = 72;
pub const FINGER_SERVER: u8 = 73;
pub const IRC_SERVER: u8 = 74;
pub const STREET_TALK_SERVER: u8 = 75;
pub const STREET_TALK_DIRECTORY_ASSISTANCE: u8 = 76;
pub const END: u8 = 255;

// rfc 3046
pub const RELAY_AGENT_INFORMATION: u8 = 82;

// preserve order
type DhcpOptionsVec = Vec<Option<DhcpOption>>;
type Ipv4AddrVec = Vec<Ipv4Addr>;

/// Static route
#[derive(Debug, Clone, PartialOrd, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct StaticRoute {
    pub destination: Ipv4Addr,
    pub router: Ipv4Addr,
}

/// Ipv4 with mask
#[derive(Debug, Clone, PartialOrd, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct Ipv4WithMask {
    pub ipv4addr: Ipv4Addr,
    pub mask: Ipv4Addr,
}

/// Relay Agent Information
#[derive(Debug, Clone, PartialOrd, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub enum RelayAgentInformationSubOption {
    AgentCircuit(Vec<u8>),
    AgentRemote(Vec<u8>),
    Unknown(Vec<u8>),
}

/// NetBios Node Type
#[derive(Debug, Clone, PartialOrd, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub enum NetBiosNodeType {
    B,
    P,
    M,
    H,
}

/// DHCP Overload Option
#[derive(Debug, Clone, PartialOrd, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub enum Overload {
    Sname,
    File,
    Both,
}

/// DHCP message type
///
/// Required in all DHCP packets
#[derive(Debug, Clone, PartialOrd, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

/// Client identifier
#[derive(Debug, Clone, PartialOrd, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct ClientIdentifier {
    pub(crate) typ: u8,
    pub(crate) data: Vec<u8>,
}

impl ClientIdentifier {
    pub fn new(typ: u8, data: Vec<u8>) -> Self {
        Self {
            typ,
            data,
        }
    }
}

/// Contains all DHCP Options
///
/// Preserves option
///
/// Use `From<Vec<DhcpOption>>`, [`DhcpOptions::new_with_options`] or [`DhcpOptions::from_bytes`] for creation.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct DhcpOptions {
    #[cfg_attr(feature = "with_serde", serde(serialize_with = "DhcpOptions::serialize_options", deserialize_with = "DhcpOptions::deserialize_options"))]
    options: DhcpOptionsVec,

}

impl DhcpOptions {
    pub fn new() -> Self {
        Self {
            options: Self::new_with_options(vec![])
        }
    }

    /// Creates a new collection of [`DhcpOption`].
    pub fn new_with_options(init_options: Vec<DhcpOption>) -> DhcpOptionsVec {
        let mut options: DhcpOptionsVec = Vec::with_capacity(OPTIONS_SIZE);

        let mut option_map: HashMap<u8, DhcpOption> = init_options.into_iter()
            .map(|o| (o.tag(), o))
            .collect();

        for t in 0..OPTIONS_SIZE {
            options.push(option_map.remove(&(t as u8)));
        }
        options
    }

    #[cfg(feature = "with_serde")]
    fn serialize_options<S>(data: &[Option<DhcpOption>], s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        // fixed vec is only used for easier access
        let none_removed: Vec<&DhcpOption> = data.iter().filter_map(Option::as_ref).collect();
        none_removed.serialize(s)
    }

    #[cfg(feature = "with_serde")]
    fn deserialize_options<'de, D>(deserializer: D) -> Result<Vec<Option<DhcpOption>>, D::Error>
        where
            D: Deserializer<'de>,
    {
        // prepare empty fixed vector
        let mut option_fixed = Self::new_with_options(vec![]);

        // deserialize options
        let options: Vec<DhcpOption> = Deserialize::deserialize(deserializer)?;

        // insert options using tag == index
        for option in options {
            let tag = option.tag() as usize;
            option_fixed[tag] = Some(option);
        }

        Ok(option_fixed)
    }

    /// Generates bytes from all defined [`DhcpOption`]
    /// Mostly used in conjunction with [`DhcpPacket`](crate::DhcpPacket)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.options.iter().filter_map(|o| {
            o.as_ref().map(|s| s.to_bytes())
        }).flatten().collect()
    }

    /// Generate [`DhcpOptions`] by parsing the given byte slice
    /// Mostly used in conjunction with [`DhcpPacket`](crate::DhcpPacket)
    pub fn from_bytes(mut bytes: &[u8]) -> DhcpResult<DhcpOptions> {
        let mut options = Self::new_with_options(vec![]);

        loop {
            let tag = bytes[0];
            if tag == PAD {
                bytes = &bytes[1..];
            } else if tag == END {
                options[END as usize] = Some(DhcpOption::End);
                return Ok(Self {
                    options,
                });
            } else {
                let data_length = bytes[1] as usize;
                let data_start = 2; // 1 tag + 1 length
                let data_end = data_length + data_start; // take [length] bytes
                let data = &bytes[data_start..data_end];
                bytes = &bytes[data_end..]; // leftover bytes
                options[tag as usize] = Some(DhcpOption::from_bytes(tag, data_length, data)?);
            }
        }
    }

    pub fn parameter_request_list(&self) -> Option<&[u8]> {
        if let Some(DhcpOption::ParameterRequestList(data)) = &self.options[CLIENT_IDENTIFIER as usize] {
            Some(data.as_slice())
        } else {
            None
        }
    }

    pub fn message_type(&self) -> Option<&DhcpOption> {
        self.option(MESSAGE_TYPE)
    }

    pub fn option(&self, tag: u8) -> Option<&DhcpOption> {
        self.options[tag as usize].as_ref()
    }

    pub fn option_mut(&mut self, tag: u8) -> Option<&mut DhcpOption> {
        self.options[tag as usize].as_mut()
    }

    /// A reference to all defined [`DhcpOption`]
    pub fn options(&self) -> Vec<&DhcpOption> {
        self.options.iter().filter_map(Option::as_ref).collect()
    }

    /// A list of all [`DhcpOption`] as mutable reference
    pub fn options_mut(&mut self) -> Vec<&mut DhcpOption> {
        self.options.iter_mut().filter_map(Option::as_mut).collect()
    }

    /// Insert or update a single [`DhcpOption`]
    pub fn upsert(&mut self, option: DhcpOption) {
        let tag = option.tag() as usize;
        self.options[tag] = Some(option);
    }

    /// Insert or update a single [`DhcpOption`] wrapped as [`Option`]
    pub fn upsert_option(&mut self, option: Option<DhcpOption>) {
        if let Some(o) = option {
            let tag = o.tag() as usize;
            self.options[tag] = Some(o);
        }
    }

    /// Inserts all defined DhcpOptions to the existing collection
    pub fn merge(&mut self, options: Self) {
        for o in options.into_iter() {
            if let Some(option) = &o {
                let tag = option.tag() as usize;
                self.options[tag] = o
            }
        }
    }

    /// Remove a single [`DhcpOption`]
    pub fn remove(&mut self, tag: u8) {
        self.options[tag as usize] = None;
    }

    /// Iterator over all [`DhcpOption`]
    pub fn iter(&mut self) -> impl Iterator<Item=&Option<DhcpOption>> {
        self.options.iter()
    }

    /// Mutable iteration over all [`DhcpOption`]
    pub fn iter_mut(&mut self) -> impl Iterator<Item=&mut Option<DhcpOption>> {
        self.options.iter_mut()
    }

    /// Try to extract option value
    pub fn try_ascii_option(&self, tag: u8) -> DhcpResult<AsciiString> {
        self.option(tag).ok_or_else(|| DhcpError::OptionNotExist(tag))?.try_to_ascii()
    }

    /// Try to extract option value
    pub fn try_ipv4_option(&self, tag: u8) -> DhcpResult<Ipv4Addr> {
        self.option(tag).ok_or_else(|| DhcpError::OptionNotExist(tag))?.try_to_ipv4()
    }

    /// Try to extract option value
    pub fn try_ipv4vec_option(&self, tag: u8) -> DhcpResult<Ipv4AddrVec> {
        self.option(tag).ok_or_else(|| DhcpError::OptionNotExist(tag))?.try_to_ipv4vec()
    }

    /// Try to extract option value
    pub fn try_u8_option(&self, tag: u8) -> DhcpResult<u8> {
        self.option(tag).ok_or_else(|| DhcpError::OptionNotExist(tag))?.try_to_u8()
    }

    /// Try to extract option value
    pub fn try_u16_option(&self, tag: u8) -> DhcpResult<u16> {
        self.option(tag).ok_or_else(|| DhcpError::OptionNotExist(tag))?.try_to_u16()
    }

    /// Try to extract option value
    pub fn try_u32_option(&self, tag: u8) -> DhcpResult<u32> {
        self.option(tag).ok_or_else(|| DhcpError::OptionNotExist(tag))?.try_to_u32()
    }

    /// Try to extract option value
    pub fn try_vec_u8_option(&self, tag: u8) -> DhcpResult<Vec<u8>> {
        self.option(tag).ok_or_else(|| DhcpError::OptionNotExist(tag))?.try_to_vec_u8()
    }

    /// Try to extract option value
    pub fn try_to_i32(&self, tag: u8) -> DhcpResult<i32> {
        self.option(tag).ok_or_else(|| DhcpError::OptionNotExist(tag))?.try_to_i32()
    }

    /// Try to extract option value
    pub fn try_to_bool(&self, tag: u8) -> DhcpResult<bool> {
        self.option(tag).ok_or_else(|| DhcpError::OptionNotExist(tag))?.try_to_bool()
    }
}

impl IntoIterator for DhcpOptions {
    type Item = Option<DhcpOption>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.options.into_iter()
    }
}

impl From<Vec<DhcpOption>> for DhcpOptions {
    fn from(o: Vec<DhcpOption>) -> Self {
        Self {
            options: Self::new_with_options(o)
        }
    }
}

impl From<Vec<Option<DhcpOption>>> for DhcpOptions {
    fn from(o: Vec<Option<DhcpOption>>) -> Self {
        Self {
            options: Self::new_with_options(o.into_iter()
                .filter_map(|s| s)
                .collect()
            )
        }
    }
}

impl From<Option<DhcpOptions>> for DhcpOptions {
    fn from(o: Option<DhcpOptions>) -> Self {
        o.unwrap_or_else(|| DhcpOptions::new())
    }
}

/// Represents a single Dhcp Option
///
/// Use [`DhcpOption::from_bytes`] or [`DhcpOption::to_bytes`] to create/convert.
#[derive(Debug, Clone, PartialOrd, PartialEq)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub enum DhcpOption {
    Pad,
    SubnetMask(Ipv4Addr),
    TimeOffset(i32),
    Router(Ipv4AddrVec),
    TimeServer(Ipv4AddrVec),
    NameServer(Ipv4AddrVec),
    DomainNameServer(Ipv4AddrVec),
    LogServer(Ipv4AddrVec),
    CookieServer(Ipv4AddrVec),
    LPRServer(Ipv4AddrVec),
    ImpressServer(Ipv4AddrVec),
    ResourceLocationServer(Ipv4AddrVec),
    HostName(AsciiString),
    BootFileSize(u16),
    MeritDumpFile(AsciiString),
    DomainName(AsciiString),
    SwapServer(Ipv4Addr),
    RootPath(AsciiString),
    ExtensionPath(AsciiString),
    IpForwarding(bool),
    NonLocalSourceRouting(bool),
    PolicyFilter(Vec<Ipv4WithMask>),
    MaximumDatagramReassemblySize(u16),
    DefaultIpTTL(u8),
    PathMtuAgingTimeout(u32),
    PathMtuPlateauTable(Vec<u16>),
    InterfaceMtu(u16),
    AllSubnetsLocal(bool),
    BroadcastAddress(Ipv4Addr),
    MaskSupplier(bool),
    PerformRouterDiscovery(bool),
    RouterSolicitationAddress(Ipv4Addr),
    StaticRoute(Vec<StaticRoute>),
    TrailerEncapsulation(bool),
    ArpCacheTimeout(u32),
    EthernetEncapsulation(bool),
    TcpDefaultTTL(u8),
    TcpKeepAliveInterval(u32),
    TcpKeepAliveGarbage(bool),
    NetworkInformationServiceDomain(AsciiString),
    NetworkInformationServers(Ipv4AddrVec),
    NetworkTimeProtocolServers(Ipv4AddrVec),
    VendorSpecific(Vec<u8>),
    NetBiosOverTcpIpNameServer(Ipv4AddrVec),
    NetBiosOverTcpIpDatagramDistributionServer(Ipv4AddrVec),
    NetBiosOverTcpIpNodeType(NetBiosNodeType),
    NetBiosOverTcpIpScope(AsciiString),
    XWindowSystemFontServer(Ipv4AddrVec),
    XWindowSystemDisplayManager(Ipv4AddrVec),
    RequestedIpAddress(Ipv4Addr),
    IpAddressLeaseTime(u32),
    OptionOverload(Overload),
    MessageType(MessageType),
    ServerIdentifier(Ipv4Addr),
    ParameterRequestList(Vec<u8>),
    Message(AsciiString),
    MaximumDhcpMessageSize(u16),
    RenewalTimeValue(u32),
    RebindingTimeValue(u32),
    VendorClassIdentifier(Vec<u8>),
    ClientIdentifier(ClientIdentifier),
    NetworkInformationServicePlusDomain(AsciiString),
    NetworkInformationServicePlusServer(Ipv4AddrVec),
    TftpServer(AsciiString),
    BootFileName(AsciiString),
    MobileIpHomeAgent(Ipv4AddrVec),
    SmtpServer(Ipv4AddrVec),
    Pop3Server(Ipv4AddrVec),
    NntpServer(Ipv4AddrVec),
    WwwServer(Ipv4AddrVec),
    FingerServer(Ipv4AddrVec),
    IrcServer(Ipv4AddrVec),
    StreetTalkServer(Ipv4AddrVec),
    StreetTalkDirectoryAssistanceServer(Ipv4AddrVec),
    End,
    RelayAgentInformation(Vec<RelayAgentInformationSubOption>),
    Unknown(u8, Vec<u8>),
}


impl DhcpOption {
    /// Try to get value if type is known without match
    pub fn try_to_bool(&self) -> DhcpResult<bool> {
        Ok(match self {
            DhcpOption::IpForwarding(v) => v,
            DhcpOption::NonLocalSourceRouting(v) => v,
            DhcpOption::AllSubnetsLocal(v) => v,
            DhcpOption::MaskSupplier(v) => v,
            DhcpOption::TrailerEncapsulation(v) => v,
            DhcpOption::EthernetEncapsulation(v) => v,
            DhcpOption::TcpKeepAliveGarbage(v) => v,
            _ => return Err(DhcpError::ConversionError(self.tag()))
        }.clone())
    }

    /// Try to get value if type is known without match
    pub fn try_to_vec_u8(&self) -> DhcpResult<Vec<u8>> {
        Ok(match self {
            DhcpOption::VendorSpecific(v) => v,
            DhcpOption::ParameterRequestList(v) => v,
            DhcpOption::VendorClassIdentifier(v) => v,
            _ => return Err(DhcpError::ConversionError(self.tag()))
        }.clone())
    }

    /// Try to get value if type is known without match
    pub fn try_to_ascii(&self) -> DhcpResult<AsciiString> {
        Ok(match self {
            DhcpOption::HostName(v) => v,
            DhcpOption::MeritDumpFile(v) => v,
            DhcpOption::DomainName(v) => v,
            DhcpOption::RootPath(v) => v,
            DhcpOption::ExtensionPath(v) => v,
            DhcpOption::NetworkInformationServiceDomain(v) => v,
            DhcpOption::Message(v) => v,
            DhcpOption::NetworkInformationServicePlusDomain(v) => v,
            DhcpOption::TftpServer(v) => v,
            DhcpOption::BootFileName(v) => v,
            _ => return Err(DhcpError::ConversionError(self.tag()))
        }.clone())
    }

    /// Try to get value if type is known without match
    pub fn try_to_ipv4(&self) -> DhcpResult<Ipv4Addr> {
        Ok(match self {
            DhcpOption::SubnetMask(v, ) => v,
            DhcpOption::SwapServer(v, ) => v,
            DhcpOption::BroadcastAddress(v, ) => v,
            DhcpOption::RouterSolicitationAddress(v, ) => v,
            DhcpOption::RequestedIpAddress(v, ) => v,
            DhcpOption::ServerIdentifier(v, ) => v,
            _ => return Err(DhcpError::ConversionError(self.tag()))
        }.clone())
    }

    /// Try to get value if type is known without match
    pub fn try_to_ipv4vec(&self) -> DhcpResult<Ipv4AddrVec> {
        Ok(match self {
            DhcpOption::Router(v, ) => v,
            DhcpOption::TimeServer(v, ) => v,
            DhcpOption::NameServer(v, ) => v,
            DhcpOption::DomainNameServer(v, ) => v,
            DhcpOption::LogServer(v, ) => v,
            DhcpOption::CookieServer(v, ) => v,
            DhcpOption::LPRServer(v, ) => v,
            DhcpOption::ImpressServer(v, ) => v,
            DhcpOption::ResourceLocationServer(v, ) => v,
            DhcpOption::NetworkInformationServers(v, ) => v,
            DhcpOption::NetworkTimeProtocolServers(v, ) => v,
            DhcpOption::NetBiosOverTcpIpNameServer(v, ) => v,
            DhcpOption::NetBiosOverTcpIpDatagramDistributionServer(v, ) => v,
            DhcpOption::XWindowSystemFontServer(v, ) => v,
            DhcpOption::XWindowSystemDisplayManager(v, ) => v,
            DhcpOption::NetworkInformationServicePlusServer(v, ) => v,
            DhcpOption::MobileIpHomeAgent(v, ) => v,
            DhcpOption::SmtpServer(v, ) => v,
            DhcpOption::Pop3Server(v, ) => v,
            DhcpOption::NntpServer(v, ) => v,
            DhcpOption::WwwServer(v, ) => v,
            DhcpOption::FingerServer(v, ) => v,
            DhcpOption::IrcServer(v, ) => v,
            DhcpOption::StreetTalkServer(v, ) => v,
            DhcpOption::StreetTalkDirectoryAssistanceServer(v, ) => v,
            _ => return Err(DhcpError::ConversionError(self.tag()))
        }.clone())
    }

    /// Try to get value if type is known without match
    pub fn try_to_u8(&self) -> DhcpResult<u8> {
        Ok(*match self {
            DhcpOption::DefaultIpTTL(v, ) => v,
            DhcpOption::TcpDefaultTTL(v, ) => v,
            _ => return Err(DhcpError::ConversionError(self.tag()))
        })
    }

    /// Try to get value if type is known without match
    pub fn try_to_u16(&self) -> DhcpResult<u16> {
        Ok(*match self {
            DhcpOption::BootFileSize(v, ) => v,
            DhcpOption::InterfaceMtu(v, ) => v,
            DhcpOption::MaximumDhcpMessageSize(v, ) => v,
            _ => return Err(DhcpError::ConversionError(self.tag()))
        })
    }

    /// Try to get value if type is known without match
    pub fn try_to_u32(&self) -> DhcpResult<u32> {
        Ok(*match self {
            DhcpOption::PathMtuAgingTimeout(v, ) => v,
            DhcpOption::ArpCacheTimeout(v, ) => v,
            DhcpOption::TcpKeepAliveInterval(v, ) => v,
            DhcpOption::IpAddressLeaseTime(v, ) => v,
            DhcpOption::RenewalTimeValue(v, ) => v,
            DhcpOption::RebindingTimeValue(v, ) => v,
            _ => return Err(DhcpError::ConversionError(self.tag()))
        })
    }

    /// Try to get value if type is known without match
    pub fn try_to_i32(&self) -> DhcpResult<i32> {
        Ok(*match self {
            DhcpOption::TimeOffset(v, ) => v,
            _ => return Err(DhcpError::ConversionError(self.tag()))
        })
    }

    /// Returns the Dhcp tag
    pub fn tag(&self) -> u8 {
        match self {
            DhcpOption::Pad => PAD,
            DhcpOption::SubnetMask(_) => SUBNET_MASK,
            DhcpOption::TimeOffset(_) => TIME_OFFSET,
            DhcpOption::Router(_) => ROUTER,
            DhcpOption::TimeServer(_) => TIME_SERVER,
            DhcpOption::NameServer(_) => NAME_SERVER,
            DhcpOption::DomainNameServer(_) => DOMAIN_NAME_SERVER,
            DhcpOption::LogServer(_) => LOG_SERVER,
            DhcpOption::CookieServer(_) => COOKIE_SERVER,
            DhcpOption::LPRServer(_) => LPR_SERVER,
            DhcpOption::ImpressServer(_) => IMPRESS_SERVER,
            DhcpOption::ResourceLocationServer(_) => RESOURCE_LOCATION_SERVER,
            DhcpOption::HostName(_) => HOST_NAME,
            DhcpOption::BootFileSize(_) => BOOT_FILE_SIZE,
            DhcpOption::MeritDumpFile(_) => MERIT_DUMP_FILE,
            DhcpOption::DomainName(_) => DOMAIN_NAME,
            DhcpOption::SwapServer(_) => SWAP_SERVER,
            DhcpOption::RootPath(_) => ROOT_PATH,
            DhcpOption::ExtensionPath(_) => EXTENSION_PATH,
            DhcpOption::IpForwarding(_) => IP_FORWARDING,
            DhcpOption::NonLocalSourceRouting(_) => NON_LOCAL_SOURCE_ROUTING,
            DhcpOption::PolicyFilter(_) => POLICY_FILTER,
            DhcpOption::MaximumDatagramReassemblySize(_) => MAXIMUM_DATAGRAM_REASSEMBLY_SIZE,
            DhcpOption::DefaultIpTTL(_) => DEFAULT_IP_TTL,
            DhcpOption::PathMtuAgingTimeout(_) => PATH_MTU_AGING_TIMEOUT,
            DhcpOption::PathMtuPlateauTable(_) => PATH_MTU_PLATEAU_TABLE,
            DhcpOption::InterfaceMtu(_) => INTERFACE_MTU,
            DhcpOption::AllSubnetsLocal(_) => ALL_SUBNETS_LOCAL,
            DhcpOption::BroadcastAddress(_) => BROADCAST_ADDRESS,
            DhcpOption::MaskSupplier(_) => MASK_SUPPLIER,
            DhcpOption::PerformRouterDiscovery(_) => PERFORM_ROUTER_DISCOVERY,
            DhcpOption::RouterSolicitationAddress(_) => ROUTER_SOLICITATION_ADDRESS,
            DhcpOption::StaticRoute(_) => STATIC_ROUTE,
            DhcpOption::TrailerEncapsulation(_) => TRAILER_ENCAPSULATION,
            DhcpOption::ArpCacheTimeout(_) => ARP_CACHE_TIMEOUT,
            DhcpOption::EthernetEncapsulation(_) => ETHERNET_ENCAPSULATION,
            DhcpOption::TcpDefaultTTL(_) => TCP_DEFAULT_TTL,
            DhcpOption::TcpKeepAliveInterval(_) => TCP_KEEPALIVE_INTERVAL,
            DhcpOption::TcpKeepAliveGarbage(_) => TCP_KEEPALIVE_GARGABE,
            DhcpOption::NetworkInformationServiceDomain(_) => NETWORK_INFORMATION_SERVICE_DOMAIN,
            DhcpOption::NetworkInformationServers(_) => NETBIOS_OVER_TCP_IP_NAME_SERVER,
            DhcpOption::NetworkTimeProtocolServers(_) => NETWORK_TIME_PROTOCOL_SERVERS,
            DhcpOption::VendorSpecific(_) => VENDOR_SPECIFIC,
            DhcpOption::NetBiosOverTcpIpNameServer(_) => NETBIOS_OVER_TCP_IP_NAME_SERVER,
            DhcpOption::NetBiosOverTcpIpDatagramDistributionServer(_) => NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER,
            DhcpOption::NetBiosOverTcpIpNodeType(_) => NETBIOS_OVER_TCP_IP_NODE_TYPE,
            DhcpOption::NetBiosOverTcpIpScope(_) => NETBIOS_OVER_TCP_IP_SCOPE,
            DhcpOption::XWindowSystemFontServer(_) => X_WINDOW_SYSTEM_FONT_SERVER,
            DhcpOption::XWindowSystemDisplayManager(_) => X_WINDOW_SYSTEM_DISPLAY_MANAGER,
            DhcpOption::RequestedIpAddress(_) => REQUESTED_IP_ADDRESS,
            DhcpOption::IpAddressLeaseTime(_) => IP_ADDRESS_LEASE_TIME,
            DhcpOption::OptionOverload(_) => OPTION_OVERLOAD,
            DhcpOption::MessageType(_) => MESSAGE_TYPE,
            DhcpOption::ServerIdentifier(_) => SERVER_IDENTIFIER,
            DhcpOption::ParameterRequestList(_) => PARAMETER_REQUEST_LIST,
            DhcpOption::Message(_) => MESSAGE,
            DhcpOption::MaximumDhcpMessageSize(_) => MAXIMUM_DHCP_MESSAGE_SIZE,
            DhcpOption::RenewalTimeValue(_) => RENEWAL_TIME_VALUE,
            DhcpOption::RebindingTimeValue(_) => REBINDING_TIME_VALUE,
            DhcpOption::VendorClassIdentifier(_) => VENDOR_CLASS_IDENTIFIER,
            DhcpOption::ClientIdentifier { .. } => CLIENT_IDENTIFIER,
            DhcpOption::NetworkInformationServicePlusDomain(_) => NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN,
            DhcpOption::NetworkInformationServicePlusServer(_) => NETWORK_INFORMATION_SERVICE_PLUS_SERVERS,
            DhcpOption::TftpServer(_) => TFTP_SERVER_NAME,
            DhcpOption::BootFileName(_) => BOOT_FILE_NAME,
            DhcpOption::MobileIpHomeAgent(_) => MOBILE_IP_HOME_AGENT,
            DhcpOption::SmtpServer(_) => SMTP_SERVER,
            DhcpOption::Pop3Server(_) => POP3_SERVER,
            DhcpOption::NntpServer(_) => NNTP_SERVER,
            DhcpOption::WwwServer(_) => WWW_SERVER,
            DhcpOption::FingerServer(_) => FINGER_SERVER,
            DhcpOption::IrcServer(_) => IRC_SERVER,
            DhcpOption::StreetTalkServer(_) => STREET_TALK_SERVER,
            DhcpOption::StreetTalkDirectoryAssistanceServer(_) => STREET_TALK_DIRECTORY_ASSISTANCE,
            DhcpOption::End => END,
            DhcpOption::RelayAgentInformation(_) => RELAY_AGENT_INFORMATION,
            DhcpOption::Unknown(tag, _) => *tag,
        }
    }

    /// Creates a new [`DhcpOption`] from byte slice
    pub fn from_bytes(tag: u8, _length: usize, data: &[u8]) -> DhcpResult<Self> {
        Ok(match tag {
            PAD => Self::Pad,
            SUBNET_MASK => Self::SubnetMask(data.try_from_option(tag)?),
            TIME_OFFSET => Self::TimeOffset(data.try_from_option(tag)?),
            ROUTER => Self::Router(data.try_from_option_min_bytes(tag, 4)?),
            TIME_SERVER => Self::TimeServer(data.try_from_option_min_bytes(tag, 4)?),
            NAME_SERVER => Self::NameServer(data.try_from_option_min_bytes(tag, 4)?),
            DOMAIN_NAME_SERVER => Self::DomainNameServer(data.try_from_option_min_bytes(tag, 4)?),
            LOG_SERVER => Self::LogServer(data.try_from_option_min_bytes(tag, 4)?),
            COOKIE_SERVER => Self::CookieServer(data.try_from_option_min_bytes(tag, 4)?),
            LPR_SERVER => Self::LPRServer(data.try_from_option_min_bytes(tag, 4)?),
            IMPRESS_SERVER => Self::ImpressServer(data.try_from_option_min_bytes(tag, 4)?),
            RESOURCE_LOCATION_SERVER => Self::ResourceLocationServer(data.try_from_option_min_bytes(tag, 4)?),
            HOST_NAME => Self::HostName(data.try_from_option_min_bytes(tag, 1)?),
            BOOT_FILE_SIZE => Self::BootFileSize(data.try_from_option(tag)?),
            MERIT_DUMP_FILE => Self::MeritDumpFile(data.try_from_option_min_bytes(tag, 1)?),
            DOMAIN_NAME => Self::DomainName(data.try_from_option_min_bytes(tag, 1)?),
            SWAP_SERVER => Self::SwapServer(data.try_from_option(tag)?),
            ROOT_PATH => Self::RootPath(data.try_from_option_min_bytes(tag, 1)?),
            EXTENSION_PATH => Self::ExtensionPath(data.try_from_option_min_bytes(tag, 1)?),
            IP_FORWARDING => Self::IpForwarding(data.try_from_option(tag)?),
            NON_LOCAL_SOURCE_ROUTING => Self::NonLocalSourceRouting(data.try_from_option(tag)?),
            POLICY_FILTER => Self::PolicyFilter(data.try_from_option_min_bytes(tag, 8)?),
            MAXIMUM_DATAGRAM_REASSEMBLY_SIZE => {
                let data: u16 = data.try_from_option(tag)?;
                if data < 576 {
                    return Err(DhcpError::OptionInvalidValueError(tag));
                }
                Self::MaximumDatagramReassemblySize(data)
            }
            DEFAULT_IP_TTL => Self::DefaultIpTTL(data.try_from_option_min_bytes(tag, 1)?),
            PATH_MTU_AGING_TIMEOUT => Self::PathMtuAgingTimeout(data.try_from_option(tag)?),
            PATH_MTU_PLATEAU_TABLE => Self::PathMtuPlateauTable(data.try_from_option_min_bytes(tag, 2)?),
            INTERFACE_MTU => Self::InterfaceMtu(data.try_from_option(tag)?),
            ALL_SUBNETS_LOCAL => Self::AllSubnetsLocal(data.try_from_option(tag)?),
            BROADCAST_ADDRESS => Self::BroadcastAddress(data.try_from_option(tag)?),
            PERFORM_MASK_DISCOVERY => Self::PerformRouterDiscovery(data.try_from_option(tag)?),
            MASK_SUPPLIER => Self::MaskSupplier(data.try_from_option(tag)?),
            PERFORM_ROUTER_DISCOVERY => Self::PerformRouterDiscovery(data.try_from_option(tag)?),
            ROUTER_SOLICITATION_ADDRESS => Self::RouterSolicitationAddress(data.try_from_option_min_bytes(tag, 4)?),
            STATIC_ROUTE => Self::StaticRoute(data.try_from_option_min_bytes(tag, 8)?),
            TRAILER_ENCAPSULATION => Self::TrailerEncapsulation(data.try_from_option(tag)?),
            ARP_CACHE_TIMEOUT => Self::ArpCacheTimeout(data.try_from_option(tag)?),
            ETHERNET_ENCAPSULATION => Self::EthernetEncapsulation(data.try_from_option(tag)?),
            TCP_DEFAULT_TTL => {
                let value = data.try_from_option(tag)?;
                if value < 1 {
                    return Err(DhcpError::OptionInvalidValueError(tag));
                }
                Self::TcpDefaultTTL(value)
            }
            TCP_KEEPALIVE_INTERVAL => Self::TcpKeepAliveInterval(data.try_from_option(tag)?),
            TCP_KEEPALIVE_GARGABE => Self::TcpKeepAliveGarbage(data.try_from_option(tag)?),
            NETWORK_INFORMATION_SERVICE_DOMAIN => Self::NetworkInformationServiceDomain(data.try_from_option_min_bytes(tag, 1)?),
            NETWORK_INFORMATION_SERVERS => Self::NetworkInformationServers(data.try_from_option_min_bytes(tag, 4)?),
            NETWORK_TIME_PROTOCOL_SERVERS => Self::NetworkTimeProtocolServers(data.try_from_option_min_bytes(tag, 4)?),
            VENDOR_SPECIFIC => Self::VendorSpecific(data.try_from_option_min_bytes(tag, 1)?),
            NETBIOS_OVER_TCP_IP_NAME_SERVER => Self::NetBiosOverTcpIpNameServer(data.try_from_option_min_bytes(tag, 4)?),
            NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER => Self::NetBiosOverTcpIpDatagramDistributionServer(data.try_from_option_min_bytes(tag, 4)?),
            NETBIOS_OVER_TCP_IP_NODE_TYPE => Self::NetBiosOverTcpIpNodeType(data.try_from_option(tag)?),
            NETBIOS_OVER_TCP_IP_SCOPE => Self::NetBiosOverTcpIpScope(data.try_from_option_min_bytes(tag, 1)?),
            X_WINDOW_SYSTEM_FONT_SERVER => Self::XWindowSystemFontServer(data.try_from_option_min_bytes(tag, 4)?),
            X_WINDOW_SYSTEM_DISPLAY_MANAGER => Self::XWindowSystemDisplayManager(data.try_from_option_min_bytes(tag, 4)?),
            REQUESTED_IP_ADDRESS => Self::RequestedIpAddress(data.try_from_option_min_bytes(tag, 4)?),
            IP_ADDRESS_LEASE_TIME => Self::IpAddressLeaseTime(data.try_from_option_min_bytes(tag, 4)?),
            OPTION_OVERLOAD => Self::OptionOverload(data.try_from_option(tag)?),
            MESSAGE_TYPE => Self::MessageType(data.try_from_option(tag)?),
            SERVER_IDENTIFIER => Self::ServerIdentifier(data.try_from_option(tag)?),
            PARAMETER_REQUEST_LIST => Self::ParameterRequestList(data.try_from_option_min_bytes(tag, 1)?),
            MESSAGE => Self::Message(data.try_from_option_min_bytes(tag, 1)?),
            MAXIMUM_DHCP_MESSAGE_SIZE => {
                let data: u16 = data.try_from_option(tag)?;
                if data < 576 {
                    return Err(DhcpError::OptionInvalidValueError(tag));
                }
                Self::MaximumDhcpMessageSize(data)
            }
            RENEWAL_TIME_VALUE => Self::RenewalTimeValue(data.try_from_option(tag)?),
            REBINDING_TIME_VALUE => Self::RebindingTimeValue(data.try_from_option(tag)?),
            VENDOR_CLASS_IDENTIFIER => Self::VendorClassIdentifier(data.try_from_option_min_bytes(tag, 1)?),
            CLIENT_IDENTIFIER => {
                Self::ClientIdentifier(ClientIdentifier {
                    typ: data[0],
                    data: data[1..].to_vec(),
                })
            }
            NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN => Self::NetworkInformationServicePlusDomain(data.try_from_option_min_bytes(tag, 4)?),
            NETWORK_INFORMATION_SERVICE_PLUS_SERVERS => Self::NetworkInformationServicePlusServer(data.try_from_option_min_bytes(tag, 4)?),
            TFTP_SERVER_NAME => Self::TftpServer(data.try_from_option(tag)?),
            BOOT_FILE_NAME => Self::BootFileName(data.try_from_option_min_bytes(tag, 1)?),
            MOBILE_IP_HOME_AGENT => Self::MobileIpHomeAgent(data.try_from_option(tag)?),
            SMTP_SERVER => Self::SmtpServer(data.try_from_option_min_bytes(tag, 4)?),
            POP3_SERVER => Self::Pop3Server(data.try_from_option_min_bytes(tag, 4)?),
            NNTP_SERVER => Self::NntpServer(data.try_from_option_min_bytes(tag, 4)?),
            WWW_SERVER => Self::WwwServer(data.try_from_option_min_bytes(tag, 4)?),
            FINGER_SERVER => Self::FingerServer(data.try_from_option_min_bytes(tag, 4)?),
            IRC_SERVER => Self::IrcServer(data.try_from_option_min_bytes(tag, 4)?),
            STREET_TALK_SERVER => Self::StreetTalkServer(data.try_from_option_min_bytes(tag, 4)?),
            STREET_TALK_DIRECTORY_ASSISTANCE => Self::StreetTalkDirectoryAssistanceServer(data.try_from_option_min_bytes(tag, 4)?),
            END => Self::End,
            RELAY_AGENT_INFORMATION => Self::RelayAgentInformation(data.try_from_option(tag)?),
            _ => Self::Unknown(tag, data.to_vec())
        })
    }

    /// Generates a new list of bytes with tag and content
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            DhcpOption::Pad => vec![PAD],
            DhcpOption::SubnetMask(data) => data.to_option_bytes(SUBNET_MASK),
            DhcpOption::TimeOffset(data) => data.to_option_bytes(TIME_OFFSET),
            DhcpOption::Router(data) => data.to_option_bytes(ROUTER),
            DhcpOption::TimeServer(data) => data.to_option_bytes(TIME_SERVER),
            DhcpOption::NameServer(data) => data.to_option_bytes(NAME_SERVER),
            DhcpOption::DomainNameServer(data) => data.to_option_bytes(DOMAIN_NAME_SERVER),
            DhcpOption::LogServer(data) => data.to_option_bytes(LOG_SERVER),
            DhcpOption::CookieServer(data) => data.to_option_bytes(COOKIE_SERVER),
            DhcpOption::LPRServer(data) => data.to_option_bytes(LPR_SERVER),
            DhcpOption::ImpressServer(data) => data.to_option_bytes(IMPRESS_SERVER),
            DhcpOption::ResourceLocationServer(data) => data.to_option_bytes(RESOURCE_LOCATION_SERVER),
            DhcpOption::HostName(data) => data.to_option_bytes(HOST_NAME),
            DhcpOption::BootFileSize(data) => data.to_option_bytes(BOOT_FILE_SIZE),
            DhcpOption::MeritDumpFile(data) => data.to_option_bytes(MERIT_DUMP_FILE),
            DhcpOption::DomainName(data) => data.to_option_bytes(DOMAIN_NAME),
            DhcpOption::SwapServer(data) => data.to_option_bytes(SWAP_SERVER),
            DhcpOption::RootPath(data) => data.to_option_bytes(ROOT_PATH),
            DhcpOption::ExtensionPath(data) => data.to_option_bytes(EXTENSION_PATH),
            DhcpOption::IpForwarding(data) => data.to_option_bytes(IP_FORWARDING),
            DhcpOption::NonLocalSourceRouting(data) => data.to_option_bytes(NON_LOCAL_SOURCE_ROUTING),
            DhcpOption::PolicyFilter(data) => data.to_option_bytes(POLICY_FILTER),
            DhcpOption::MaximumDatagramReassemblySize(data) => data.to_option_bytes(MAXIMUM_DATAGRAM_REASSEMBLY_SIZE),
            DhcpOption::DefaultIpTTL(data) => data.to_option_bytes(DEFAULT_IP_TTL),
            DhcpOption::PathMtuAgingTimeout(data) => data.to_option_bytes(PATH_MTU_AGING_TIMEOUT),
            DhcpOption::PathMtuPlateauTable(data) => data.to_option_bytes(PATH_MTU_PLATEAU_TABLE),
            DhcpOption::InterfaceMtu(data) => data.to_option_bytes(INTERFACE_MTU),
            DhcpOption::AllSubnetsLocal(data) => data.to_option_bytes(ALL_SUBNETS_LOCAL),
            DhcpOption::BroadcastAddress(data) => data.to_option_bytes(BROADCAST_ADDRESS),
            DhcpOption::MaskSupplier(data) => data.to_option_bytes(MASK_SUPPLIER),
            DhcpOption::PerformRouterDiscovery(data) => data.to_option_bytes(PERFORM_ROUTER_DISCOVERY),
            DhcpOption::RouterSolicitationAddress(data) => data.to_option_bytes(ROUTER_SOLICITATION_ADDRESS),
            DhcpOption::StaticRoute(data) => data.to_option_bytes(STATIC_ROUTE),
            DhcpOption::TrailerEncapsulation(data) => data.to_option_bytes(TRAILER_ENCAPSULATION),
            DhcpOption::ArpCacheTimeout(data) => data.to_option_bytes(ARP_CACHE_TIMEOUT),
            DhcpOption::EthernetEncapsulation(data) => data.to_option_bytes(ETHERNET_ENCAPSULATION),
            DhcpOption::TcpDefaultTTL(data) => data.to_option_bytes(TCP_DEFAULT_TTL),
            DhcpOption::TcpKeepAliveInterval(data) => data.to_option_bytes(TCP_KEEPALIVE_INTERVAL),
            DhcpOption::TcpKeepAliveGarbage(data) => data.to_option_bytes(TCP_KEEPALIVE_GARGABE),
            DhcpOption::NetworkInformationServiceDomain(data) => data.to_option_bytes(NETWORK_INFORMATION_SERVICE_DOMAIN),
            DhcpOption::NetworkInformationServers(data) => data.to_option_bytes(NETWORK_INFORMATION_SERVERS),
            DhcpOption::NetworkTimeProtocolServers(data) => data.to_option_bytes(NETWORK_TIME_PROTOCOL_SERVERS),
            DhcpOption::VendorSpecific(data) => data.to_option_bytes(VENDOR_SPECIFIC),
            DhcpOption::NetBiosOverTcpIpNameServer(data) => data.to_option_bytes(NETBIOS_OVER_TCP_IP_NAME_SERVER),
            DhcpOption::NetBiosOverTcpIpDatagramDistributionServer(data) => data.to_option_bytes(NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER),
            DhcpOption::NetBiosOverTcpIpNodeType(data) => data.to_option_bytes(NETBIOS_OVER_TCP_IP_NODE_TYPE),
            DhcpOption::NetBiosOverTcpIpScope(data) => data.to_option_bytes(NETBIOS_OVER_TCP_IP_SCOPE),
            DhcpOption::XWindowSystemFontServer(data) => data.to_option_bytes(X_WINDOW_SYSTEM_FONT_SERVER),
            DhcpOption::XWindowSystemDisplayManager(data) => data.to_option_bytes(X_WINDOW_SYSTEM_DISPLAY_MANAGER),
            DhcpOption::RequestedIpAddress(data) => data.to_option_bytes(REQUESTED_IP_ADDRESS),
            DhcpOption::IpAddressLeaseTime(data) => data.to_option_bytes(IP_ADDRESS_LEASE_TIME),
            DhcpOption::OptionOverload(data) => data.to_option_bytes(OPTION_OVERLOAD),
            DhcpOption::MessageType(data) => data.to_option_bytes(MESSAGE_TYPE),
            DhcpOption::ServerIdentifier(data) => data.to_option_bytes(SERVER_IDENTIFIER),
            DhcpOption::ParameterRequestList(data) => data.to_option_bytes(PARAMETER_REQUEST_LIST),
            DhcpOption::Message(data) => data.to_option_bytes(MESSAGE),
            DhcpOption::MaximumDhcpMessageSize(data) => data.to_option_bytes(MAXIMUM_DHCP_MESSAGE_SIZE),
            DhcpOption::RenewalTimeValue(data) => data.to_option_bytes(RENEWAL_TIME_VALUE),
            DhcpOption::RebindingTimeValue(data) => data.to_option_bytes(REBINDING_TIME_VALUE),
            DhcpOption::VendorClassIdentifier(data) => data.to_option_bytes(VENDOR_CLASS_IDENTIFIER),
            DhcpOption::ClientIdentifier(client_identifier) => {
                let mut bytes = client_identifier.data.clone();
                bytes.insert(0, bytes.len() as u8);
                bytes.insert(0, client_identifier.typ);
                bytes.insert(0, CLIENT_IDENTIFIER);
                bytes
            }
            DhcpOption::NetworkInformationServicePlusDomain(data) => data.to_option_bytes(NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN),
            DhcpOption::NetworkInformationServicePlusServer(data) => data.to_option_bytes(NETWORK_INFORMATION_SERVICE_PLUS_SERVERS),
            DhcpOption::TftpServer(data) => data.to_option_bytes(TFTP_SERVER_NAME),
            DhcpOption::BootFileName(data) => data.to_option_bytes(BOOT_FILE_NAME),
            DhcpOption::MobileIpHomeAgent(data) => data.to_option_bytes(MOBILE_IP_HOME_AGENT),
            DhcpOption::SmtpServer(data) => data.to_option_bytes(SMTP_SERVER),
            DhcpOption::Pop3Server(data) => data.to_option_bytes(POP3_SERVER),
            DhcpOption::NntpServer(data) => data.to_option_bytes(NNTP_SERVER),
            DhcpOption::WwwServer(data) => data.to_option_bytes(WWW_SERVER),
            DhcpOption::FingerServer(data) => data.to_option_bytes(FINGER_SERVER),
            DhcpOption::IrcServer(data) => data.to_option_bytes(IRC_SERVER),
            DhcpOption::StreetTalkServer(data) => data.to_option_bytes(STREET_TALK_SERVER),
            DhcpOption::StreetTalkDirectoryAssistanceServer(data) => data.to_option_bytes(STREET_TALK_DIRECTORY_ASSISTANCE),
            DhcpOption::End => vec![END],
            DhcpOption::RelayAgentInformation(data) => data.to_option_bytes(RELAY_AGENT_INFORMATION),
            DhcpOption::Unknown(tag, data) => {
                let mut bytes = data.clone();
                bytes.insert(0, bytes.len() as u8);
                bytes.insert(0, *tag);
                bytes
            }
        }
    }
}
