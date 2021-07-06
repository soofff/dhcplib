use ascii::AsciiString;
use std::convert::{TryFrom, TryInto};
use std::net::Ipv4Addr;
use crate::DhcpPacket;
use crate::dhcp::{Flags, MessageOperation, HardwareAddressType, MacAddress};
use crate::error::DhcpError;
use crate::option::{DhcpOptions, DhcpOption, MessageType, MESSAGE_TYPE, REQUESTED_IP_ADDRESS, PARAMETER_REQUEST_LIST, CLIENT_IDENTIFIER, MAXIMUM_DHCP_MESSAGE_SIZE, ClientIdentifier, SERVER_IDENTIFIER, IP_ADDRESS_LEASE_TIME};

macro_rules! packet {
    ($t:ident) => {
        /// Represents a Dhcp Packet depending on the message type.
        ///
        /// Conversation functions are available according to rfc.
        pub struct $t { packet: DhcpPacket }

        impl $t {
            pub fn packet(&self) -> &DhcpPacket {
                &self.packet
            }
        }

        impl From<$t> for DhcpPacket {
            fn from(p: $t) -> Self {
                p.packet
            }
        }

        impl From<DhcpPacket> for $t {
            fn from(packet: DhcpPacket) -> Self {
                Self {
                    packet
                }
            }
        }
    };
}

packet!(DhcpDeclinePacket);

packet!(DhcpReleasePacket);

packet!(DhcpAckPacket);

packet!(DhcpNakPacket);

/// Represents all dhcp message types with possible conversations.
///
/// Reflects the Client/Server communication.
pub enum DhcpMessaging {
    Discover(DhcpDiscoverPacket),
    Offer(DhcpOfferPacket),
    Request(DhcpRequestPacket),
    Inform(DhcpInformPacket),
    Release(DhcpReleasePacket),
    Decline(DhcpDeclinePacket),
    Ack(DhcpAckPacket),
    Nak(DhcpNakPacket),
}

// todo: https://datatracker.ietf.org/doc/html/rfc2131#section-4.3.6 ?
impl DhcpMessaging {
    /// Inner packet
    pub fn packet(&self) -> &DhcpPacket {
        match self {
            DhcpMessaging::Discover(p) => &p.packet,
            DhcpMessaging::Offer(p) => &p.packet,
            DhcpMessaging::Request(p) => &p.packet,
            DhcpMessaging::Inform(p) => &p.packet,
            DhcpMessaging::Release(p) => &p.packet,
            DhcpMessaging::Decline(p) => &p.packet,
            DhcpMessaging::Ack(p) => &p.packet,
            DhcpMessaging::Nak(p) => &p.packet,
        }
    }

    /// Creates a decline packet.
    pub fn decline<C>(
        client_mac_address: C,
    ) -> DhcpDeclinePacket
        where
            C: Into<MacAddress>,
    {
        let options: DhcpOptions = vec![
            DhcpOption::MessageType(MessageType::Decline)
        ].into();

        DhcpDeclinePacket {
            packet: DhcpPacket::new(
                MessageOperation::BootRequest,
                HardwareAddressType::Ethernet,
                0,
                rand::random(),
                0,
                Flags::Unicast,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                client_mac_address.into(),
                AsciiString::default(),
                AsciiString::default(),
                options,
            )
        }
    }

    /// Creates a release packet.
    pub fn release<C>(
        client_mac_address: C,
        client_ip_address: Ipv4Addr,
    ) -> DhcpDeclinePacket
        where
            C: Into<MacAddress>,
    {
        let options: DhcpOptions = vec![
            DhcpOption::MessageType(MessageType::Decline)
        ].into();

        DhcpDeclinePacket {
            packet: DhcpPacket::new(
                MessageOperation::BootRequest,
                HardwareAddressType::Ethernet,
                0,
                rand::random(),
                0,
                Flags::Unicast,
                client_ip_address,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                client_mac_address.into(),
                AsciiString::default(),
                AsciiString::default(),
                options,
            )
        }
    }

    /// Creates a inform packet.
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::too_many_arguments))]
    pub fn inform<C, O>(client_mac_address: C,
                        client_ip_address: Ipv4Addr,
                        client_identifier: Option<ClientIdentifier>,
                        vendor_class_identifier: Option<Vec<u8>>,
                        parameter_requested_list: Option<Vec<u8>>,
                        maximum_accepted_size: Option<u16>,
                        broadcast: bool,
                        additional_options: O,
    ) -> DhcpInformPacket
        where
            C: Into<MacAddress>,
            O: Into<DhcpOptions>,
    {
        let mut options = additional_options.into();
        options.upsert(DhcpOption::MessageType(MessageType::Inform));
        options.upsert_option(client_identifier.map(DhcpOption::ClientIdentifier));
        options.upsert_option(vendor_class_identifier.map(DhcpOption::VendorClassIdentifier));
        options.upsert_option(parameter_requested_list.map(DhcpOption::ParameterRequestList));
        options.upsert_option(maximum_accepted_size.map(DhcpOption::MaximumDhcpMessageSize));

        let flag = if broadcast {
            Flags::Broadcast
        } else {
            Flags::Unicast
        };

        DhcpInformPacket {
            packet: DhcpPacket::new(
                MessageOperation::BootRequest,
                HardwareAddressType::Ethernet,
                0,
                rand::random(),
                0,
                flag,
                client_ip_address,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                client_mac_address.into(),
                AsciiString::default(),
                AsciiString::default(),
                options,
            )
        }
    }

    #[cfg_attr(feature = "cargo-clippy", allow(clippy::too_many_arguments))]
    pub fn discover<C, O>(client_mac_address: C,
                          requested_ip_address: Option<Ipv4Addr>,
                          lease_time: Option<u32>,
                          client_identifier: Option<ClientIdentifier>,
                          vendor_class_identifier: Option<Vec<u8>>,
                          parameter_requested_list: Option<Vec<u8>>,
                          maximum_accepted_size: Option<u16>,
                          additional_options: O,
    ) -> DhcpDiscoverPacket
        where
            C: Into<MacAddress>,
            O: Into<DhcpOptions>,
    {
        let mut options = additional_options.into();
        options.upsert(DhcpOption::MessageType(MessageType::Discover));

        options.upsert_option(requested_ip_address.map(DhcpOption::RequestedIpAddress));
        options.upsert_option(lease_time.map(DhcpOption::IpAddressLeaseTime));
        options.upsert_option(client_identifier.map(DhcpOption::ClientIdentifier));
        options.upsert_option(vendor_class_identifier.map(DhcpOption::VendorClassIdentifier));
        options.upsert_option(parameter_requested_list.map(DhcpOption::ParameterRequestList));
        options.upsert_option(maximum_accepted_size.map(DhcpOption::MaximumDhcpMessageSize));

        options.remove(SERVER_IDENTIFIER);

        DhcpDiscoverPacket {
            packet: DhcpPacket::new(
                MessageOperation::BootRequest,
                HardwareAddressType::Ethernet,
                0,
                rand::random(),
                0,
                Flags::Broadcast,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                client_mac_address.into(),
                AsciiString::default(),
                AsciiString::default(),
                options,
            )
        }
    }
}

impl From<DhcpMessaging> for Vec<u8> {
    fn from(m: DhcpMessaging) -> Self {
        match m {
            DhcpMessaging::Discover(p) => { p.packet.into() }
            DhcpMessaging::Offer(p) => { p.packet.into() }
            DhcpMessaging::Request(p) => { p.packet.into() }
            DhcpMessaging::Inform(p) => { p.packet.into() }
            DhcpMessaging::Release(p) => { p.packet.into() }
            DhcpMessaging::Decline(p) => { p.packet.into() }
            DhcpMessaging::Ack(p) => { p.packet.into() }
            DhcpMessaging::Nak(p) => { p.packet.into() }
        }
    }
}

impl TryFrom<&[u8]> for DhcpMessaging {
    type Error = DhcpError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let p: DhcpPacket = value.try_into()?;
        p.try_into()
    }
}

impl TryFrom<DhcpPacket> for DhcpMessaging {
    type Error = DhcpError;

    fn try_from(packet: DhcpPacket) -> Result<Self, Self::Error> {
        Ok(match packet.option(MESSAGE_TYPE) {
            Some(DhcpOption::MessageType(MessageType::Discover)) => {
                DhcpMessaging::Discover(DhcpDiscoverPacket { packet })
            }
            Some(DhcpOption::MessageType(MessageType::Offer)) => {
                DhcpMessaging::Offer(DhcpOfferPacket { packet })
            }
            Some(DhcpOption::MessageType(MessageType::Request)) => {
                DhcpMessaging::Request(DhcpRequestPacket { packet })
            }
            Some(DhcpOption::MessageType(MessageType::Inform)) => {
                DhcpMessaging::Inform(DhcpInformPacket { packet })
            }
            Some(DhcpOption::MessageType(MessageType::Release)) => {
                DhcpMessaging::Release(DhcpReleasePacket { packet })
            }
            Some(DhcpOption::MessageType(MessageType::Decline)) => {
                DhcpMessaging::Decline(DhcpDeclinePacket { packet })
            }
            Some(DhcpOption::MessageType(MessageType::Ack)) => {
                DhcpMessaging::Ack(DhcpAckPacket { packet })
            }
            Some(DhcpOption::MessageType(MessageType::Nak)) => {
                DhcpMessaging::Nak(DhcpNakPacket { packet })
            }
            _ => {
                return Err(DhcpError::DhcpMessagePacketError);
            }
        })
    }
}

packet!(DhcpDiscoverPacket);

impl DhcpDiscoverPacket {
    /// Converts a discover packet into an offer packet
    pub fn into_offer<I, O>(mut self,
                            lease: u32,
                            client_ip_address: I,
                            server_ip_address: I,
                            filename: Option<AsciiString>,
                            message: Option<AsciiString>,
                            additional_options: O,
    ) -> DhcpOfferPacket
        where
            I: Into<Ipv4Addr>,
            O: Into<DhcpOptions>
    {
        let server_ip = server_ip_address.into();

        self.packet.operation = MessageOperation::BootReply;
        self.packet.hardware_type = HardwareAddressType::Ethernet;
        self.packet.hops = 0;
        self.packet.seconds = 0;
        self.packet.client = Ipv4Addr::UNSPECIFIED;
        self.packet.your = client_ip_address.into();
        self.packet.server = server_ip;
        self.packet.filename = filename.map(Into::into).unwrap_or_default();

        self.packet.options_mut().merge(additional_options.into());
        self.packet.options_mut().upsert_option(message.map(DhcpOption::Message));
        self.packet.options_mut().remove(REQUESTED_IP_ADDRESS);
        self.packet.options_mut().remove(PARAMETER_REQUEST_LIST);
        self.packet.options_mut().remove(CLIENT_IDENTIFIER);
        self.packet.options_mut().remove(MAXIMUM_DHCP_MESSAGE_SIZE);
        self.packet.options_mut().upsert(DhcpOption::ServerIdentifier(server_ip));
        self.packet.options_mut().upsert(DhcpOption::IpAddressLeaseTime(lease));
        self.packet.options_mut().upsert(DhcpOption::MessageType(MessageType::Offer));

        DhcpOfferPacket { packet: self.packet }
    }
}

packet!(DhcpInformPacket);

impl DhcpInformPacket {
    /// Converts an inform packet into an ack packet
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::too_many_arguments))]
    pub fn into_ack<O>(mut self,
                       client_ip_address: Ipv4Addr,
                       server_ip_address: Ipv4Addr,
                       filename: Option<AsciiString>,
                       server_name: Option<AsciiString>,
                       message: Option<AsciiString>,
                       vendor_class_identifier: Option<Vec<u8>>,
                       additional_options: O,
    ) -> DhcpAckPacket
        where
            O: Into<DhcpOptions>,
    {
        self.packet.operation = MessageOperation::BootReply;
        self.packet.hardware_type = HardwareAddressType::Ethernet;
        self.packet.hops = 0;
        self.packet.seconds = 0;
        self.packet.client = client_ip_address;
        self.packet.filename = filename.unwrap_or_default();
        self.packet.server_hostname = server_name.unwrap_or_default();

        self.packet.options_mut().merge(additional_options.into());

        self.packet.options_mut().remove(REQUESTED_IP_ADDRESS);
        self.packet.options_mut().remove(PARAMETER_REQUEST_LIST);
        self.packet.options_mut().remove(CLIENT_IDENTIFIER);
        self.packet.options_mut().remove(MAXIMUM_DHCP_MESSAGE_SIZE);
        self.packet.options_mut().remove(IP_ADDRESS_LEASE_TIME);

        self.packet.options_mut().upsert(DhcpOption::ServerIdentifier(server_ip_address));
        self.packet.options_mut().upsert_option(message.map(DhcpOption::Message));
        self.packet.options_mut().upsert_option(vendor_class_identifier.map(DhcpOption::VendorClassIdentifier));
        self.packet.options_mut().upsert(DhcpOption::MessageType(MessageType::Ack));
        DhcpAckPacket { packet: self.packet }
    }
}

packet!(DhcpRequestPacket);

impl DhcpRequestPacket {
    /// Converts an request packet into an ack packet
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::too_many_arguments))]
    pub fn into_ack<O>(mut self,
                       lease: u32,
                       client_ip_address: Ipv4Addr,
                       server_ip_address: Ipv4Addr,
                       filename: Option<AsciiString>,
                       server_name: Option<AsciiString>,
                       message: Option<AsciiString>,
                       vendor_class_identifier: Option<Vec<u8>>,
                       additional_options: O,
    ) -> DhcpAckPacket
        where
            O: Into<DhcpOptions>,
    {
        self.packet.operation = MessageOperation::BootReply;
        self.packet.hardware_type = HardwareAddressType::Ethernet;
        self.packet.hops = 0;
        self.packet.seconds = 0;
        self.packet.client = client_ip_address;
        self.packet.filename = filename.unwrap_or_default();
        self.packet.server_hostname = server_name.unwrap_or_default();

        self.packet.options_mut().merge(additional_options.into());

        self.packet.options_mut().remove(REQUESTED_IP_ADDRESS);
        self.packet.options_mut().remove(PARAMETER_REQUEST_LIST);
        self.packet.options_mut().remove(CLIENT_IDENTIFIER);
        self.packet.options_mut().remove(MAXIMUM_DHCP_MESSAGE_SIZE);

        self.packet.options_mut().upsert(DhcpOption::ServerIdentifier(server_ip_address));
        self.packet.options_mut().upsert_option(message.map(DhcpOption::Message));
        self.packet.options_mut().upsert_option(vendor_class_identifier.map(DhcpOption::VendorClassIdentifier));
        self.packet.options_mut().upsert(DhcpOption::IpAddressLeaseTime(lease));
        self.packet.options_mut().upsert(DhcpOption::MessageType(MessageType::Ack));
        DhcpAckPacket { packet: self.packet }
    }

    /// Converts an request packet into a nak packet
    pub fn into_nak(mut self,
                    server_ip_address: Ipv4Addr,
                    message: Option<AsciiString>,
                    client_identifier: Option<ClientIdentifier>,
                    vendor_class_identifier: Option<Vec<u8>>,
    ) -> DhcpNakPacket {
        let server_ip = server_ip_address;

        self.packet.your = Ipv4Addr::UNSPECIFIED;
        self.packet.server = Ipv4Addr::UNSPECIFIED;
        self.packet.operation = MessageOperation::BootReply;
        self.packet.hops = 0;
        self.packet.hardware_type = HardwareAddressType::Ethernet;
        self.packet.seconds = 0;

        self.packet.options_mut().remove(REQUESTED_IP_ADDRESS);
        self.packet.options_mut().remove(IP_ADDRESS_LEASE_TIME);
        self.packet.options_mut().remove(PARAMETER_REQUEST_LIST);
        self.packet.options_mut().remove(CLIENT_IDENTIFIER);
        self.packet.options_mut().remove(MAXIMUM_DHCP_MESSAGE_SIZE);

        self.packet.options_mut().upsert(DhcpOption::ServerIdentifier(server_ip));
        self.packet.options_mut().upsert_option(message.map(DhcpOption::Message));
        self.packet.options_mut().upsert(DhcpOption::MessageType(MessageType::Nak));
        self.packet.options_mut().upsert_option(client_identifier.map(DhcpOption::ClientIdentifier));
        self.packet.options_mut().upsert_option(vendor_class_identifier.map(DhcpOption::VendorClassIdentifier));

        DhcpNakPacket { packet: self.packet }
    }
}

packet!(DhcpOfferPacket);

impl DhcpOfferPacket {
    /// Converts an offer packet into an request packet
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::too_many_arguments))]
    pub fn into_request<C, O>(mut self,
                              client_hardware_address: C,
                              seconds: u16,
                              client_ip_address: Option<Ipv4Addr>,
                              broadcast: bool,
                              requested_ip_address: Option<Ipv4Addr>,
                              lease_time: Option<u32>,
                              client_identifier: Option<ClientIdentifier>,
                              vendor_class_identifier: Option<Vec<u8>>,
                              server_identifier: Option<Ipv4Addr>,
                              parameter_requested_list: Option<Vec<u8>>,
                              maximum_accepted_size: Option<u16>,
                              additional_options: O,
    ) -> DhcpRequestPacket
        where
            C: Into<MacAddress>,
            O: Into<DhcpOptions>,
    {
        let mut options = additional_options.into();
        options.upsert(DhcpOption::MessageType(MessageType::Request));
        options.upsert_option(requested_ip_address.map(DhcpOption::RequestedIpAddress));
        options.upsert_option(lease_time.map(DhcpOption::IpAddressLeaseTime));
        options.upsert_option(client_identifier.map(DhcpOption::ClientIdentifier));
        options.upsert_option(vendor_class_identifier.map(DhcpOption::VendorClassIdentifier));
        options.upsert_option(server_identifier.map(DhcpOption::ServerIdentifier));
        options.upsert_option(parameter_requested_list.map(DhcpOption::ParameterRequestList));
        options.upsert_option(maximum_accepted_size.map(DhcpOption::MaximumDhcpMessageSize));

        let flags = if broadcast {
            Flags::Broadcast
        } else {
            Flags::Unicast
        };

        self.packet.operation = MessageOperation::BootRequest;
        self.packet.hardware_type = HardwareAddressType::Ethernet;
        self.packet.hops = 0;
        self.packet.seconds = seconds;
        self.packet.flags = flags;
        self.packet.client_hardware = client_hardware_address.into();
        self.packet.client = client_ip_address.unwrap_or(Ipv4Addr::UNSPECIFIED);
        self.packet.your = Ipv4Addr::UNSPECIFIED;
        self.packet.server = Ipv4Addr::UNSPECIFIED;
        self.packet.gateway = Ipv4Addr::UNSPECIFIED;
        self.packet.options_mut().merge(options);

        DhcpRequestPacket { packet: self.packet }
    }
}


#[test]
fn test() {
    let client_mac = macaddr::MacAddr6::new(0, 1, 2, 3, 4, 5);
    let client_ip = Ipv4Addr::new(1, 2, 3, 4);
    let server_ip = Ipv4Addr::new(5, 6, 7, 8);

    let discover = DhcpMessaging::discover(
        client_mac,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let offer = discover.into_offer(
        7200,
        client_ip,
        server_ip,
        None,
        None,
        None,
    );
    let _request = offer.into_request(
        client_mac,
        2,
        Some(client_ip),
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
}