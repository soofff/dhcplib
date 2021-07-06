use std::net::Ipv4Addr;
use std::convert::TryInto;
use ascii::AsciiString;
use crate::option::{NetBiosNodeType, Overload, MessageType, RelayAgentInformationSubOption};
use crate::error::{DhcpError, DhcpResult};

pub const MESSAGE_TYPE_DISCOVER: u8 = 1;
pub const MESSAGE_TYPE_OFFER: u8 = 2;
pub const MESSAGE_TYPE_REQUEST: u8 = 3;
pub const MESSAGE_TYPE_DECLINE: u8 = 4;
pub const MESSAGE_TYPE_PACK: u8 = 5;
pub const MESSAGE_TYPE_NAK: u8 = 6;
pub const MESSAGE_TYPE_RELEASE: u8 = 7;
pub const MESSAGE_TYPE_INFORM: u8 = 8;

pub const NODE_TYPE_B: u8 = 1;
pub const NODE_TYPE_P: u8 = 2;
pub const NODE_TYPE_M: u8 = 4;
pub const NODE_TYPE_H: u8 = 8;

pub const RELAY_AGENT_CIRCUIT: u8 = 1;
pub const RELAY_AGENT_REMOTE: u8 = 2;

pub const OVERLOAD_FILE: u8 = 1;
pub const OVERLOAD_SNAME: u8 = 2;
pub const OVERLOAD_BOTH: u8 = 3;

macro_rules! impl_length {
    ($t:ty) => {
        impl TryIntoOptionMinBytes<$t> for &[u8] {
            fn length(&self) -> usize {
                self.len()
            }
        }
    };
}

pub(crate) trait TryToOption<T> {
    fn try_from_option(&self, tag: u8) -> DhcpResult<T>;
}

pub(crate) trait TryIntoOptionMinBytes<T>: TryToOption<T>
{
    fn try_from_option_min_bytes(&self, tag: u8, min_bytes: usize) -> DhcpResult<T> {
        if self.length() < min_bytes {
            return Err(DhcpError::OptionParseError(tag));
        }
        self.try_from_option(tag)
    }

    fn length(&self) -> usize;
}

impl_length!(Vec<Ipv4Addr>);

impl_length!(AsciiString);

impl_length!(Vec<(Ipv4Addr, Ipv4Addr)>);

impl_length!(u8);

impl_length!(Vec<u16>);

impl_length!(Ipv4Addr);

impl_length!(Vec<u8>);

impl_length!(u32);

pub(crate) trait ToOptionBytes {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8>;
}

impl TryToOption<Ipv4Addr> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<Ipv4Addr> {
        let fixed: [u8; 4] = self[0..4].try_into().map_err(|_| DhcpError::OptionParseError(tag))?;
        Ok(Ipv4Addr::from(fixed))
    }
}

impl TryToOption<Vec<Ipv4Addr>> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<Vec<Ipv4Addr>> {
        if self.len() % 4 == 0 {
            let mut ip_vec = vec![];
            for chunk in self.chunks_exact(4) {
                ip_vec.push(Ipv4Addr::from([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
            Ok(ip_vec)
        } else {
            Err(DhcpError::OptionParseError(tag))
        }
    }
}

impl TryToOption<u8> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<u8> {
        self[0..1].try_into().map(u8::from_be_bytes).map_err(|_| DhcpError::OptionParseError(tag))
    }
}

impl TryToOption<u16> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<u16> {
        self[0..2].try_into().map(u16::from_be_bytes).map_err(|_| DhcpError::OptionParseError(tag))
    }
}

impl TryToOption<u32> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<u32> {
        self[0..4].try_into().map(u32::from_be_bytes).map_err(|_| DhcpError::OptionParseError(tag))
    }
}

impl TryToOption<i32> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<i32> {
        self[0..4].try_into().map(i32::from_be_bytes).map_err(|_| DhcpError::OptionParseError(tag))
    }
}

impl TryToOption<AsciiString> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<AsciiString> {
        AsciiString::from_ascii(self.to_vec()).map_err(|_| DhcpError::OptionParseError(tag))
    }
}

impl TryToOption<bool> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<bool> {
        self.get(0)
            .ok_or(DhcpError::OptionParseError(tag))
            .map(|value| {
                match value {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(DhcpError::OptionParseError(tag))
                }
            })?
    }
}

impl TryToOption<Vec<(Ipv4Addr, Ipv4Addr)>> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<Vec<(Ipv4Addr, Ipv4Addr)>> {
        if self.len() % 8 == 0 {
            Ok(self.chunks_exact(8).map(|b| {
                (Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                 Ipv4Addr::new(b[4], b[5], b[6], b[7]))
            }).collect())
        } else {
            Err(DhcpError::OptionParseError(tag))
        }
    }
}

impl TryToOption<Vec<u8>> for &[u8] {
    fn try_from_option(&self, _: u8) -> DhcpResult<Vec<u8>> {
        Ok(self.to_vec())
    }
}

impl TryToOption<Vec<u16>> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<Vec<u16>> {
        if self.len() % 2 == 0 {
            let mut result: Vec<u16> = vec![];
            for chunk in self.chunks_exact(2) {
                result.push(chunk.try_from_option(tag)?);
            }
            Ok(result)
        } else {
            Err(DhcpError::OptionParseError(tag))
        }
    }
}

impl TryToOption<NetBiosNodeType> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<NetBiosNodeType> {
        match self.get(0).ok_or(DhcpError::OptionParseError(tag)) {
            Ok(&NODE_TYPE_B) => Ok(NetBiosNodeType::B),
            Ok(&NODE_TYPE_P) => Ok(NetBiosNodeType::P),
            Ok(&NODE_TYPE_M) => Ok(NetBiosNodeType::M),
            Ok(&NODE_TYPE_H) => Ok(NetBiosNodeType::H),
            _ => Err(DhcpError::OptionParseError(tag))
        }
    }
}

impl TryToOption<Overload> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<Overload> {
        match self.get(0).ok_or(DhcpError::OptionParseError(tag)) {
            Ok(&OVERLOAD_FILE) => Ok(Overload::File),
            Ok(&OVERLOAD_SNAME) => Ok(Overload::Sname),
            Ok(&OVERLOAD_BOTH) => Ok(Overload::Both),
            _ => Err(DhcpError::OptionParseError(tag))
        }
    }
}

impl TryToOption<MessageType> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<MessageType> {
        match self.get(0).ok_or(DhcpError::OptionParseError(tag)) {
            Ok(&MESSAGE_TYPE_DISCOVER) => Ok(MessageType::Discover),
            Ok(&MESSAGE_TYPE_OFFER) => Ok(MessageType::Offer),
            Ok(&MESSAGE_TYPE_REQUEST) => Ok(MessageType::Request),
            Ok(&MESSAGE_TYPE_DECLINE) => Ok(MessageType::Decline),
            Ok(&MESSAGE_TYPE_PACK) => Ok(MessageType::Ack),
            Ok(&MESSAGE_TYPE_NAK) => Ok(MessageType::Nak),
            Ok(&MESSAGE_TYPE_RELEASE) => Ok(MessageType::Release),
            Ok(&MESSAGE_TYPE_INFORM) => Ok(MessageType::Inform),
            _ => Err(DhcpError::OptionParseError(tag))
        }
    }
}

impl TryToOption<Vec<RelayAgentInformationSubOption>> for &[u8] {
    fn try_from_option(&self, tag: u8) -> DhcpResult<Vec<RelayAgentInformationSubOption>> {
        let mut result = vec![];
        let mut bytes = *self;
        loop {
            let sub_tag = bytes.get(0).ok_or(DhcpError::OptionParseError(tag))?;
            let length = *bytes.get(1).ok_or(DhcpError::OptionParseError(tag))? as usize + 2;
            let data = bytes[2..length].to_vec();

            result.push(match *sub_tag {
                RELAY_AGENT_CIRCUIT => RelayAgentInformationSubOption::AgentCircuit(data),
                RELAY_AGENT_REMOTE => RelayAgentInformationSubOption::AgentRemote(data),
                _ => RelayAgentInformationSubOption::Unknown(data),
            });

            bytes = &bytes[length..];

            if bytes.is_empty() {
                break;
            }
        }

        Ok(result)
    }
}


impl ToOptionBytes for Ipv4Addr {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        let mut data = self.octets().to_vec();
        data.insert(0, data.len() as u8);
        data.insert(0, tag);
        data
    }
}

impl ToOptionBytes for Vec<Ipv4Addr> {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        let mut bytes = vec![tag];
        self.iter().for_each(|ip| {
            bytes.extend_from_slice(&ip.octets());
        });
        bytes.insert(1, (bytes.len() - 1) as u8);
        bytes
    }
}

impl ToOptionBytes for u16 {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        let mut data = vec![tag, 2];
        data.extend(&self.to_be_bytes());
        data
    }
}

impl ToOptionBytes for u32 {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        let mut data = vec![tag, 4];
        data.extend(&self.to_be_bytes());
        data
    }
}

impl ToOptionBytes for i16 {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        let mut data = vec![tag, 2];
        data.extend(&self.to_be_bytes());
        data
    }
}

impl ToOptionBytes for i32 {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        let mut data = vec![tag, 4];
        data.extend(&self.to_be_bytes());
        data
    }
}

impl ToOptionBytes for AsciiString {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        let mut data: Vec<u8> = self.as_bytes().to_vec();
        data.insert(0, data.len() as u8);
        data.insert(0, tag);
        data
    }
}

impl ToOptionBytes for &bool {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        vec![tag, 1, match self {
            false => 0,
            true => 1
        }]
    }
}

impl ToOptionBytes for &Vec<(Ipv4Addr, Ipv4Addr)> {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        let mut data = vec![];

        self.iter().for_each(|ips| {
            data.extend_from_slice(&ips.0.octets());
            data.extend_from_slice(&ips.1.octets());
        });
        data.insert(0, data.len() as u8);
        data.insert(0, tag);

        data
    }
}


impl ToOptionBytes for &u8 {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        vec![tag, 1, **self]
    }
}


impl ToOptionBytes for &Vec<u16> {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        let mut data: Vec<u8> = vec![];
        self.iter().map(|b| b.to_be_bytes()).for_each(|s| {
            data.push(s[0]);
            data.push(s[1]);
        });

        data.insert(0, data.len() as u8);
        data.insert(0, tag);
        data
    }
}

impl ToOptionBytes for &Vec<u8> {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        let mut data = self.to_vec();
        data.insert(0, data.len() as u8);
        data.insert(0, tag);
        data
    }
}

impl ToOptionBytes for &NetBiosNodeType {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        vec![tag, 1, match self {
            NetBiosNodeType::B => NODE_TYPE_B,
            NetBiosNodeType::P => NODE_TYPE_P,
            NetBiosNodeType::M => NODE_TYPE_M,
            NetBiosNodeType::H => NODE_TYPE_H
        }]
    }
}

impl ToOptionBytes for &Overload {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        vec![tag, 1, match self {
            Overload::File => OVERLOAD_FILE,
            Overload::Sname => OVERLOAD_SNAME,
            Overload::Both => OVERLOAD_BOTH,
        }]
    }
}

impl ToOptionBytes for &MessageType {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        vec![tag, 1, match self {
            MessageType::Discover => MESSAGE_TYPE_DISCOVER,
            MessageType::Offer => MESSAGE_TYPE_OFFER,
            MessageType::Request => MESSAGE_TYPE_REQUEST,
            MessageType::Decline => MESSAGE_TYPE_DECLINE,
            MessageType::Ack => MESSAGE_TYPE_PACK,
            MessageType::Nak => MESSAGE_TYPE_NAK,
            MessageType::Release => MESSAGE_TYPE_RELEASE,
            MessageType::Inform => MESSAGE_TYPE_INFORM,
        }]
    }
}

impl ToOptionBytes for &Vec<RelayAgentInformationSubOption> {
    fn to_option_bytes(&self, tag: u8) -> Vec<u8> {
        let mut sub_options: Vec<u8> = self.iter().map(|r| {
            let (sub_tag, data) = match r {
                RelayAgentInformationSubOption::AgentRemote(sub_data) => (RELAY_AGENT_REMOTE, sub_data),
                RelayAgentInformationSubOption::AgentCircuit(sub_data) => (RELAY_AGENT_CIRCUIT, sub_data),
                RelayAgentInformationSubOption::Unknown(sub_data) => (0, sub_data),
            };

            let mut data: Vec<u8> = data.iter().copied().collect();
            data.insert(0, data.len() as u8);
            data.insert(0, sub_tag);
            data
        }).flatten().collect();

        sub_options.insert(0, sub_options.len() as u8);
        sub_options.insert(0, tag);

        sub_options
    }
}


#[test]
fn test_parse_ipv4() {
    let bytes: &[u8] = &[1, 2, 3, 4];
    let ip = Ipv4Addr::new(1, 2, 3, 4);
    let parsed_ip: Ipv4Addr = bytes.try_from_option(0).unwrap();
    assert_eq!(ip, parsed_ip);
}

#[test]
fn test_parse_ipv4_vec() {
    let bytes: &[u8] = &[1, 2, 3, 4, 5, 5, 5, 5];
    let ips = vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 5, 5, 5)];
    let parsed_ip: Vec<Ipv4Addr> = bytes.try_from_option(0).unwrap();
    assert_eq!(ips, parsed_ip);
}

#[test]
fn test_parse_u8() {
    let bytes: &[u8] = &[111];
    let result: u8 = bytes.try_from_option(0).unwrap();
    assert_eq!(111 as u8, result);
}

#[test]
fn test_parse_u16() {
    let bytes: &[u8] = &[111, 222];
    let result: u16 = bytes.try_from_option(0).unwrap();
    assert_eq!(28638 as u16, result);
}

#[test]
fn test_parse_u32() {
    let bytes: &[u8] = &[111, 222, 111, 222];
    let result: u32 = bytes.try_from_option(0).unwrap();
    assert_eq!(1876848606 as u32, result);
}

#[test]
fn test_parse_i32() {
    let bytes: &[u8] = &[1, 2, 3, 4];
    let result: i32 = bytes.try_from_option(0).unwrap();
    assert_eq!(16909060 as i32, result);
}

#[test]
fn test_parse_ascii_string() {
    let bytes: &[u8] = &['D' as u8, 'h' as u8, 'c' as u8, 'p' as u8];
    let result: AsciiString = bytes.try_from_option(0).unwrap();
    assert_eq!(AsciiString::from(vec![ascii::AsciiChar::D,
                                      ascii::AsciiChar::h,
                                      ascii::AsciiChar::c,
                                      ascii::AsciiChar::p,
    ]), result);
}

#[test]
fn test_parse_bool() {
    let bytes: &[u8] = &[0];
    let result: bool = bytes.try_from_option(0).unwrap();
    assert_eq!(false, result);
}

#[test]
fn test_parse_ipv4_tuple_vec() {
    let bytes: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    let result: Vec<(Ipv4Addr, Ipv4Addr)> = bytes.try_from_option(0).unwrap();
    assert_eq!(vec![(Ipv4Addr::new(1, 2, 3, 4),
                     Ipv4Addr::new(5, 6, 7, 8))],
               result);
}

#[test]
fn test_parse_u8_vec() {
    let bytes: &[u8] = &[1, 100, 200];
    let result: Vec<u8> = bytes.try_from_option(0).unwrap();
    assert_eq!(vec![1, 100, 200], result);
}

#[test]
fn test_parse_u16_vec() {
    let bytes: &[u8] = &[10, 100, 200, 10];
    let result: Vec<u16> = bytes.try_from_option(0).unwrap();
    assert_eq!(vec![2660, 51210], result);
}

#[test]
fn test_parse_netbios_node_type() {
    let bytes: &[u8] = &[2];
    let result: NetBiosNodeType = bytes.try_from_option(0).unwrap();
    assert_eq!(NetBiosNodeType::P, result);
}

#[test]
fn test_parse_overload() {
    let bytes: &[u8] = &[3];
    let result: Overload = bytes.try_from_option(0).unwrap();
    assert_eq!(Overload::Both, result);
}

#[test]
fn test_parse_message_type() {
    let bytes: &[u8] = &[5];
    let result: MessageType = bytes.try_from_option(0).unwrap();
    assert_eq!(MessageType::Ack, result);
}

#[test]
fn test_parse_relay_agent_information_sub_option() {
    let bytes: &[u8] = &[RELAY_AGENT_REMOTE, 3, 1, 2, 3,
        RELAY_AGENT_CIRCUIT, 1, 1];
    let result: Vec<RelayAgentInformationSubOption> = bytes.try_from_option(0).unwrap();
    assert_eq!(vec![RelayAgentInformationSubOption::AgentRemote(vec![1, 2, 3]),
                    RelayAgentInformationSubOption::AgentCircuit(vec![1]),
    ], result);
}

#[test]
fn test_into_bytes_ipv4() {
    let bytes: &[u8] = &[0 as u8, 4, 1, 2, 3, 4];
    assert_eq!(bytes, Ipv4Addr::new(1, 2, 3, 4).to_option_bytes(0))
}

#[test]
fn test_into_bytes_ipv4_vec() {
    let bytes: &[u8] = &[0 as u8, 8, 1, 2, 3, 4, 5, 5, 5, 5];
    assert_eq!(bytes, vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 5, 5, 5)]
        .to_option_bytes(0))
}

#[test]
fn test_into_bytes_u16() {
    let bytes: &[u8] = &[0 as u8, 2, 1, 0];
    assert_eq!(bytes, (256 as u16).to_option_bytes(0));
}

#[test]
fn test_into_bytes_u32() {
    let bytes: &[u8] = &[0 as u8, 4, 255, 255, 255, 255];
    assert_eq!(bytes, u32::MAX.to_option_bytes(0));
}

#[test]
fn test_into_bytes_i16() {
    let bytes: &[u8] = &[0 as u8, 2, 127, 255];
    assert_eq!(bytes, i16::MAX.to_option_bytes(0))
}

#[test]
fn test_into_bytes_i32() {
    let bytes: &[u8] = &[0 as u8, 4, 127, 255, 255, 255];
    assert_eq!(bytes, i32::MAX.to_option_bytes(0))
}

#[test]
fn test_into_bytes_ascii_string() {
    let bytes: &[u8] = &[0 as u8, 2, 65, 122];
    assert_eq!(bytes, AsciiString::from(&[ascii::AsciiChar::A, ascii::AsciiChar::z] as &[ascii::AsciiChar]).to_option_bytes(0))
}

#[test]
fn test_into_bytes_bool() {
    let bytes: &[u8] = &[0 as u8, 1, 0];
    assert_eq!(bytes, (&false).to_option_bytes(0))
}

#[test]
fn test_into_bytes_ipv4_tuple_vec() {
    let bytes: &[u8] = &[0 as u8, 16, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8];
    assert_eq!(bytes, (&vec![(Ipv4Addr::new(1, 1, 2, 2),
                              Ipv4Addr::new(3, 3, 4, 4)),
                             (Ipv4Addr::new(5, 5, 6, 6),
                              Ipv4Addr::new(7, 7, 8, 8))])
        .to_option_bytes(0));
}

#[test]
fn test_into_bytes_u8() {
    let bytes: &[u8] = &[0 as u8, 1, 5];
    assert_eq!(bytes, (&(5 as u8)).to_option_bytes(0));
}

#[test]
fn test_into_bytes_u16_vec() {
    let bytes: &[u8] = &[0 as u8, 2, 4, 87];
    assert_eq!(bytes, (&(1111 as u16)).to_option_bytes(0));
}

#[test]
fn test_into_bytes_u8_vec() {
    let bytes: &[u8] = &[0 as u8, 3, 0, 2, 3];
    assert_eq!(bytes, (&vec![0 as u8, 2, 3]).to_option_bytes(0))
}

#[test]
fn test_into_bytes_netbios_node_type() {
    let bytes: &[u8] = &[0 as u8, 1, NODE_TYPE_M];
    assert_eq!(bytes, (&NODE_TYPE_M).to_option_bytes(0))
}

#[test]
fn test_into_bytes_overload() {
    let bytes: &[u8] = &[0 as u8, 1, OVERLOAD_SNAME];
    assert_eq!(bytes, (&OVERLOAD_SNAME).to_option_bytes(0))
}

#[test]
fn test_into_bytes_message_type() {
    let bytes: &[u8] = &[0 as u8, 1, MESSAGE_TYPE_DECLINE];
    assert_eq!(bytes, (&MESSAGE_TYPE_DECLINE).to_option_bytes(0))
}

#[test]
fn test_into_bytes_relay_agent_information_vec() {
    let bytes: &[u8] = &[0 as u8,
        8,
        1, 1, 1,
        2, 3, 5, 6, 7];
    let data = vec![RelayAgentInformationSubOption::AgentCircuit(vec![1 as u8]),
                    RelayAgentInformationSubOption::AgentRemote(vec![5, 6, 7])];

    assert_eq!(bytes, (&data).to_option_bytes(0))
}