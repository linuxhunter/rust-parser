use std::{net::Ipv4Addr, str::FromStr};

use nom7::{IResult, number::complete::{be_u32, be_u8, be_u16, be_u24}, combinator::map_res, Err, error::{make_error, ErrorKind}, sequence::tuple, bytes::streaming::take};

#[derive(Debug, PartialEq)]
pub enum MethodOrEventID {
    MethodID(u16),
    EventID(u16),
}

impl std::fmt::Display for MethodOrEventID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl MethodOrEventID {
    fn from_u16(value: u16) -> Self {
        if (value & 0x8000) != 0 {
            MethodOrEventID::EventID(value & 0x7FFF)
        } else {
            MethodOrEventID::MethodID(value)
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct MessageID {
    service_id: u16,
    is_event_id: bool,
    method_or_event_id: MethodOrEventID,
}

impl std::fmt::Display for MessageID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut is_event_id = 0u8;
        if self.is_event_id == true {
            is_event_id = 1u8;
        }
        write!(f, "{}:{}:{}", self.service_id, is_event_id, self.method_or_event_id)
    }
}

impl MessageID {
    fn from_u32(value: u32) -> Result<Self, String> {
        let service_id = ((value >> 16) & 0xFFFF) as u16;
        let is_event_id = if value & 0x00008000 != 0 {
            true
        } else {
            false
        };
        let meth_or_event_id = (value & 0x00007FFF) as u16;
        Ok(MessageID {
            service_id,
            is_event_id,
            method_or_event_id: MethodOrEventID::from_u16(meth_or_event_id),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct RequestID {
    client_id: u16,
    session_id: u16,
}

impl std::fmt::Display for RequestID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.client_id, self.session_id)
    }
}

impl RequestID {
    fn from_u32(value: u32) -> Result<Self, String> {
        let client_id = ((value >> 16) & 0xFFFF) as u16;
        let session_id = (value & 0x0000FFFF) as u16;
        Ok(RequestID {
            client_id,
            session_id,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum MessageType {
    Request,
    RequestNoReturn,
    Notification,
    Response,
    Error,
    Invalid,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl MessageType {
    fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0x00 => Ok(MessageType::Request),
            0x01 => Ok(MessageType::RequestNoReturn),
            0x02 => Ok(MessageType::Notification),
            0x80 => Ok(MessageType::Response),
            0x81 => Ok(MessageType::Error),
            _ => Err(String::from("unsupported message type"))
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct SomeIPHeader {
    message_id: MessageID,
    length: u32,
    request_id: RequestID,
    protocol_version: u8,
    interface_version: u8,
    message_type: MessageType,
    return_code: u8,
}

#[derive(Debug, PartialEq)]
pub struct SomeIpSdEntrySubscribeEventGroup {
    reserved: u8,
    initial_data_request_flag: u8,
    eventgroup_id: u16,
}

#[derive(Debug, PartialEq)]
pub enum SomeIpSdEntryLastItem {
    MinorVersion(u32),
    EventGroup(SomeIpSdEntrySubscribeEventGroup),
}

impl SomeIpSdEntryLastItem {
    fn from_u32(data: u32, entry_type: u8) -> Result<Self, String> {
        if entry_type == 0x06 || entry_type == 0x07 {
            let reserved = ((data >> 24) & 0xFF) as u8;
            let initial_data_request_flag = ((data >> 16) & 0xFF) as u8;
            let eventgroup_id = (data & 0xFFFF) as u16;
            Ok(SomeIpSdEntryLastItem::EventGroup(SomeIpSdEntrySubscribeEventGroup {
                reserved,
                initial_data_request_flag,
                eventgroup_id,
            }))
        } else {
            Ok(SomeIpSdEntryLastItem::MinorVersion(data))
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct SomeIpSdEntry {
    entry_type: u8,
    index_1st_options: u8,
    index_2nd_options: u8,
    num_of_option_1: u8,
    num_of_option_2: u8,
    service_id: u16,
    instance_id: u16,
    major_version: u8,
    ttl: u32,
    last_item: SomeIpSdEntryLastItem,
}

#[derive(Debug, PartialEq)]
pub enum SomeIpSdOptionType {
    IPv4_EndPoint,
    Ipv4_MultiCast,
}

impl SomeIpSdOptionType {
    fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0x04 => Ok(SomeIpSdOptionType::IPv4_EndPoint),
            0x14 => Ok(SomeIpSdOptionType::Ipv4_MultiCast),
            _ => Err(String::from("Invalid Some IP SD option type")),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct SomeIpSdOption {
    length: u16,
    sd_option_type: SomeIpSdOptionType,
    ipv4_addr: Ipv4Addr,
    l4_protocol: u8,
}

#[derive(Debug, PartialEq)]
pub struct SomeIpSdHeader {
    flags: u8,
    length_entries: u32,
    entries_array: Vec<SomeIpSdEntry>,
    length_options: u32,
    options_array: Option<Vec<SomeIpSdOption>>,
}

pub fn parse_some_ip_header(input: &[u8]) -> IResult<&[u8], SomeIPHeader> {
    let (rem, message_id) = map_res(be_u32, |data| MessageID::from_u32(data))(input)?;
    let (rem, length) = be_u32(rem)?;
    let (rem, request_id) = map_res(be_u32, |data| RequestID::from_u32(data))(rem)?;
    let (rem, protocol_version) = be_u8(rem)?;
    let (rem, interface_version) = be_u8(rem)?;
    let (rem, message_type) = map_res(be_u8, |data| MessageType::from_u8(data))(rem)?;
    let (rem, return_code) = be_u8(rem)?;
    Ok((rem, SomeIPHeader {
        message_id,
        length,
        request_id,
        protocol_version,
        interface_version,
        message_type,
        return_code,
    }))
}

fn transform_num_of_option(data: u8) -> Result<(u8, u8), String> {
    let num_of_option_1 = ((data >> 4) & 0x0F) as u8;
    let num_of_option_2 = (data & 0x0F) as u8;
    Ok((num_of_option_1, num_of_option_2))
}

pub fn parse_some_ip_sd_entries(input: &[u8], length_entries: u32) -> IResult<&[u8], Vec<SomeIpSdEntry>> {
    if input.len() < length_entries as usize {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    let mut rem = input;
    let mut entries = Vec::new();
    while input.len() - rem.len() < length_entries as usize {
        let (tmp_rem, (
            entry_type,
            index_1st_options,
            index_2nd_options,
            (num_of_option_1, num_of_option_2),
            service_id,
            instance_id,
            major_version,
            ttl,
            item
        )) = tuple((
            be_u8,
            be_u8,
            be_u8,
            map_res(be_u8, |data| transform_num_of_option(data)),
            be_u16,
            be_u16,
            be_u8,
            be_u24,
            be_u32
        ))(rem)?;
        let last_item = SomeIpSdEntryLastItem::from_u32(item, entry_type).unwrap();
        entries.push(SomeIpSdEntry {
            entry_type,
            index_1st_options,
            index_2nd_options,
            num_of_option_1,
            num_of_option_2,
            service_id,
            instance_id,
            major_version,
            ttl,
            last_item,
        });
        rem = tmp_rem;
    }
    Ok((rem, entries))
}

pub fn transform_vec_to_ipv4addr(data: &[u8]) -> Result<Ipv4Addr, String> {
    if data.len() < 4 {
        return Err(String::from("Invalid IPv4 address"));
    }
    Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

pub fn parse_some_ip_sd_option(input: &[u8], _length_options: u32) -> IResult<&[u8], Vec<SomeIpSdOption>> {
    if input.is_empty() {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    let mut rem = input;
    let mut sd_options = Vec::new();
    while !rem.is_empty() {
        let (tmp_rem, (
            length,
            sd_option_type,
            _,
            ipv4_addr,
            _,
            l4_protocol,
            _unknown_part
        )) = tuple((
            be_u16,
            map_res(be_u8, |data| SomeIpSdOptionType::from_u8(data)),
            be_u8,
            map_res(take(4usize), transform_vec_to_ipv4addr),
            be_u8,
            be_u8,
            be_u16
        ))(rem)?;
        sd_options.push(SomeIpSdOption {
            length,
            sd_option_type,
            ipv4_addr,
            l4_protocol,
        });
        rem = tmp_rem;
    }
    Ok((rem, sd_options))
}

pub fn parse_some_ip_sd_header(input: &[u8]) -> IResult<&[u8], SomeIpSdHeader> {
    let (rem, flags) = be_u8(input)?;
    let (rem, _) = be_u24(rem)?;
    let (rem, length_entries) = be_u32(rem)?;
    let (rem, entries_array) = parse_some_ip_sd_entries(rem, length_entries)?;
    let (rem, length_options) = be_u32(rem)?;
    let mut last_rem = rem;
    let mut options_array = None;
    if length_options > 0 {
        let (rem, tmp_data) = parse_some_ip_sd_option(rem, length_options)?;
        last_rem = rem;
        options_array = Some(tmp_data);
    }
    Ok((last_rem, SomeIpSdHeader {
        flags,
        length_entries,
        entries_array,
        length_options,
        options_array,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOME_IP_HEADER: &[u8] = &[
                    0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x08, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x01,
        0x01, 0x00
    ];
    #[test]
    fn test_parse_some_ip_header() {
        match parse_some_ip_header(SOME_IP_HEADER) {
            Ok((rem, header)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(header, SomeIPHeader {
                    message_id: MessageID::from_u32(0xFFFF0000).unwrap(),
                    length: 0x08,
                    request_id: RequestID::from_u32(0xdeadbeef).unwrap(),
                    protocol_version: 0x01,
                    interface_version: 0x01,
                    message_type: MessageType::from_u8(0x01).unwrap(),
                    return_code: 0x00,
                });
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }
    
    const SOME_IP_SD_HEADER: &[u8] = &[
                    0xff, 0xff, 0x81, 0x00, 0x00, 0x00,
        0x00, 0x3c, 0x00, 0x00, 0x00, 0x1e, 0x01, 0x01,
        0x02, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x01, 0x00, 0x00, 0x20, 0x00, 0x58,
        0x00, 0x63, 0x01, 0x01, 0x51, 0x80, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x18, 0x00, 0x09,
        0x04, 0x00, 0xc0, 0xa8, 0x84, 0x83, 0x00, 0x06,
        0x77, 0x67, 0x00, 0x09, 0x04, 0x00, 0xc0, 0xa8,
        0x84, 0x83, 0x00, 0x11, 0x77, 0x25
    ];
    #[test]
    fn test_parse_some_ip_sd_header() {
        match parse_some_ip_header(SOME_IP_SD_HEADER) {
            Ok((rem, header)) => {
                assert_eq!(header, SomeIPHeader {
                    message_id: MessageID::from_u32(0xFFFF8100).unwrap(),
                    length: 0x3c,
                    request_id: RequestID::from_u32(0x0000001e).unwrap(),
                    protocol_version: 0x01,
                    interface_version: 0x01,
                    message_type: MessageType::from_u8(0x02).unwrap(),
                    return_code: 0x00,
                });
                match parse_some_ip_sd_header(rem) {
                    Ok((rem, sd_header)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(sd_header, SomeIpSdHeader {
                            flags: 0xc0,
                            length_entries: 0x10,
                            entries_array: vec![
                                SomeIpSdEntry {
                                    entry_type: 0x01,
                                    index_1st_options: 0x00,
                                    index_2nd_options: 0x00,
                                    num_of_option_1: 0x02,
                                    num_of_option_2: 0x00,
                                    service_id: 0x0058,
                                    instance_id: 0x0063,
                                    major_version: 0x01,
                                    ttl: 86400,
                                    last_item: SomeIpSdEntryLastItem::MinorVersion(0x01),
                                }
                            ],
                            length_options: 0x18,
                            options_array: Some(vec![
                                SomeIpSdOption {
                                    length: 0x0009,
                                    sd_option_type: SomeIpSdOptionType::IPv4_EndPoint,
                                    ipv4_addr: Ipv4Addr::from_str("192.168.132.131").unwrap(),
                                    l4_protocol: 0x06,
                                },
                                SomeIpSdOption {
                                    length: 0x0009,
                                    sd_option_type: SomeIpSdOptionType::IPv4_EndPoint,
                                    ipv4_addr: Ipv4Addr::from_str("192.168.132.131").unwrap(),
                                    l4_protocol: 0x11,
                                }
                            ]),
                        })
                    },
                    Err(_) => {
                        panic!("should not reach here")
                    }
                }
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    const SOME_IP_SD_HEADER_2_ENTRIES_2_OPTIONS: &[u8] = &[
                    0xff, 0xff, 0x81, 0x00, 0x00, 0x00,
        0x00, 0x4c, 0x00, 0x00, 0x00, 0x18, 0x01, 0x01,
        0x02, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x06, 0x00, 0x00, 0x20, 0x00, 0x58,
        0x00, 0x63, 0x01, 0x01, 0x51, 0x80, 0x00, 0x00,
        0x00, 0x01, 0x06, 0x00, 0x00, 0x20, 0x00, 0x58,
        0x00, 0x63, 0x01, 0x01, 0x51, 0x80, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x18, 0x00, 0x09,
        0x04, 0x00, 0xc0, 0xa8, 0x84, 0x82, 0x00, 0x06,
        0xb9, 0x42, 0x00, 0x09, 0x04, 0x00, 0xc0, 0xa8,
        0x84, 0x82, 0x00, 0x11, 0xb2, 0x3c
    ];
    #[test]
    fn test_parse_some_ip_header_2() {
        match parse_some_ip_header(SOME_IP_SD_HEADER_2_ENTRIES_2_OPTIONS) {
            Ok((rem, header)) => {
                assert_eq!(header, SomeIPHeader {
                    message_id: MessageID::from_u32(0xFFFF8100).unwrap(),
                    length: 0x4c,
                    request_id: RequestID::from_u32(0x00000018).unwrap(),
                    protocol_version: 0x01,
                    interface_version: 0x01,
                    message_type: MessageType::from_u8(0x02).unwrap(),
                    return_code: 0x00,
                });
                match parse_some_ip_sd_header(rem) {
                    Ok((rem, sd_header)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(sd_header, SomeIpSdHeader {
                            flags: 0xc0,
                            length_entries: 0x20,
                            entries_array: vec![
                                SomeIpSdEntry {
                                    entry_type: 0x06,
                                    index_1st_options: 0x00,
                                    index_2nd_options: 0x00,
                                    num_of_option_1: 0x02,
                                    num_of_option_2: 0x00,
                                    service_id: 0x58,
                                    instance_id: 0x63,
                                    major_version: 0x01,
                                    ttl: 86400,
                                    last_item: SomeIpSdEntryLastItem::EventGroup(SomeIpSdEntrySubscribeEventGroup {
                                        reserved: 0x00,
                                        initial_data_request_flag: 0x00,
                                        eventgroup_id: 0x0001,
                                    }),
                                },
                                SomeIpSdEntry {
                                    entry_type: 0x06,
                                    index_1st_options: 0x00,
                                    index_2nd_options: 0x00,
                                    num_of_option_1: 0x02,
                                    num_of_option_2: 0x00,
                                    service_id: 0x58,
                                    instance_id: 0x63,
                                    major_version: 0x01,
                                    ttl: 86400,
                                    last_item: SomeIpSdEntryLastItem::EventGroup(SomeIpSdEntrySubscribeEventGroup {
                                        reserved: 0x00,
                                        initial_data_request_flag: 0x00,
                                        eventgroup_id: 0x0002,
                                    }),
                                },
                            ],
                            length_options: 0x18,
                            options_array: Some(vec![
                                SomeIpSdOption {
                                    length: 0x0009,
                                    sd_option_type: SomeIpSdOptionType::IPv4_EndPoint,
                                    ipv4_addr: Ipv4Addr::from_str("192.168.132.130").unwrap(),
                                    l4_protocol: 0x06,
                                },
                                SomeIpSdOption {
                                    length: 0x0009,
                                    sd_option_type: SomeIpSdOptionType::IPv4_EndPoint,
                                    ipv4_addr: Ipv4Addr::from_str("192.168.132.130").unwrap(),
                                    l4_protocol: 0x11,
                                },
                            ]),
                        });
                    },
                    Err(_) => {
                        panic!("should not reach here");
                    }
                }
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    const SOME_IP_SD_FIND_SERVICE: &[u8] = &[
                    0xff, 0xff, 0x81, 0x00, 0x00, 0x00,
        0x00, 0x24, 0x00, 0x00, 0x00, 0x18, 0x01, 0x01,
        0x02, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00
    ];
    #[test]
    fn test_parse_some_ip_sd_find_service() {
        match parse_some_ip_header(SOME_IP_SD_FIND_SERVICE) {
            Ok((rem, header)) => {
                assert_eq!(header, SomeIPHeader {
                    message_id: MessageID::from_u32(0xFFFF8100).unwrap(),
                    length: 0x24,
                    request_id: RequestID::from_u32(0x00000018).unwrap(),
                    protocol_version: 0x01,
                    interface_version: 0x01,
                    message_type: MessageType::from_u8(0x02).unwrap(),
                    return_code: 0x00,
                });
                match parse_some_ip_sd_header(rem) {
                    Ok((rem, sd_header)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(sd_header, SomeIpSdHeader {
                            flags: 0xc0,
                            length_entries: 0x10,
                            entries_array: vec![
                                SomeIpSdEntry {
                                    entry_type: 0x00,
                                    index_1st_options: 0x00,
                                    index_2nd_options: 0x00,
                                    num_of_option_1: 0x00,
                                    num_of_option_2: 0x00,
                                    service_id: 0x0058,
                                    instance_id: 0xffff,
                                    major_version: 0xff,
                                    ttl: 16777215,
                                    last_item: SomeIpSdEntryLastItem::MinorVersion(0xffffffff),
                                }
                            ],
                            length_options: 0x00,
                            options_array: None,
                        })
                    },
                    Err(_) => {
                        panic!("should not reach here")
                    }
                }
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    const SOME_IP_SD_OFFER_SERVICE: &[u8] = &[
                    0xff, 0xff, 0x81, 0x00, 0x00, 0x00,
        0x00, 0x3c, 0x00, 0x00, 0x00, 0x1e, 0x01, 0x01,
        0x02, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x01, 0x00, 0x00, 0x20, 0x00, 0x58,
        0x00, 0x63, 0x01, 0x01, 0x51, 0x80, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x18, 0x00, 0x09,
        0x04, 0x00, 0xc0, 0xa8, 0x84, 0x83, 0x00, 0x06,
        0x77, 0x67, 0x00, 0x09, 0x04, 0x00, 0xc0, 0xa8,
        0x84, 0x83, 0x00, 0x11, 0x77, 0x25
    ];
    #[test]
    fn test_parse_some_ip_sd_offer_service() {
        match parse_some_ip_header(SOME_IP_SD_OFFER_SERVICE) {
            Ok((rem, header)) => {
                assert_eq!(header, SomeIPHeader {
                    message_id: MessageID::from_u32(0xFFFF8100).unwrap(),
                    length: 0x3c,
                    request_id: RequestID::from_u32(0x0000001e).unwrap(),
                    protocol_version: 0x01,
                    interface_version: 0x01,
                    message_type: MessageType::from_u8(0x02).unwrap(),
                    return_code: 0x00,
                });
                match parse_some_ip_sd_header(rem) {
                    Ok((rem, sd_header)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(sd_header, SomeIpSdHeader {
                            flags: 0xc0,
                            length_entries: 0x10,
                            entries_array: vec![
                                SomeIpSdEntry {
                                    entry_type: 0x01,
                                    index_1st_options: 0x00,
                                    index_2nd_options: 0x00,
                                    num_of_option_1: 0x02,
                                    num_of_option_2: 0x00,
                                    service_id: 0x0058,
                                    instance_id: 0x0063,
                                    major_version: 0x01,
                                    ttl: 86400,
                                    last_item: SomeIpSdEntryLastItem::MinorVersion(0x00000001),
                                }
                            ],
                            length_options: 0x18,
                            options_array: Some(vec![
                                SomeIpSdOption {
                                    length: 0x0009,
                                    sd_option_type: SomeIpSdOptionType::IPv4_EndPoint,
                                    ipv4_addr: Ipv4Addr::from_str("192.168.132.131").unwrap(),
                                    l4_protocol: 0x06,
                                },
                                SomeIpSdOption {
                                    length: 0x0009,
                                    sd_option_type: SomeIpSdOptionType::IPv4_EndPoint,
                                    ipv4_addr: Ipv4Addr::from_str("192.168.132.131").unwrap(),
                                    l4_protocol: 0x11,
                                },
                            ]),
                        })
                    },
                    Err(_) => {
                        panic!("should not reach here")
                    }
                }
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    const SOME_IP_SD_SUBSCRIBE: &[u8] = &[
                    0xff, 0xff, 0x81, 0x00, 0x00, 0x00,
        0x00, 0x4c, 0x00, 0x00, 0x00, 0x18, 0x01, 0x01,
        0x02, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x06, 0x00, 0x00, 0x20, 0x00, 0x58,
        0x00, 0x63, 0x01, 0x01, 0x51, 0x80, 0x00, 0x00,
        0x00, 0x01, 0x06, 0x00, 0x00, 0x20, 0x00, 0x58,
        0x00, 0x63, 0x01, 0x01, 0x51, 0x80, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x18, 0x00, 0x09,
        0x04, 0x00, 0xc0, 0xa8, 0x84, 0x82, 0x00, 0x06,
        0xb9, 0x42, 0x00, 0x09, 0x04, 0x00, 0xc0, 0xa8,
        0x84, 0x82, 0x00, 0x11, 0xb2, 0x3c
    ];
    #[test]
    fn test_parse_some_ip_sd_subscribe() {
        match parse_some_ip_header(SOME_IP_SD_SUBSCRIBE) {
            Ok((rem, header)) => {
                assert_eq!(header, SomeIPHeader {
                    message_id: MessageID::from_u32(0xFFFF8100).unwrap(),
                    length: 0x4c,
                    request_id: RequestID::from_u32(0x00000018).unwrap(),
                    protocol_version: 0x01,
                    interface_version: 0x01,
                    message_type: MessageType::from_u8(0x02).unwrap(),
                    return_code: 0x00,
                });
                match parse_some_ip_sd_header(rem) {
                    Ok((rem, sd_header)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(sd_header, SomeIpSdHeader {
                            flags: 0xc0,
                            length_entries: 0x20,
                            entries_array: vec![
                                SomeIpSdEntry {
                                    entry_type: 0x06,
                                    index_1st_options: 0x00,
                                    index_2nd_options: 0x00,
                                    num_of_option_1: 0x02,
                                    num_of_option_2: 0x00,
                                    service_id: 0x0058,
                                    instance_id: 0x0063,
                                    major_version: 0x01,
                                    ttl: 86400,
                                    last_item: SomeIpSdEntryLastItem::EventGroup(SomeIpSdEntrySubscribeEventGroup {
                                        reserved: 0x00,
                                        initial_data_request_flag: 0x00,
                                        eventgroup_id: 0x0001,
                                    }),
                                },
                                SomeIpSdEntry {
                                    entry_type: 0x06,
                                    index_1st_options: 0x00,
                                    index_2nd_options: 0x00,
                                    num_of_option_1: 0x02,
                                    num_of_option_2: 0x00,
                                    service_id: 0x0058,
                                    instance_id: 0x0063,
                                    major_version: 0x01,
                                    ttl: 86400,
                                    last_item: SomeIpSdEntryLastItem::EventGroup(SomeIpSdEntrySubscribeEventGroup {
                                        reserved: 0x00,
                                        initial_data_request_flag: 0x00,
                                        eventgroup_id: 0x0002,
                                    }),
                                }
                            ],
                            length_options: 0x18,
                            options_array: Some(vec![
                                SomeIpSdOption {
                                    length: 0x0009,
                                    sd_option_type: SomeIpSdOptionType::IPv4_EndPoint,
                                    ipv4_addr: Ipv4Addr::from_str("192.168.132.130").unwrap(),
                                    l4_protocol: 0x06,
                                },
                                SomeIpSdOption {
                                    length: 0x0009,
                                    sd_option_type: SomeIpSdOptionType::IPv4_EndPoint,
                                    ipv4_addr: Ipv4Addr::from_str("192.168.132.130").unwrap(),
                                    l4_protocol: 0x11,
                                },
                            ]),
                        })
                    },
                    Err(_) => {
                        panic!("should not reach here")
                    }
                }
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    const SOME_IP_SD_SUBSCRIBE_ACK: &[u8] = &[
                    0xff, 0xff, 0x81, 0x00, 0x00, 0x00,
        0x00, 0x40, 0x00, 0x00, 0x00, 0x1f, 0x01, 0x01,
        0x02, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x07, 0x00, 0x00, 0x00, 0x00, 0x58,
        0x00, 0x63, 0x01, 0x01, 0x51, 0x80, 0x00, 0x00,
        0x00, 0x01, 0x07, 0x00, 0x00, 0x10, 0x00, 0x58,
        0x00, 0x63, 0x01, 0x01, 0x51, 0x80, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x09,
        0x14, 0x00, 0xef, 0xff, 0x00, 0x01, 0x00, 0x11,
        0x77, 0x26
    ];
    #[test]
    fn test_parse_some_ip_sd_subscirbe_ack() {
        match parse_some_ip_header(SOME_IP_SD_SUBSCRIBE_ACK) {
            Ok((rem, header)) => {
                assert_eq!(header, SomeIPHeader {
                    message_id: MessageID::from_u32(0xFFFF8100).unwrap(),
                    length: 0x40,
                    request_id: RequestID::from_u32(0x0000001f).unwrap(),
                    protocol_version: 0x01,
                    interface_version: 0x01,
                    message_type: MessageType::from_u8(0x02).unwrap(),
                    return_code: 0x00,
                });
                match parse_some_ip_sd_header(rem) {
                    Ok((rem, sd_header)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(sd_header, SomeIpSdHeader {
                            flags: 0xc0,
                            length_entries: 0x20,
                            entries_array: vec![
                                SomeIpSdEntry {
                                    entry_type: 0x07,
                                    index_1st_options: 0x00,
                                    index_2nd_options: 0x00,
                                    num_of_option_1: 0x00,
                                    num_of_option_2: 0x00,
                                    service_id: 0x0058,
                                    instance_id: 0x0063,
                                    major_version: 0x01,
                                    ttl: 86400,
                                    last_item: SomeIpSdEntryLastItem::EventGroup(SomeIpSdEntrySubscribeEventGroup {
                                        reserved: 0x00,
                                        initial_data_request_flag: 0x00,
                                        eventgroup_id: 0x0001,
                                    }),
                                },
                                SomeIpSdEntry {
                                    entry_type: 0x07,
                                    index_1st_options: 0x00,
                                    index_2nd_options: 0x00,
                                    num_of_option_1: 0x01,
                                    num_of_option_2: 0x00,
                                    service_id: 0x0058,
                                    instance_id: 0x0063,
                                    major_version: 0x01,
                                    ttl: 86400,
                                    last_item: SomeIpSdEntryLastItem::EventGroup(SomeIpSdEntrySubscribeEventGroup {
                                        reserved: 0x00,
                                        initial_data_request_flag: 0x00,
                                        eventgroup_id: 0x0002,
                                    }),
                                }
                            ],
                            length_options: 0x0c,
                            options_array: Some(vec![
                                SomeIpSdOption {
                                    length: 0x0009,
                                    sd_option_type: SomeIpSdOptionType::Ipv4_MultiCast,
                                    ipv4_addr: Ipv4Addr::from_str("239.255.0.1").unwrap(),
                                    l4_protocol: 0x11,
                                }
                            ]),
                        });
                    },
                    Err(_) => {
                        panic!("should not reach here")
                    }
                }
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }
    const SOME_IP_REQUEST: &[u8] = &[
                    0x00, 0x58, 0x00, 0x17, 0x00, 0x00,
        0x00, 0x38, 0x00, 0x67, 0x00, 0x03, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x2e, 0x40, 0x01, 0x00, 0x20,
        0x00, 0x1e, 0xfe, 0xff, 0x00, 0x48, 0x00, 0x65,
        0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x2c,
        0x00, 0x20, 0x00, 0x77, 0x00, 0x6f, 0x00, 0x72,
        0x00, 0x6c, 0x00, 0x64, 0x00, 0x21, 0x00, 0x00,
        0x40, 0x02, 0x00, 0x06, 0x00, 0x04, 0x10, 0x20,
        0x30, 0x40
    ];
    #[test]
    fn test_parse_some_ip_request() {
        match parse_some_ip_header(SOME_IP_REQUEST) {
            Ok((rem, header)) => {
                assert_eq!(header, SomeIPHeader {
                    message_id: MessageID::from_u32(0x00580017).unwrap(),
                    length: 0x38,
                    request_id: RequestID::from_u32(0x00670003).unwrap(),
                    protocol_version: 0x01,
                    interface_version: 0x01,
                    message_type: MessageType::from_u8(0x00).unwrap(),
                    return_code: 0x00,
                });
                assert_eq!(rem.len(), (header.length - 8) as usize);
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    const SOME_IP_RESPONSE: &[u8] = &[
                    0x00, 0x58, 0x00, 0x17, 0x00, 0x00,
        0x00, 0x37, 0x00, 0x67, 0x00, 0x03, 0x01, 0x01,
        0x80, 0x00, 0x01, 0x00, 0x2c, 0xfe, 0xff, 0x00,
        0x77, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x63, 0x00,
        0x6f, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x20, 0x00,
        0x74, 0x00, 0x6f, 0x00, 0x20, 0x00, 0x73, 0x00,
        0x68, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x79, 0x00,
        0x61, 0x00, 0x6e, 0x00, 0x67, 0x00, 0x21, 0x00,
        0x00
    ];
    #[test]
    fn test_parse_some_ip_response() {
        match parse_some_ip_header(SOME_IP_RESPONSE) {
            Ok((rem, header)) => {
                assert_eq!(header, SomeIPHeader {
                    message_id: MessageID::from_u32(0x00580017).unwrap(),
                    length: 0x37,
                    request_id: RequestID::from_u32(0x00670003).unwrap(),
                    protocol_version: 0x01,
                    interface_version: 0x01,
                    message_type: MessageType::from_u8(0x80).unwrap(),
                    return_code: 0x00,
                });
                assert_eq!(rem.len(), (header.length - 8) as usize);
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    const SOME_IP_REQUEST_NO_RETURN: &[u8] = &[
                    0x00, 0x58, 0x00, 0x1c, 0x00, 0x00,
        0x00, 0x0c, 0x00, 0x67, 0x00, 0x04, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x01
    ];
    #[test]
    fn test_parse_some_ip_request_no_return() {
        match parse_some_ip_header(SOME_IP_REQUEST_NO_RETURN) {
            Ok((rem, header)) => {
                assert_eq!(header, SomeIPHeader {
                    message_id: MessageID::from_u32(0x0058001c).unwrap(),
                    length: 0x0c,
                    request_id: RequestID::from_u32(0x00670004).unwrap(),
                    protocol_version: 0x01,
                    interface_version: 0x01,
                    message_type: MessageType::from_u8(0x01).unwrap(),
                    return_code: 0x00,
                });
                assert_eq!(rem.len(), (header.length - 8) as usize);
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }
}
