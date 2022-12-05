use nom7::{IResult, number::complete::{be_u32, be_u8, be_u16, be_u24}, combinator::map_res, Err, error::{make_error, ErrorKind}, sequence::tuple};

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
    minor_version: u32,
}

#[derive(Debug, PartialEq)]
pub struct SomeIpSdHeader {
    flags: u8,
    length_entries: u32,
    entries_array: Vec<SomeIpSdEntry>,
    length_options: u32,
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
            minor_version
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
            minor_version,
        });
        rem = tmp_rem;
    }
    Ok((rem, entries))
}

pub fn parse_some_ip_sd_header(input: &[u8]) -> IResult<&[u8], SomeIpSdHeader> {
    let (rem, flags) = be_u8(input)?;
    let (rem, _) = be_u24(rem)?;
    let (rem, length_entries) = be_u32(rem)?;
    let (rem, entries_array) = parse_some_ip_sd_entries(rem, length_entries)?;
    let (rem, length_options) = be_u32(rem)?;
    Ok((rem, SomeIpSdHeader {
        flags,
        length_entries,
        entries_array,
        length_options,
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
                        assert_eq!(rem.len(), sd_header.length_options as usize);
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
                                    minor_version: 0x01,
                                }
                            ],
                            length_options: 0x18,
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
}