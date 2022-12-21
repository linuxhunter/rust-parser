use nom7::ErrorConvert;
use nom7::error::{ParseError, Error};
use nom7::number::complete::{be_u8, be_u16};
use nom7::sequence::tuple;
use nom7::{IResult, bytes::complete::take_while_m_n};
use nom7::combinator::verify;
use nom7::bits::streaming::take;
use nom7::multi::length_data;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum MQTTTypeCode {
    UNASSIGNED = 0,
    CONNECT = 1,
    CONNACK = 2,
    PUBLISH = 3,
    PUBACK = 4,
    PUBREC = 5,
    PUBREL = 6,
    PUBCOMP = 7,
    SUBSCRIBE = 8,
    SUBACK = 9,
    UNSUBSCRIBE = 10,
    UNSUBACK = 11,
    PINGREQ = 12,
    PINGRESP = 13,
    DISCONNECT = 14,
    AUTH = 15,
}

impl std::fmt::Display for MQTTTypeCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl MQTTTypeCode {
    pub fn from_u8(code: u8) -> Self {
        match code {
            0 => MQTTTypeCode::UNASSIGNED,
            1 => MQTTTypeCode::CONNECT,
            2 => MQTTTypeCode::CONNACK,
            3 => MQTTTypeCode::PUBLISH,
            4 => MQTTTypeCode::PUBACK,
            5 => MQTTTypeCode::PUBREC,
            6 => MQTTTypeCode::PUBREL,
            7 => MQTTTypeCode::PUBCOMP,
            8 => MQTTTypeCode::SUBSCRIBE,
            9 => MQTTTypeCode::SUBACK,
            10 => MQTTTypeCode::UNSUBSCRIBE,
            11 => MQTTTypeCode::UNSUBACK,
            12 => MQTTTypeCode::PINGREQ,
            13 => MQTTTypeCode::PINGRESP,
            14 => MQTTTypeCode::DISCONNECT,
            15 => MQTTTypeCode::AUTH,
            _ => MQTTTypeCode::UNASSIGNED,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct FixedHeader {
    pub message_type: MQTTTypeCode,
    pub dup_flag: bool,
    pub qos_level: u8,
    pub retain: bool,
    pub remaining_length: u32,
}

#[derive(Debug, PartialEq)]
pub struct MQTTConnectData {
    pub protocol_name: String,
    pub protocol_version: u8,
    pub username_flag: bool,
    pub password_flag: bool,
    pub will_retain: bool,
    pub qos_level: u8,
    pub will_flag: bool,
    pub clean_session_flag: bool,
    pub keep_alive: u16,
    pub client_id: String,
}

#[derive(Debug, PartialEq)]
pub struct MQTTConnectAck {
    return_code: u8,
}

#[derive(Debug, PartialEq)]
pub struct MQTTSubscribeRequest {
    message_identifier: u16,
    topic: String,
    requested_qos: u8,
}

#[derive(Debug, PartialEq)]
pub struct MQTTSubscribeAck {
    message_identifier: u16,
    granted_qos: u8,
}

#[derive(Debug, PartialEq)]
pub struct MQTTPublishMessage {
    topic: String,
    message: Vec<u8>,
}

pub fn is_continue_bit_set(val: u8) -> bool {
    (val & 0x80) != 0
}

pub fn convert_variant(continued_part: Vec<u8>, non_continued_part: u8) -> u32 {
    let mut multiplier = 1u32;
    let mut result = 0u32;
    for part in continued_part {
        result += (part & 0x7F) as u32 * multiplier;
        multiplier *= 0x80;
    }
    result += (non_continued_part & 0x7F) as u32 * multiplier;
    result
}

pub fn parse_mqtt_variable_integer(input: &[u8]) -> IResult<&[u8], u32> {
    let (rem, continued_part) = take_while_m_n(0, 3, is_continue_bit_set)(input)?;
    let (rem, non_continued_part) = verify(be_u8, |&val| !is_continue_bit_set(val))(rem)?;
    Ok((rem, convert_variant(continued_part.to_vec(), non_continued_part)))
}

pub fn my_bits<'a, O, E, P>(parser: P) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>
    where
        E: ParseError<&'a [u8]>,
        Error<(&'a [u8], usize)>: ErrorConvert<E>,
        P: FnMut((&'a [u8], usize)) -> IResult<(&'a [u8], usize), O, Error<(&'a [u8], usize)>>,
{
    // use full path to disambiguate nom `bits` from this current function name
    nom7::bits::bits(parser)
}

#[inline]
pub fn parse_fixed_header_flags(input: &[u8]) -> IResult<&[u8], (u8, u8, u8, u8)> {
    my_bits(tuple((
        take(4u8),
        take(1u8),
        take(2u8),
        take(1u8),
    )))(input)
}

pub fn parse_connect_flags(input: &[u8]) -> IResult<&[u8], (u8, u8, u8, u8, u8, u8, u8)> {
    my_bits(tuple((
        take(1u8),
        take(1u8),
        take(1u8),
        take(2u8),
        take(1u8),
        take(1u8),
        take(1u8),
    )))(input)
}

pub fn parse_message_type(code: u8) -> MQTTTypeCode {
    match code {
        0..=15 => {
            MQTTTypeCode::from_u8(code)
        },
        _ => {
            MQTTTypeCode::UNASSIGNED
        }
    }
}

pub fn parse_fixed_header(input: &[u8]) -> IResult<&[u8], FixedHeader> {
    let (rem, flags) = parse_fixed_header_flags(input)?;
    let (rem, remaining_length) = parse_mqtt_variable_integer(rem)?;
    Ok((rem, FixedHeader {
        message_type: parse_message_type(flags.0),
        dup_flag: flags.1 != 0,
        qos_level: flags.2,
        retain: flags.3 != 0,
        remaining_length,
    }))
}

pub fn parse_connect_command(input: &[u8]) -> IResult<&[u8], MQTTConnectData> {
    let (rem, protocol_name) = length_data(be_u16)(input)?;
    let (rem, protocol_version) = be_u8(rem)?;
    let (rem, flags) = parse_connect_flags(rem)?;
    let (rem, keep_alive) = be_u16(rem)?;
    let (rem, client_id) = length_data(be_u16)(rem)?;
    Ok((rem, MQTTConnectData {
        protocol_name: String::from_utf8(protocol_name.to_vec()).unwrap(),
        protocol_version: protocol_version,
        username_flag: flags.0 != 0,
        password_flag: flags.1 != 0,
        will_retain: flags.2 != 0,
        qos_level: flags.3,
        will_flag: flags.4 != 0,
        clean_session_flag: flags.5 != 0,
        keep_alive: keep_alive,
        client_id: String::from_utf8(client_id.to_vec()).unwrap(),
    }))
}

pub fn parse_connect_ack(input: &[u8]) -> IResult<&[u8], MQTTConnectAck> {
    let (rem, _) = be_u8(input)?;
    let (rem, return_code) = be_u8(rem)?;
    Ok((rem, MQTTConnectAck {
        return_code,
    }))
}

pub fn parse_subscribe_request(input: &[u8]) -> IResult<&[u8], MQTTSubscribeRequest> {
    let (rem, message_identifier) = be_u16(input)?;
    let (rem, topic) = length_data(be_u16)(rem)?;
    let (rem, requested_qos) = be_u8(rem)?;
    Ok((rem, MQTTSubscribeRequest {
        message_identifier,
        topic: String::from_utf8(topic.to_vec()).unwrap(),
        requested_qos,
    }))
}

pub fn parse_subscribe_ack(input: &[u8]) -> IResult <&[u8], MQTTSubscribeAck> {
    let (rem, message_identifier) = be_u16(input)?;
    let (rem, granted_qos) = be_u8(rem)?;
    Ok((rem, MQTTSubscribeAck {
        message_identifier,
        granted_qos,
    }))
}

pub fn parse_publish_message(input: &[u8]) -> IResult<&[u8], MQTTPublishMessage> {
    let (mut rem, topic) = length_data(be_u16)(input)?;
    let message = rem.to_vec();
    rem = &rem[rem.len()..];
    Ok((rem, MQTTPublishMessage {
        topic: String::from_utf8(topic.to_vec()).unwrap(),
        message: message,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom7::error::ErrorKind;
    use nom7::Err;

    #[test]
    fn test_parse_mqtt_variable_integer() {
        let result = parse_mqtt_variable_integer(&[0xFF, 0xFF, 0xFF, 0x7F]);
        match result {
            Ok((rem, value)) => {
                assert_eq!(rem.len() , 0);
                assert_eq!(value, 268435455);
            },
            Err(_) => {
                panic!("Result should have been OK");
            }
        }
    }
    #[test]
    fn test_parse_mqtt_variable_integer2() {
        let result = parse_mqtt_variable_integer(&[0xFF, 0xFF, 0xFF, 0xFF]);
        match result {
            Ok((_, _)) => {
                panic!("Result should not have been ok");
            },
            Err(Err::Error(err)) => {
                assert_eq!(err.code, ErrorKind::Verify);
            },
            _ => {
                panic!("no no no");
            }
        }
    }
    #[test]
    fn test_parse_mqtt_variable_integer3() {
        let result = parse_mqtt_variable_integer(&[0x00]);
        match result {
            Ok((rem, value)) => {
                assert_eq!(rem.len() , 0);
                assert_eq!(value, 0u32);
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }
    #[test]
    fn test_parse_mqtt_variable_integer4() {
        let result = parse_mqtt_variable_integer(&[0xFF, 0xFF, 0xFF, 0x80]);
        match result {
            Ok((_, _)) => {
                panic!("no no no");
            },
            Err(Err::Error(err)) => {
                assert_eq!(err.code, ErrorKind::Verify);
            },
            _ => {
                panic!("no no no");
            }
        }
    }
    #[test]
    fn test_parse_fix_header_connect_command() {
        let result = parse_fixed_header(&[0x10, 0x25]);
        match result {
            Ok((rem, header)) => {
                assert_eq!(rem.len() , 0);
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::CONNECT,
                    dup_flag: false,
                    qos_level: 0,
                    retain: false,
                    remaining_length: 37u32,
                });
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }
    #[test]
    fn test_parse_fix_header_connect_ack() {
        let result = parse_fixed_header(&[0x20, 0x02]);
        match result {
            Ok((rem, header)) => {
                assert_eq!(rem.len() , 0);
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::CONNACK,
                    dup_flag: false,
                    qos_level: 0,
                    retain: false,
                    remaining_length: 2u32,
                });
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }
    #[test]
    fn test_parse_fix_header_subscribe_request() {
        let result = parse_fixed_header(&[0x82, 0x10]);
        match result {
            Ok((rem, header)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::SUBSCRIBE,
                    dup_flag: false,
                    qos_level: 1,
                    retain: false,
                    remaining_length: 16u32,
                });
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }
    #[test]
    fn test_parse_fix_header_publish_message() {
        let result = parse_fixed_header(&[0x31, 0x30]);
        match result {
            Ok((rem, header)) => {
                assert_eq!(rem.len() , 0);
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::PUBLISH,
                    dup_flag: false,
                    qos_level: 0,
                    retain: true,
                    remaining_length: 48u32,
                });
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }
    #[test]
    fn test_parse_fix_header_ping_request() {
        let result = parse_fixed_header(&[0xc0, 0x00]);
        match result {
            Ok((rem, header)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::PINGREQ,
                    dup_flag: false,
                    qos_level: 0,
                    retain: false,
                    remaining_length: 0,
                });
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }
    #[test]
    fn test_parse_fix_header_ping_response() {
        let result = parse_fixed_header(&[0xd0, 0x00]);
        match result {
            Ok((rem, header)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::PINGRESP,
                    dup_flag: false,
                    qos_level: 0,
                    retain: false,
                    remaining_length: 0,
                });
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }
    #[test]
    fn test_parse_fix_header_publish_message2() {
        let result = parse_fixed_header(&[0x30, 0x17]);
        match result {
            Ok((rem, header)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::PUBLISH,
                    dup_flag: false,
                    qos_level: 0,
                    retain: false,
                    remaining_length: 23,
                });
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }
    const MQTT_CONNECT_COMMAND: &[u8] = &[
                    0x10, 0x25, 0x00, 0x06, 0x4d, 0x51,
        0x49, 0x73, 0x64, 0x70, 0x03, 0x02, 0x00, 0x05,
        0x00, 0x17, 0x70, 0x61, 0x68, 0x6f, 0x2f, 0x33,
        0x34, 0x41, 0x41, 0x45, 0x35, 0x34, 0x41, 0x37,
        0x35, 0x44, 0x38, 0x33, 0x39, 0x35, 0x36, 0x36,
        0x45,
    ];
    #[test]
    fn test_parse_connect_command() {
        let result = parse_fixed_header(MQTT_CONNECT_COMMAND);
        match result {
            Ok((rem, header)) => {
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::CONNECT,
                    dup_flag: false,
                    qos_level: 0,
                    retain: false,
                    remaining_length: 37u32,
                });
                match header.message_type {
                    MQTTTypeCode::CONNECT => {
                        let result = parse_connect_command(rem);
                        match result {
                            Ok((rem, message)) => {
                                assert_eq!(rem.len(), 0);
                                assert_eq!(message, MQTTConnectData {
                                    protocol_name: String::from("MQIsdp"),
                                    protocol_version: 3u8,
                                    username_flag: false,
                                    password_flag: false,
                                    will_retain: false,
                                    qos_level: 0,
                                    will_flag: false,
                                    clean_session_flag: true,
                                    keep_alive: 5u16,
                                    client_id: String::from("paho/34AAE54A75D839566E"),
                                });
                            },
                            Err(_) => {
                                panic!(" no no no");
                            }
                        }
                    },
                    _ => {
                        panic!("no no no");
                    }
                }
            },
            Err(_) => {
                panic!("no no no");
            }
        }

    }
    const MQTT_CONNECT_ACK: &[u8] = &[0x20, 0x02, 0x00, 0x00];
    #[test]
    fn test_parse_connect_ack() {
        let result = parse_fixed_header(MQTT_CONNECT_ACK);
        match result {
            Ok((rem, header)) => {
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::CONNACK,
                    dup_flag: false,
                    qos_level: 0,
                    retain: false,
                    remaining_length: 2u32,
                });
                let result = parse_connect_ack(rem);
                match result {
                    Ok((rem, message)) => {
                        assert_eq!(rem.len() , 0);
                        assert_eq!(message, MQTTConnectAck {
                            return_code: 0u8,
                        });
                    },
                    Err(_) => {
                        panic!("no no no");
                    }
                }
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }
    const MQTT_SUBSCRIBE_REQUEST: &[u8] = &[
                    0x82, 0x10, 0x00, 0x01, 0x00, 0x0b,
        0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x6f,
        0x70, 0x69, 0x63, 0x00,
    ];
    #[test]
    fn test_parse_subscribe_request() {
        let result = parse_fixed_header(MQTT_SUBSCRIBE_REQUEST);
        match result {
            Ok((rem, header)) => {
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::SUBSCRIBE,
                    dup_flag: false,
                    qos_level: 1u8,
                    retain: false,
                    remaining_length: 16u32,
                });
                let result = parse_subscribe_request(rem);
                match result {
                    Ok((rem, message)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(message, MQTTSubscribeRequest {
                            message_identifier: 1u16,
                            topic: String::from("SampleTopic"),
                            requested_qos: 0u8,
                        });
                    },
                    Err(_) => {
                        panic!("no no no");
                    }
                }
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }

    const MQTT_SUBSCRIBE_ACK: &[u8] = &[0x90, 0x03, 0x00, 0x01, 0x00];
    #[test]
    fn test_parse_subscribe_ack() {
        let result = parse_fixed_header(MQTT_SUBSCRIBE_ACK);
        match result {
            Ok((rem, header)) => {
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::SUBACK,
                    dup_flag: false,
                    qos_level: 0,
                    retain: false,
                    remaining_length: 3,
                });
                let result = parse_subscribe_ack(rem);
                match result {
                    Ok((rem, message)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(message, MQTTSubscribeAck {
                            message_identifier: 1u16,
                            granted_qos: 0u8,
                        });
                    },
                    Err(_) => {
                        panic!("no no no");
                    }
                }
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }

    const MQTT_PUBLISH_MESSAGE: &[u8] = &[
                    0x31, 0x30, 0x00, 0x0b, 0x53, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x54, 0x6f, 0x70, 0x69,
        0x63, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66,
        0x72, 0x6f, 0x6d, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x50, 0x61, 0x68, 0x6f, 0x20, 0x62, 0x6c, 0x6f,
        0x63, 0x6b, 0x69, 0x6e, 0x67, 0x20, 0x63, 0x6c,
        0x69, 0x65, 0x6e, 0x74
    ];
    #[test]
    fn test_parse_publish_message() {
        let result = parse_fixed_header(MQTT_PUBLISH_MESSAGE);
        match result {
            Ok((rem, header)) => {
                assert_eq!(header, FixedHeader {
                    message_type: MQTTTypeCode::PUBLISH,
                    dup_flag: false,
                    qos_level: 0,
                    retain: true,
                    remaining_length: 48u32,
                });
                let result = parse_publish_message(rem);
                match result {
                    Ok((rem, message)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(message, MQTTPublishMessage {
                            topic: String::from("SampleTopic"),
                            message: vec![0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66,
                                    0x72, 0x6f, 0x6d, 0x20, 0x74, 0x68, 0x65, 0x20,
                                    0x50, 0x61, 0x68, 0x6f, 0x20, 0x62, 0x6c, 0x6f,
                                    0x63, 0x6b, 0x69, 0x6e, 0x67, 0x20, 0x63, 0x6c,
                                    0x69, 0x65, 0x6e, 0x74],
                        });
                    },
                    Err(_) => {
                        panic!("no no no");
                    }
                }
            },
            Err(_) => {
                panic!("no no no");
            }
        }
    }
}