use nom7::{IResult, number::complete::{be_u8, be_u16, be_u32}, bytes::complete::take, multi::length_data, combinator::map_res};
use std::str::FromStr;

pub const DHCP_OPT_SUBNET_MASK: u8 = 0x01;
pub const DHCP_OPT_MESSAGE_TYPE: u8 = 0x35;
pub const DHCP_OPT_CLIENT_ID: u8 = 0x3d;
pub const DHCP_OPT_REQUESTED_IP_ADDRESS: u8 = 0x32;
pub const DHCP_OPT_SERVER_ID: u8 = 0x36;
pub const DHCP_OPT_PARAMETER_REQUEST_LIST: u8 = 0x37;
pub const DHCP_OPT_RENEWAL_TIME_VALUE: u8 = 0x3a;
pub const DHCP_OPT_REBINDING_TIME_VALUE: u8 = 0x3b;
pub const DHCP_OPT_IP_ADDRESS_LEASE_TIME: u8 = 0x33;
pub const DHCP_OPT_END: u8 = 0xff;

#[derive(Debug, PartialEq)]
pub struct DHCPHeader {
    opcode: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    txid: u32,
    seconds: u16,
    flags: u16,
    ciaddr: Vec<u8>,
    yiaddr: Vec<u8>,
    siaddr: Vec<u8>,
    giaddr: Vec<u8>,
    chaddr: Vec<u8>,
    sname: Vec<u8>,
    bootfilename: Vec<u8>,
    magic: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct DHCPOptSubnetMask {
    subnet_mask: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct DHCPOptMessageType {
    message_type: u8,
}

#[derive(Debug, PartialEq)]
pub struct DHCPOptClientId {
    hardware_type: u8,
    client_mac_address: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct DHCPOptRequestedIpAddress {
    requested_ip_address: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct DHCPOptParameterRequestList {
    parameter_request_list: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct DHCPOptServerId {
    dhcp_server_id: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct DHCPOptTimeValue {
    seconds: u32,
}

#[derive(Debug, PartialEq)]
pub struct DHCPOptGeneric {
    generic: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum DHCPOptionWrapper {
    SubnetMask(DHCPOptSubnetMask),
    MessageType(DHCPOptMessageType),
    ClientId(DHCPOptClientId),
    RequestedIpAddress(DHCPOptRequestedIpAddress),
    ParameterRequestList(DHCPOptParameterRequestList),
    ServerId(DHCPOptServerId),
    TimeValue(DHCPOptTimeValue),
    Generic(DHCPOptGeneric),
    End,
}

#[derive(Debug, PartialEq)]
pub struct DHCPOption {
    code: u8,
    option: DHCPOptionWrapper,
    data: Option<Vec<u8>>,
}

pub fn parse_dhcp_header(input: &[u8]) -> IResult<&[u8], DHCPHeader> {
    let (rem, opcode) = be_u8(input)?;
    let (rem, htype) = be_u8(rem)?;
    let (rem, hlen) = be_u8(rem)?;
    let (rem, hops) = be_u8(rem)?;
    let (rem, txid) = be_u32(rem)?;
    let (rem, seconds) = be_u16(rem)?;
    let (rem, flags) = be_u16(rem)?;
    let (rem, ciaddr) = take(4usize)(rem)?;
    let (rem, yiaddr) = take(4usize)(rem)?;
    let (rem, siaddr) = take(4usize)(rem)?;
    let (rem, giaddr) = take(4usize)(rem)?;
    let (rem, chaddr) = take(16usize)(rem)?;
    let (rem, sname) = take(64usize)(rem)?;
    let (rem, bootfilename) = take(128usize)(rem)?;
    let (rem, magic) = take(4usize)(rem)?;
    Ok((rem, DHCPHeader {
        opcode,
        htype,
        hlen,
        hops,
        txid,
        seconds,
        flags,
        ciaddr: ciaddr.to_vec(),
        yiaddr: yiaddr.to_vec(),
        siaddr: siaddr.to_vec(),
        giaddr: giaddr.to_vec(),
        chaddr: chaddr.to_vec(),
        sname: sname.to_vec(),
        bootfilename: bootfilename.to_vec(),
        magic: magic.to_vec(),
    }))
}

pub fn parse_u8(input: &[u8]) -> IResult<&[u8], u8> {
    be_u8(input)
}

pub fn parse_u32(input: &[u8]) -> IResult<&[u8], u32> {
    be_u32(input)
}

pub fn parse_dhcp_option_subnet_mask(input: &[u8]) -> IResult<&[u8], DHCPOptionWrapper> {
    let (rem, subnet_mask) = length_data(be_u8)(input)?;
    Ok((rem, DHCPOptionWrapper::SubnetMask(DHCPOptSubnetMask {
        subnet_mask: subnet_mask.to_vec(),
    })))
}

pub fn parse_dhcp_option_message_type(input: &[u8]) -> IResult<&[u8], DHCPOptionWrapper> {
    let (rem, message_type) = map_res(length_data(be_u8), parse_u8)(input)?;
    Ok((rem, DHCPOptionWrapper::MessageType(DHCPOptMessageType {
        message_type: message_type.1
    })))
}

pub fn parse_dhcp_option_client_id(input: &[u8]) -> IResult<&[u8], DHCPOptionWrapper> {
    let (rem, length) = be_u8(input)?;
    let (rem, hardware_type) = be_u8(rem)?;
    let (rem, client_mac_address) = take((length - 1) as usize)(rem)?;
    Ok((rem, DHCPOptionWrapper::ClientId(DHCPOptClientId {
        hardware_type,
        client_mac_address: client_mac_address.to_vec(),
    })))
}

pub fn parse_dhcp_option_requested_ip_address(input: &[u8]) -> IResult<&[u8], DHCPOptionWrapper> {
    let (rem, requested_ip_address) = length_data(be_u8)(input)?;
    Ok((rem, DHCPOptionWrapper::RequestedIpAddress(DHCPOptRequestedIpAddress {
        requested_ip_address: requested_ip_address.to_vec(),
    })))
}

pub fn parse_dhcp_option_parameter_request_list(input: &[u8]) -> IResult<&[u8], DHCPOptionWrapper> {
    let (rem, parameter_request_list) = length_data(be_u8)(input)?;
    Ok((rem, DHCPOptionWrapper::ParameterRequestList(DHCPOptParameterRequestList {
        parameter_request_list: parameter_request_list.to_vec(),
    })))
}

pub fn parse_dhcp_option_dhcp_server_id(input: &[u8]) -> IResult<&[u8], DHCPOptionWrapper> {
    let (rem, dhcp_server_id) = length_data(be_u8)(input)?;
    Ok((rem, DHCPOptionWrapper::ServerId(DHCPOptServerId {
        dhcp_server_id: dhcp_server_id.to_vec(),
    })))
}

pub fn parse_dhcp_option_time_value(input: &[u8]) -> IResult<&[u8], DHCPOptionWrapper> {
    let (rem, seconds) = map_res(length_data(be_u8), parse_u32)(input)?;
    Ok((rem, DHCPOptionWrapper::TimeValue(DHCPOptTimeValue {
        seconds: seconds.1
    })))
}

pub fn parse_dhcp_option_generic(input: &[u8]) -> IResult<&[u8], DHCPOptionWrapper> {
    let (rem, data) = length_data(be_u8)(input)?;
    Ok((rem, DHCPOptionWrapper::Generic(DHCPOptGeneric {
        generic: data.to_vec(),
    })))
}

pub fn parse_dhcp_option(input: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (rem, code) = be_u8(input)?;
    match code {
        DHCP_OPT_SUBNET_MASK => {
            let (rem, option) = parse_dhcp_option_subnet_mask(rem)?;
            return Ok((rem, DHCPOption {
                code,
                option,
                data: None,
            }));
        }
        DHCP_OPT_MESSAGE_TYPE => {
            let (rem, option) = parse_dhcp_option_message_type(rem)?;
            return Ok((rem, DHCPOption {
                code,
                option,
                data: None,
            }));
        },
        DHCP_OPT_CLIENT_ID => {
            let (rem, option) = parse_dhcp_option_client_id(rem)?;
            return Ok((rem, DHCPOption {
                code,
                option,
                data: None,
            }))
        },
        DHCP_OPT_REQUESTED_IP_ADDRESS => {
            let (rem, option) = parse_dhcp_option_requested_ip_address(rem)?;
            return Ok((rem, DHCPOption {
                code,
                option,
                data: None,
            }))
        },
        DHCP_OPT_SERVER_ID => {
            let (rem, option) = parse_dhcp_option_dhcp_server_id(rem)?;
            return Ok((rem, DHCPOption {
                code,
                option,
                data: None,
            }))
        },
        DHCP_OPT_PARAMETER_REQUEST_LIST => {
            let (rem, option) = parse_dhcp_option_parameter_request_list(rem)?;
            return Ok((rem, DHCPOption {
                code,
                option,
                data: None,
            }))
        },
        DHCP_OPT_RENEWAL_TIME_VALUE => {
            let (rem, option) = parse_dhcp_option_time_value(rem)?;
            return Ok((rem, DHCPOption {
                code,
                option,
                data: None,
            }));
        },
        DHCP_OPT_REBINDING_TIME_VALUE => {
            let (rem, option) = parse_dhcp_option_time_value(rem)?;
            return Ok((rem, DHCPOption {
                code,
                option,
                data: None,
            }));
        },
        DHCP_OPT_IP_ADDRESS_LEASE_TIME => {
            let (rem, option) = parse_dhcp_option_time_value(rem)?;
            return Ok((rem, DHCPOption {
                code,
                option,
                data: None,
            }));
        },
        DHCP_OPT_END => {
            return Ok((rem, DHCPOption {
                code,
                option: DHCPOptionWrapper::End,
                data: None,
            }))
        }
        _ => {
            let (rem, option) = parse_dhcp_option_generic(rem)?;
            return Ok((rem, DHCPOption {
                code,
                option,
                data: None,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dhcp_discover() {
        let pcap = include_bytes!("pcaps/dhcp/discover.pcap");
        let payloads = &pcap[24+16+42..];
        match parse_dhcp_header(payloads) {
            Ok((rem, header)) => {
                assert_eq!(header.opcode, 0x01);
                assert_eq!(header.htype, 0x01);
                assert_eq!(header.hlen, 0x06);
                assert_eq!(header.hops, 0x00);
                assert_eq!(header.txid, 0x00003d1d);
                assert_eq!(header.seconds, 0x0000);
                assert_eq!(header.flags, 0x00000);
                assert_eq!(header.ciaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.yiaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.siaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.giaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.chaddr, vec![0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.sname, [0; 64].to_vec());
                assert_eq!(header.bootfilename, [0; 128].to_vec());
                assert_eq!(header.magic, vec![0x63, 0x82, 0x53, 0x63]);
                let mut rem = rem;
                loop {
                    match parse_dhcp_option(rem) {
                        Ok((rem1, option)) => {
                            match option.code {
                                DHCP_OPT_END => {
                                    break;
                                },
                                DHCP_OPT_MESSAGE_TYPE => {
                                    assert_eq!(option.option, DHCPOptionWrapper::MessageType(DHCPOptMessageType {
                                        message_type: 0x01,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_CLIENT_ID => {
                                    assert_eq!(option.option, DHCPOptionWrapper::ClientId(DHCPOptClientId {
                                        hardware_type: 0x01,
                                        client_mac_address: vec![0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42],
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_REQUESTED_IP_ADDRESS => {
                                    assert_eq!(option.option, DHCPOptionWrapper::RequestedIpAddress(DHCPOptRequestedIpAddress {
                                        requested_ip_address: vec![0x00, 0x00, 0x00, 0x00],
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_PARAMETER_REQUEST_LIST => {
                                    assert_eq!(option.option, DHCPOptionWrapper::ParameterRequestList(DHCPOptParameterRequestList {
                                        parameter_request_list: vec![0x01, 0x03, 0x06, 0x2a],
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                _ => {
                                    unimplemented!();
                                }
                            }
                            rem = rem1;
                        },
                        Err(_) => {
                            panic!("should not reach here")
                        }
                    }
                }
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    #[test]
    fn test_parse_dhcp_request() {
        let pcap = include_bytes!("pcaps/dhcp/request.pcap");
        let payloads = &pcap[24+16+42..];
        match parse_dhcp_header(payloads) {
            Ok((rem, header)) => {
                assert_eq!(header.opcode, 0x01);
                assert_eq!(header.htype, 0x01);
                assert_eq!(header.hlen, 0x06);
                assert_eq!(header.hops, 0x00);
                assert_eq!(header.txid, 0x00003d1e);
                assert_eq!(header.seconds, 0x0000);
                assert_eq!(header.flags, 0x00000);
                assert_eq!(header.ciaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.yiaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.siaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.giaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.chaddr, vec![0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.sname, [0; 64].to_vec());
                assert_eq!(header.bootfilename, [0; 128].to_vec());
                assert_eq!(header.magic, vec![0x63, 0x82, 0x53, 0x63]);

                let mut rem = rem;
                loop {
                    match parse_dhcp_option(rem) {
                        Ok((rem1, option)) => {
                            match option.code {
                                DHCP_OPT_END => {
                                    break;
                                },
                                DHCP_OPT_SUBNET_MASK => {
                                    assert_eq!(option.option, DHCPOptionWrapper::SubnetMask(DHCPOptSubnetMask {
                                        subnet_mask: vec![0xff, 0xff, 0xff, 0x00],
                                    }));
                                    assert_eq!(option.data, None);
                                }
                                DHCP_OPT_MESSAGE_TYPE => {
                                    assert_eq!(option.option, DHCPOptionWrapper::MessageType(DHCPOptMessageType {
                                        message_type: 0x03,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_CLIENT_ID => {
                                    assert_eq!(option.option, DHCPOptionWrapper::ClientId(DHCPOptClientId {
                                        hardware_type: 0x01,
                                        client_mac_address: vec![0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42],
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_REQUESTED_IP_ADDRESS => {
                                    assert_eq!(option.option, DHCPOptionWrapper::RequestedIpAddress(DHCPOptRequestedIpAddress {
                                        requested_ip_address: vec![0xc0, 0xa8, 0x00, 0x0a],
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_SERVER_ID => {
                                    assert_eq!(option.option, DHCPOptionWrapper::ServerId(DHCPOptServerId {
                                        dhcp_server_id: vec![0xc0, 0xa8, 0x00, 0x01],
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_RENEWAL_TIME_VALUE => {
                                    assert_eq!(option.option, DHCPOptionWrapper::TimeValue(DHCPOptTimeValue {
                                        seconds: 0x00000708,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_REBINDING_TIME_VALUE => {
                                    assert_eq!(option.option, DHCPOptionWrapper::TimeValue(DHCPOptTimeValue {
                                        seconds: 0x00000c4e,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_IP_ADDRESS_LEASE_TIME => {
                                    assert_eq!(option.option, DHCPOptionWrapper::TimeValue(DHCPOptTimeValue {
                                        seconds: 0x00000e10,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_PARAMETER_REQUEST_LIST => {
                                    assert_eq!(option.option, DHCPOptionWrapper::ParameterRequestList(DHCPOptParameterRequestList {
                                        parameter_request_list: vec![0x01, 0x03, 0x06, 0x2a],
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                _ => {
                                    unimplemented!();
                                }
                            }
                            rem = rem1;
                        },
                        Err(_) => {
                            panic!("should not reach here");
                        }
                    }
                }
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    #[test]
    fn test_parse_dhcp_offer() {
        let pcap = include_bytes!("pcaps/dhcp/offer.pcap");
        let payloads = &pcap[24+16+42..];
        match parse_dhcp_header(payloads) {
            Ok((rem, header)) => {
                assert_eq!(header.opcode, 0x02);
                assert_eq!(header.htype, 0x01);
                assert_eq!(header.hlen, 0x06);
                assert_eq!(header.hops, 0x00);
                assert_eq!(header.txid, 0x00003d1d);
                assert_eq!(header.seconds, 0x0000);
                assert_eq!(header.flags, 0x00000);
                assert_eq!(header.ciaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.yiaddr, vec![0xc0, 0xa8, 0x00, 0x0a]);
                assert_eq!(header.siaddr, vec![0xc0, 0xa8, 0x00, 0x01]);
                assert_eq!(header.giaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.chaddr, vec![0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.sname, [0; 64].to_vec());
                assert_eq!(header.bootfilename, [0; 128].to_vec());
                assert_eq!(header.magic, vec![0x63, 0x82, 0x53, 0x63]);

                let mut rem = rem;
                loop {
                    match parse_dhcp_option(rem) {
                        Ok((rem1, option)) => {
                            match option.code {
                                DHCP_OPT_END => {
                                    break;
                                },
                                DHCP_OPT_MESSAGE_TYPE => {
                                    assert_eq!(option.option, DHCPOptionWrapper::MessageType(DHCPOptMessageType {
                                        message_type: 0x02,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_SUBNET_MASK => {
                                    assert_eq!(option.option, DHCPOptionWrapper::SubnetMask(DHCPOptSubnetMask {
                                        subnet_mask: vec![0xff, 0xff, 0xff, 0x00],
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_RENEWAL_TIME_VALUE => {
                                    assert_eq!(option.option, DHCPOptionWrapper::TimeValue(DHCPOptTimeValue {
                                        seconds: 0x00000708,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_REBINDING_TIME_VALUE => {
                                    assert_eq!(option.option, DHCPOptionWrapper::TimeValue(DHCPOptTimeValue {
                                        seconds: 0x00000c4e,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_IP_ADDRESS_LEASE_TIME => {
                                    assert_eq!(option.option, DHCPOptionWrapper::TimeValue(DHCPOptTimeValue {
                                        seconds: 0x00000e10,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_SERVER_ID => {
                                    assert_eq!(option.option, DHCPOptionWrapper::ServerId(DHCPOptServerId {
                                        dhcp_server_id: vec![0xc0, 0xa8, 0x00, 0x01],
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                _ => {
                                    unimplemented!();
                                }
                            }
                            rem = rem1;
                        },
                        Err(_) => {
                            panic!("should not reach here")
                        }
                    }
                }
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    #[test]
    fn test_parse_dhcp_ack() {
        let pcap = include_bytes!("pcaps/dhcp/ack.pcap");
        let payloads = &pcap[24+16+42..];
        match parse_dhcp_header(payloads) {
            Ok((rem, header)) => {
                assert_eq!(header.opcode, 0x02);
                assert_eq!(header.htype, 0x01);
                assert_eq!(header.hlen, 0x06);
                assert_eq!(header.hops, 0x00);
                assert_eq!(header.txid, 0x00003d1e);
                assert_eq!(header.seconds, 0x0000);
                assert_eq!(header.flags, 0x00000);
                assert_eq!(header.ciaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.yiaddr, vec![0xc0, 0xa8, 0x00, 0x0a]);
                assert_eq!(header.siaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.giaddr, vec![0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.chaddr, vec![0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.sname, [0; 64].to_vec());
                assert_eq!(header.bootfilename, [0; 128].to_vec());
                assert_eq!(header.magic, vec![0x63, 0x82, 0x53, 0x63]);

                let mut rem = rem;
                loop {
                    match parse_dhcp_option(rem) {
                        Ok((rem1, option)) => {
                            match option.code {
                                DHCP_OPT_END => {
                                    break;
                                },
                                DHCP_OPT_MESSAGE_TYPE => {
                                    assert_eq!(option.option, DHCPOptionWrapper::MessageType(DHCPOptMessageType {
                                        message_type: 0x05,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_RENEWAL_TIME_VALUE => {
                                    assert_eq!(option.option, DHCPOptionWrapper::TimeValue(DHCPOptTimeValue {
                                        seconds: 0x00000708,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_REBINDING_TIME_VALUE => {
                                    assert_eq!(option.option, DHCPOptionWrapper::TimeValue(DHCPOptTimeValue {
                                        seconds: 0x00000c4e,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_IP_ADDRESS_LEASE_TIME => {
                                    assert_eq!(option.option, DHCPOptionWrapper::TimeValue(DHCPOptTimeValue {
                                        seconds: 0x00000e10,
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_SERVER_ID => {
                                    assert_eq!(option.option, DHCPOptionWrapper::ServerId(DHCPOptServerId {
                                        dhcp_server_id: vec![0xc0, 0xa8, 0x00, 0x01],
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                DHCP_OPT_SUBNET_MASK => {
                                    assert_eq!(option.option, DHCPOptionWrapper::SubnetMask(DHCPOptSubnetMask {
                                        subnet_mask: vec![0xff, 0xff, 0xff, 0x00],
                                    }));
                                    assert_eq!(option.data, None);
                                },
                                _ => {
                                    unimplemented!();
                                }
                            }
                            rem = rem1;
                        },
                        Err(_) => {
                            panic!("should not reach here")
                        }
                    }
                }
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }
}