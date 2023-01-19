use std::net::{IpAddr, Ipv4Addr};
use nom7::{IResult, sequence::tuple, number::complete::{be_u8, be_u32, be_u16}, multi::count, bytes::complete::take};

#[derive(Debug, PartialEq)]
pub struct BlockPropertiesOptions {
    option: u8,
    sub_option: u8,
}

#[derive(Debug, PartialEq)]
pub struct BlockDeviceInfo {
    vendor_id: u16,
    device_id: u16,
}

#[derive(Debug, PartialEq)]
pub struct BlockDeviceRole {
    device_role_details: u8,
}

#[derive(Debug, PartialEq)]
pub struct BlockDeviceNameOfStation {
    block_info: u16,
    name_of_station: String,
}

#[derive(Debug, PartialEq)]
pub struct BlockIpInfo {
    block_info: u16,
    ip_address: IpAddr,
    sub_netmask: IpAddr,
    standard_gateway: IpAddr,
}

#[derive(Debug, PartialEq)]
pub struct BlockControlResponse {
    option: u8,
    sub_option: u8,
    block_error: u8,
}

#[derive(Debug, PartialEq)]
pub enum ProfinetDCPBlockData {
    DEV_PROPS_OPTS(Vec<BlockPropertiesOptions>),
    DEV_PROPS_MANUFACURER_SPECIFIC(String),
    DEV_PROPS_NAME_OF_STATION(BlockDeviceNameOfStation),
    DEV_PROPS_DEV_ID(BlockDeviceInfo),
    DEV_PROPS_DEV_ROLE(BlockDeviceRole),
    DEV_PROPS_IP_INFO(BlockIpInfo),
    DEV_PROPS_END_TRANSACTION(u16),
    DEV_PROPS_CONTROL_RESPONSE(BlockControlResponse),
}

#[derive(Debug, PartialEq)]
pub struct ProfinetDCPBlock {
    option: u8,
    sub_option: u8,
    dcp_block_length: u16,
    data: Option<ProfinetDCPBlockData>,
}

#[derive(Debug, PartialEq)]
pub struct ProfinetDCP {
    service_id: u8,
    service_type: u8,
    xid: u32,
    response_delay: u16,
    dcp_data_length: u16,
    blocks: Vec<ProfinetDCPBlock>,
}

pub fn parse_profinet_dcp_option_suboption(input: &[u8]) -> IResult<&[u8], BlockPropertiesOptions> {
    let (rem, (
        option,
        sub_option,
    )) = tuple((
        be_u8,
        be_u8,
    ))(input)?;
    Ok((rem, BlockPropertiesOptions {
        option,
        sub_option,
    }))
}

pub fn parse_profinet_dcp_block_dev_properties_options(input: &[u8], dcp_block_length: u16) -> IResult<&[u8], Option<ProfinetDCPBlockData>> {
    let (rem, data) = count(parse_profinet_dcp_option_suboption, (dcp_block_length / 2) as usize)(input)?;
    Ok((rem, Some(ProfinetDCPBlockData::DEV_PROPS_OPTS(data))))
}

pub fn parse_profinet_dcp_block_vendor_device_id(input: &[u8]) -> IResult<&[u8], BlockDeviceInfo> {
    let (rem, (
        vendor_id,
        device_id,
    )) = tuple((
        be_u16,
        be_u16,
    ))(input)?;
    Ok((rem, BlockDeviceInfo {
        vendor_id,
        device_id,
    }))
}

pub fn parse_profinet_block(input: &[u8]) -> IResult<&[u8], ProfinetDCPBlock> {
    let (rem, (
        option,
        sub_option,
        dcp_block_length,
    )) = tuple((
        be_u8,
        be_u8,
        be_u16,
    ))(input)?;
    match (option, sub_option) {
        (255, 255) => {
            Ok((rem, ProfinetDCPBlock {
                option,
                sub_option,
                dcp_block_length,
                data: None,
            }))
        },
        (1, 2) => {
            let (rem, block_info) = be_u16(rem)?;
            match block_info {
                1 => {
                    let (rem, (
                        ip_address,
                        sub_netmask,
                        standard_gateway,
                    )) = tuple((
                        take(4usize),
                        take(4usize),
                        take(4usize),
                    ))(rem)?;
                    let ip_address = IpAddr::V4(Ipv4Addr::new(ip_address[0], ip_address[1], ip_address[2], ip_address[3]));
                    let sub_netmask = IpAddr::V4(Ipv4Addr::new(sub_netmask[0], sub_netmask[1], sub_netmask[2], sub_netmask[3]));
                    let standard_gateway = IpAddr::V4(Ipv4Addr::new(standard_gateway[0], standard_gateway[1], standard_gateway[2], standard_gateway[3]));
                    Ok((rem, ProfinetDCPBlock {
                        option,
                        sub_option,
                        dcp_block_length,
                        data: Some(ProfinetDCPBlockData::DEV_PROPS_IP_INFO(BlockIpInfo {
                            block_info,
                            ip_address,
                            sub_netmask,
                            standard_gateway,
                        }))
                    }))
                },
                _ => {
                    unimplemented!();
                }
            }
        },
        (2, 1) => {
            let (rem, (
                _,
                device_vendor_value,
            )) = tuple((
                be_u16,
                take((dcp_block_length - 2) as usize),
            ))(rem)?;
            Ok((rem, ProfinetDCPBlock {
                option,
                sub_option,
                dcp_block_length,
                data: Some(ProfinetDCPBlockData::DEV_PROPS_MANUFACURER_SPECIFIC(String::from_utf8(device_vendor_value.into()).unwrap())),
            }))
        },
        (2, 2) => {
            let real_block_length = if dcp_block_length % 2 != 0 {
                dcp_block_length + 1
            } else {
                dcp_block_length
            };
            let (rem, (
                block_info,
                name_of_station,
            )) = tuple((
                be_u16,
                take((real_block_length - 2) as usize),
            ))(rem)?;
            let name_of_station = String::from_utf8(name_of_station.into()).unwrap().split_whitespace().next().unwrap().into();
            Ok((rem, ProfinetDCPBlock {
                option,
                sub_option,
                dcp_block_length,
                data: Some(ProfinetDCPBlockData::DEV_PROPS_NAME_OF_STATION(BlockDeviceNameOfStation {
                    block_info,
                    name_of_station,
                })),
            }))
        },
        (2, 3) => {
            let (rem, (
                _,
                vendor_device_id,
            )) = tuple((
                be_u16,
                parse_profinet_dcp_block_vendor_device_id,
            ))(rem)?;
            Ok((rem, ProfinetDCPBlock {
                option,
                sub_option,
                dcp_block_length,
                data: Some(ProfinetDCPBlockData::DEV_PROPS_DEV_ID(vendor_device_id)),
            }))
        },
        (2, 4) => {
            let (rem, (
                _,
                device_role_details,
                _,
            )) = tuple((
                be_u16,
                be_u8,
                be_u8,
            ))(rem)?;
            Ok((rem, ProfinetDCPBlock {
                option,
                sub_option,
                dcp_block_length,
                data: Some(ProfinetDCPBlockData::DEV_PROPS_DEV_ROLE(BlockDeviceRole {
                    device_role_details,
                }))
            }))
        },
        (2, 5) => {
            let (rem, _) = be_u16(rem)?;
            let (rem, data) = parse_profinet_dcp_block_dev_properties_options(rem, dcp_block_length - 2)?;
            Ok((rem, ProfinetDCPBlock {
                option,
                sub_option,
                dcp_block_length,
                data,
            }))
        },
        (5, 2) => {
            let (rem, block_qualifier) = be_u16(rem)?;
            Ok((rem, ProfinetDCPBlock {
                option,
                sub_option,
                dcp_block_length,
                data: Some(ProfinetDCPBlockData::DEV_PROPS_END_TRANSACTION(block_qualifier)) 
            }))
        },
        (5, 4) => {
            let (rem, (
                inner_option,
                inner_sub_option,
                block_error,
            )) = tuple((
                be_u8,
                be_u8,
                be_u8,
            ))(rem)?;
            let (rem, _) = if dcp_block_length % 2 != 0 {
                take(1usize)(rem)?
            } else {
                (rem, rem)
            };
            Ok((rem, ProfinetDCPBlock {
                option,
                sub_option,
                dcp_block_length,
                data: Some(ProfinetDCPBlockData::DEV_PROPS_CONTROL_RESPONSE(BlockControlResponse {
                    option: inner_option,
                    sub_option: inner_sub_option,
                    block_error,
                })),
            }))
        },
        _ => {
            unimplemented!();
        }
    }
}

pub fn parse_profinet_dcp(input: &[u8]) -> IResult<&[u8], ProfinetDCP> {
    let (rem, (
        service_id,
        service_type,
        xid,
        response_delay,
        dcp_data_length,
    )) = tuple((
        be_u8,
        be_u8,
        be_u32,
        be_u16,
        be_u16,
    ))(input)?;
    let mut blocks = Vec::new();
    let mut rem_blocks = rem;
    let mut rem_dcp_data_length = dcp_data_length;
    loop {
        if rem_dcp_data_length == 0 {
            break;
        }
        let (tmp_rem, block) = parse_profinet_block(rem_blocks)?;
        blocks.push(block);
        rem_dcp_data_length -= (tmp_rem.as_ptr() as usize - rem_blocks.as_ptr() as usize) as u16;
        rem_blocks = tmp_rem;
    }
    Ok((rem_blocks, ProfinetDCP {
        service_id,
        service_type,
        xid,
        response_delay,
        dcp_data_length,
        blocks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_profinet_dcp_block_all() {
        let pcap = include_bytes!("pcaps/profinet/profinet_dcp_block_all.pcap");
        let payload = &pcap[24+16+20..];

        match parse_profinet_dcp(payload) {
            Ok((rem, profinet_dcp)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(profinet_dcp, ProfinetDCP {
                    service_id: 5,
                    service_type: 0,
                    xid: 0x01000001,
                    response_delay: 1,
                    dcp_data_length: 4,
                    blocks: vec![
                        ProfinetDCPBlock {
                            option: 255,
                            sub_option:255,
                            dcp_block_length: 0,
                            data: None,
                        },
                    ]
                });
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_profinet_dcp_multi_blocks() {
        let pcap = include_bytes!("pcaps/profinet/profinet_dcp_multi_blocks.pcap");
        let payload = &pcap[24+16+20..];
        match parse_profinet_dcp(payload) {
            Ok((rem, profinet_dcp)) => {
                assert_eq!(profinet_dcp.service_id, 5);
                assert_eq!(profinet_dcp.service_type, 1);
                assert_eq!(profinet_dcp.xid, 0x01000001);
                assert_eq!(profinet_dcp.response_delay, 0);
                assert_eq!(profinet_dcp.dcp_data_length, 184);
                assert_eq!(profinet_dcp.blocks, vec![
                    ProfinetDCPBlock {
                        option: 2,
                        sub_option: 5,
                        dcp_block_length: 16,
                        data: Some(ProfinetDCPBlockData::DEV_PROPS_OPTS(vec![
                            BlockPropertiesOptions {
                                option: 2,
                                sub_option:1,
                            },
                            BlockPropertiesOptions {
                                option: 2,
                                sub_option: 2,
                            },
                            BlockPropertiesOptions {
                                option: 2,
                                sub_option: 3,
                            },
                            BlockPropertiesOptions {
                                option: 2,
                                sub_option: 4,
                            },
                            BlockPropertiesOptions {
                                option: 2,
                                sub_option: 5,
                            },
                            BlockPropertiesOptions {
                                option: 1,
                                sub_option: 1,
                            },
                            BlockPropertiesOptions {
                                option: 1,
                                sub_option: 2,
                            },
                        ])),
                    },
                    ProfinetDCPBlock {
                        option: 2,
                        sub_option: 1,
                        dcp_block_length: 10,
                        data: Some(ProfinetDCPBlockData::DEV_PROPS_MANUFACURER_SPECIFIC(String::from("S7-300EC"))),
                    },
                    ProfinetDCPBlock {
                        option: 2,
                        sub_option: 2,
                        dcp_block_length: 110,
                        data: Some(ProfinetDCPBlockData::DEV_PROPS_NAME_OF_STATION(BlockDeviceNameOfStation {
                            block_info: 0,
                            name_of_station: String::from("%n%n%n"),
                        })),
                    },
                    ProfinetDCPBlock {
                        option: 2,
                        sub_option: 3,
                        dcp_block_length: 6,
                        data: Some(ProfinetDCPBlockData::DEV_PROPS_DEV_ID(BlockDeviceInfo {
                            vendor_id: 0x002a,
                            device_id: 0x0101,
                        })),
                    },
                    ProfinetDCPBlock {
                        option: 2,
                        sub_option: 4,
                        dcp_block_length: 4,
                        data: Some(ProfinetDCPBlockData::DEV_PROPS_DEV_ROLE(BlockDeviceRole {
                            device_role_details: 0x02,
                        }))
                    },
                    ProfinetDCPBlock {
                        option: 1,
                        sub_option: 2,
                        dcp_block_length: 14,
                        data: Some(ProfinetDCPBlockData::DEV_PROPS_IP_INFO(BlockIpInfo {
                            block_info: 1,
                            ip_address: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 11)),
                            sub_netmask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                            standard_gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 11)),
                        }))
                    }
                ]);
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_profinet_dcp_block_set_request() {
        let pcap = include_bytes!("pcaps/profinet/profinet_dcp_block_set_request.pcap");
        let payload = &pcap[24+16+20..];
        match parse_profinet_dcp(payload) {
            Ok((rem, profinet_dcp)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(profinet_dcp, ProfinetDCP {
                    service_id: 4,
                    service_type: 0,
                    xid: 0x01000001,
                    response_delay: 0,
                    dcp_data_length: 20,
                    blocks: vec![
                        ProfinetDCPBlock {
                            option: 2,
                            sub_option:2,
                            dcp_block_length: 9,
                            data: Some(ProfinetDCPBlockData::DEV_PROPS_NAME_OF_STATION(BlockDeviceNameOfStation {
                                block_info: 1,
                                name_of_station: String::from("%n%n%n"),
                            })),
                        },
                        ProfinetDCPBlock {
                            option: 5,
                            sub_option: 2,
                            dcp_block_length: 2,
                            data: Some(ProfinetDCPBlockData::DEV_PROPS_END_TRANSACTION(0)),
                        },
                    ],
                })
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_profinet_dcp_block_set_response() {
        let pcap = include_bytes!("pcaps/profinet/profinet_dcp_block_set_response.pcap");
        let payload = &pcap[24+16+20..];
        match parse_profinet_dcp(payload) {
            Ok((rem, profinet_dcp)) => {
                //assert_eq!(rem.len(), 0);
                assert_eq!(profinet_dcp, ProfinetDCP {
                    service_id: 4,
                    service_type: 1,
                    xid: 0x01000001,
                    response_delay: 0,
                    dcp_data_length: 16,
                    blocks: vec![
                        ProfinetDCPBlock {
                            option: 5,
                            sub_option: 4,
                            dcp_block_length: 3,
                            data: Some(ProfinetDCPBlockData::DEV_PROPS_CONTROL_RESPONSE(BlockControlResponse {
                                option: 2,
                                sub_option: 2,
                                block_error: 0,
                            })),
                        },
                        ProfinetDCPBlock {
                            option: 5,
                            sub_option: 4,
                            dcp_block_length: 3,
                            data: Some(ProfinetDCPBlockData::DEV_PROPS_CONTROL_RESPONSE(BlockControlResponse {
                                option: 5,
                                sub_option: 2,
                                block_error: 0,
                            })),
                        }
                    ],
                })
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }
}