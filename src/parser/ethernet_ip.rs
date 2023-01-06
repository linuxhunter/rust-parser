use nom7::{IResult, number::complete::{le_u16, le_u32, le_u8}, sequence::tuple, bytes::complete::take, multi::count};

#[derive(Debug, PartialEq)]
pub struct PathSegment {
    path_segment_type: u8,
    logical_segment_type: u8,
    logical_segment_format: u8,
    data: u8,
}

#[derive(Debug, PartialEq)]
pub struct CIPHeaderRequest {
    request_path_size: u8,
    request_pathes: Vec<PathSegment>,
}

#[derive(Debug, PartialEq)]
pub struct CIPHeaderResponse {
    status: u16,
}

#[derive(Debug, PartialEq)]
pub enum CIPHeaderOperation {
    REQUEST(CIPHeaderRequest),
    RESPONSE(CIPHeaderResponse)
}

#[derive(Debug, PartialEq)]
pub struct CIPHeader {
    service: u8,
    operation: CIPHeaderOperation,
}

#[derive(Debug, PartialEq)]
pub struct CIPConnectionManagerRoutePath {
    path_segment_type: u8,
    extended_link_address: bool,
    port: u8,
    link_address: u8,
}

#[derive(Debug, PartialEq)]
pub struct CIPConnectionManager {
    priority: u8,
    tick_time: u8,
    time_out_ticks: u8,
    embedded_message_request_size: u16,
    cip_embedded_message_request: Vec<u8>,
    route_path_size: u8,
    route_path: CIPConnectionManagerRoutePath,
}

#[derive(Debug, PartialEq)]
pub enum CIPCommandSpecificData {
    GENERIC(Vec<u8>),
    NONE,
}

#[derive(Debug, PartialEq)]
pub struct ServicePacket {
    cip_header: CIPHeader,
    command_specific_data: CIPCommandSpecificData,
}

#[derive(Debug, PartialEq)]
pub struct MultipleServicePacket {
    number_of_services: u16,
    service_packets: Vec<ServicePacket>,
}

#[derive(Debug, PartialEq)]
pub struct CIP {
    cip_header: CIPHeader,
    multiple_service_packet: Option<MultipleServicePacket>,
}

#[derive(Debug, PartialEq)]
pub struct CIP_CM {
    cip_header: CIPHeader,
    cip_connection_manager: CIPConnectionManager,
}

#[derive(Debug, PartialEq)]
pub struct PacketedCIP {
    cip_sequence_count: u16,
    cip: CIP,
}

#[derive(Debug, PartialEq)]
pub enum ItemData {
    CONNECTED_ADDRESS_ITEM(u32),
    CONNECTED_DATA_ITEM(PacketedCIP),
    UNCONNECTEDD_DATA_ITEM(CIP_CM),
    NONE,
}

#[derive(Debug, PartialEq)]
pub struct Item {
    id: u16,
    length: u16,
    data: ItemData,
}

#[derive(Debug, PartialEq)]
pub struct EncapsulationHeader {
    command: u16,
    length: u16,
    session_handle: u32,
    status: u32,
    sender_context: Vec<u8>,
    options: u32,
}

#[derive(Debug, PartialEq)]
pub struct CommandSpecificData {
    interface_handle: u32,
    timeout: u16,
    item_count: u16,
    item_data: Vec<Item>,
}

#[derive(Debug, PartialEq)]
pub struct EhternetIP {
    encapsulation_header: EncapsulationHeader,
    command_specific_data: CommandSpecificData,
}

pub fn parse_cip_request_path(input: &[u8]) -> IResult<&[u8], PathSegment> {
    let (rem, flags) = le_u8(input)?;
    let (rem, data) = le_u8(rem)?;
    let path_segment_type = (flags & 0xe0) >> 5;
    let logical_segment_type = (flags & 0x1c) >> 2;
    let logical_segment_format = flags & 0x03;
    Ok((rem, PathSegment {
        path_segment_type,
        logical_segment_type,
        logical_segment_format,
        data,
    }))
}

pub fn parse_cip_service_command_specific_data(input: &[u8], service: u8) -> IResult<&[u8], CIPCommandSpecificData> {
    match service {
        0x4c => {
            let (rem, data) = take(6usize)(input)?;
            Ok((rem, CIPCommandSpecificData::GENERIC(data.to_vec())))
        },
        0xcc => {
            let (rem, data) = take(4usize)(input)?;
            Ok((rem, CIPCommandSpecificData::GENERIC(data.to_vec())))
        },
        _ => {
            Ok((input, CIPCommandSpecificData::NONE))
        }
    }
}

pub fn parse_cip_service_packet(input: &[u8]) -> IResult<&[u8], ServicePacket> {
    let (rem, cip_header) = parse_cip_header(input)?;
    let (rem, command_specific_data) = parse_cip_service_command_specific_data(rem, cip_header.service)?;
    Ok((rem, ServicePacket {
        cip_header,
        command_specific_data,
    }))
}

pub fn parse_cip_multiple_service_packet(input: &[u8]) -> IResult<&[u8], Option<MultipleServicePacket>> {
        let (rem, number_of_services) = le_u16(input)?;
        let (rem, _) = take((2 * number_of_services) as usize)(rem)?;
        let (rem, service_packets) = count(parse_cip_service_packet, number_of_services as usize)(rem)?;
        Ok((rem, Some(MultipleServicePacket {
            number_of_services,
            service_packets,
        })))
}

pub fn parse_cip_cm_route_path(input: &[u8]) -> IResult<&[u8], CIPConnectionManagerRoutePath> {
    let (rem, data) = le_u8(input)?;
    let (rem, link_address) = le_u8(rem)?;
    let path_segment_type = (data & 0xe0) >> 5;
    let extended_link_address = if ((data & 0x10) >> 4) == 0x00 {
        false
    } else {
        true
    };
    let port = data & 0x0f;
    Ok((rem, CIPConnectionManagerRoutePath {
        path_segment_type,
        extended_link_address,
        port,
        link_address,
    }))
}

pub fn parse_cip_connection_manager_specific_data(input: &[u8]) -> IResult<&[u8], CIPConnectionManager> {
    let (rem, (
        data,
        time_out_ticks,
        embedded_message_request_size,
        cip_embedded_message_request,
        route_path_size,
        _reserved,
        route_path
    )) = tuple((
        le_u8,
        le_u8,
        le_u16,
        take(8usize),
        le_u8,
        le_u8,
        parse_cip_cm_route_path,
    ))(input)?;
    Ok((rem, CIPConnectionManager {
        priority: (data & 0x10) >> 4,
        tick_time: data & 0x0f,
        time_out_ticks,
        embedded_message_request_size,
        cip_embedded_message_request: cip_embedded_message_request.to_vec(),
        route_path_size,
        route_path,
    }))
}

pub fn parse_cip_header(input: &[u8]) -> IResult<&[u8], CIPHeader> {
    let (rem, service) = le_u8(input)?;
    if service & 0x80 == 0 {
        let (rem, request_path_size) = le_u8(rem)?;
        let (rem, request_pathes) = count(parse_cip_request_path, request_path_size as usize)(rem)?;
        Ok((rem, CIPHeader {
            service,
            operation: CIPHeaderOperation::REQUEST(CIPHeaderRequest {
                request_path_size,
                request_pathes,
            }),
        }))
    } else {
        let (rem, _) = le_u8(rem)?;
        let (rem, status) = le_u16(rem)?;
        Ok((rem, CIPHeader {
            service,
            operation: CIPHeaderOperation::RESPONSE(CIPHeaderResponse {
                status,
            })
        }))
    }
}

pub fn parse_cip(input: &[u8]) -> IResult<&[u8], CIP> {
    let (rem, cip_header) = parse_cip_header(input)?;
    match cip_header.service {
        0x0a | 0x8a => {
            let (rem, multiple_service_packet) = parse_cip_multiple_service_packet(rem)?;
            Ok((rem, CIP {
                cip_header,
                multiple_service_packet,
            }))
        },
        _ => {
            Ok((rem, CIP {
                cip_header,
                multiple_service_packet: None,
            }))

        },
    }
}

pub fn parse_cip_cm(input: &[u8]) -> IResult<&[u8], CIP_CM> {
    let (rem, cip_header) = parse_cip_header(input)?;
    let (rem, cip_connection_manager) = parse_cip_connection_manager_specific_data(rem)?;
    Ok((rem, CIP_CM {
        cip_header,
        cip_connection_manager,
    }))
}

pub fn parse_ethernet_ip_item(input: &[u8]) -> IResult<&[u8], Item> {
    let (rem, id) = le_u16(input)?;
    let (rem, length) = le_u16(rem)?;
    match id {
        0x0000 => {
            Ok((rem, Item {
                id,
                length,
                data: ItemData::NONE,
            }))
        },
        0x00a1 => {
            let (rem, data) = le_u32(rem)?;
            Ok((rem, Item {
                id,
                length,
                data: ItemData::CONNECTED_ADDRESS_ITEM(data),
            }))
        },
        0x00b1 => {
            let (rem, cip_sequence_count) = le_u16(rem)?;
            let (rem, cip) = parse_cip(rem)?;
            Ok((rem, Item {
                id,
                length,
                data: ItemData::CONNECTED_DATA_ITEM(PacketedCIP {
                    cip_sequence_count,
                    cip,
                }),
            }))
        },
        0x00b2 => {
            let (rem, cip_cm) = parse_cip_cm(rem)?;
            Ok((rem, Item {
                id,
                length,
                data: ItemData::UNCONNECTEDD_DATA_ITEM(cip_cm),
            }))
        },
        _ => {
            unimplemented!();
        }
    }
}

pub fn parse_ethernet_ip_encapsultion_header(input: &[u8]) -> IResult<&[u8], EncapsulationHeader> {
    let (rem, (
        command,
        length,
        session_handle,
        status,
        sender_context,
        options
    )) = tuple((
        le_u16,
        le_u16,
        le_u32,
        le_u32,
        take(8usize),
        le_u32,
    ))(input)?;
    Ok((rem, EncapsulationHeader {
        command,
        length,
        session_handle,
        status,
        sender_context: sender_context.to_vec(),
        options,
    }))
}

pub fn parse_ethernet_ip_command_specific_data(input: &[u8]) -> IResult<&[u8], CommandSpecificData> {
    let (rem, interface_handle) = le_u32(input)?;
    let (rem, timeout) = le_u16(rem)?;
    let (rem, item_count) = le_u16(rem)?;
    let (rem, item_data) = count(parse_ethernet_ip_item, item_count as usize)(rem)?;
    Ok((rem, CommandSpecificData {
        interface_handle,
        timeout,
        item_count,
        item_data,
    }))
}

pub fn parse_ethernet_ip(input: &[u8]) -> IResult<&[u8], EhternetIP> {
    let (rem, encapsulation_header) = parse_ethernet_ip_encapsultion_header(input)?;
    let (rem, command_specific_data) = parse_ethernet_ip_command_specific_data(rem)?;
    Ok((rem, EhternetIP {
        encapsulation_header,
        command_specific_data,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cip_start() {
        let pcap = include_bytes!("pcaps/cip/cip_start_plc.pcap");
        let payload = &pcap[24+16+54..];
        match parse_ethernet_ip(payload) {
            Ok((rem, ethernet_ip)) => {
                assert_eq!(rem.len(), 0x00);
                let encapsulation_header = ethernet_ip.encapsulation_header;
                assert_eq!(encapsulation_header.command, 0x0070);
                assert_eq!(encapsulation_header.length, 0x001c);
                assert_eq!(encapsulation_header.session_handle, 0x002a0001);
                assert_eq!(encapsulation_header.status, 0x00000000);
                assert_eq!(encapsulation_header.sender_context, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                assert_eq!(encapsulation_header.options, 0x00000000);

                let command_specific_data = ethernet_ip.command_specific_data;
                assert_eq!(command_specific_data.interface_handle, 0x00000000);
                assert_eq!(command_specific_data.timeout, 0x0001);
                assert_eq!(command_specific_data.item_count, 0x0002);
                assert_eq!(command_specific_data.item_data[0], Item {
                    id: 0x00a1,
                    length: 0x0004,
                    data: ItemData::CONNECTED_ADDRESS_ITEM(0xff954022),
                });
                assert_eq!(command_specific_data.item_data[1], Item {
                    id: 0x00b1,
                    length: 0x0008,
                    data: ItemData::CONNECTED_DATA_ITEM(PacketedCIP {
                        cip_sequence_count: 0x00e7,
                        cip: CIP {
                            cip_header: CIPHeader {
                                service: 0x06,
                                operation: CIPHeaderOperation::REQUEST(CIPHeaderRequest {
                                    request_path_size: 0x02,
                                    request_pathes: vec![
                                        PathSegment {
                                            path_segment_type: 0x01,
                                            logical_segment_type: 0x00,
                                            logical_segment_format: 0x00,
                                            data: 0x8e,
                                        },
                                        PathSegment {
                                            path_segment_type: 0x01,
                                            logical_segment_type: 0x01,
                                            logical_segment_format: 0x00,
                                            data: 0x01,
                                        }
                                    ],
                                }),
                            },
                            multiple_service_packet: None,
                        },
                    }),
                })
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_cip_stop() {
        let pcap = include_bytes!("pcaps/cip/cip_stop_plc.pcap");
        let payload = &pcap[24+16+54..];
        match parse_ethernet_ip(payload) {
            Ok((rem, ethernet_ip)) => {
                assert_eq!(rem.len(), 0x00);
                let encapsulation_header = ethernet_ip.encapsulation_header;
                assert_eq!(encapsulation_header.command, 0x0070);
                assert_eq!(encapsulation_header.length, 0x001c);
                assert_eq!(encapsulation_header.session_handle, 0x002a0001);
                assert_eq!(encapsulation_header.status, 0x00000000);
                assert_eq!(encapsulation_header.sender_context, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                assert_eq!(encapsulation_header.options, 0x00000000);

                let command_specific_data = ethernet_ip.command_specific_data;
                assert_eq!(command_specific_data.interface_handle, 0x00000000);
                assert_eq!(command_specific_data.timeout, 0x0001);
                assert_eq!(command_specific_data.item_count, 0x0002);
                assert_eq!(command_specific_data.item_data[0], Item {
                    id: 0x00a1,
                    length:0x0004,
                    data: ItemData::CONNECTED_ADDRESS_ITEM(0xff954022),
                });
                assert_eq!(command_specific_data.item_data[1], Item {
                    id: 0x00b1,
                    length: 0x0008,
                    data: ItemData::CONNECTED_DATA_ITEM(PacketedCIP {
                        cip_sequence_count: 0x0106,
                        cip: CIP {
                            cip_header: CIPHeader {
                                service: 0x07,
                                operation: CIPHeaderOperation::REQUEST(CIPHeaderRequest {
                                    request_path_size: 0x02,
                                    request_pathes: vec![
                                        PathSegment {
                                            path_segment_type: 0x01,
                                            logical_segment_type: 0x00,
                                            logical_segment_format: 0x00,
                                            data: 0x8e,
                                        },
                                        PathSegment {
                                            path_segment_type: 0x01,
                                            logical_segment_type: 0x01,
                                            logical_segment_format: 0x00,
                                            data: 0x01,
                                        },
                                    ],
                                }),
                            },
                            multiple_service_packet: None,
                        },
                    }),
                });
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_cip_multiple_service_request() {
        let pcap = include_bytes!("pcaps/cip/cip_multiple_service_request.pcap");
        let payload = &pcap[24+16+54..];
        match parse_ethernet_ip(payload) {
            Ok((rem, ethernet_ip)) => {
                assert_eq!(rem.len(), 0x00);
                let encapsulation_header = ethernet_ip.encapsulation_header;
                assert_eq!(encapsulation_header, EncapsulationHeader {
                    command: 0x0070,
                    length: 0x003a,
                    session_handle: 0x10020100,
                    status: 0x00000000,
                    sender_context: vec![0x1a, 0x39, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00],
                    options: 0x00000000,
                });

                let command_specific_data = ethernet_ip.command_specific_data;
                assert_eq!(command_specific_data.interface_handle, 0x00000000);
                assert_eq!(command_specific_data.timeout, 0x000a);
                assert_eq!(command_specific_data.item_count, 0x0002);
                assert_eq!(command_specific_data.item_data[0], Item {
                    id: 0x00a1,
                    length: 0x0004,
                    data: ItemData::CONNECTED_ADDRESS_ITEM(0x00351309),
                });
                assert_eq!(command_specific_data.item_data[1], Item {
                    id: 0x00b1,
                    length: 0x0026,
                    data: ItemData::CONNECTED_DATA_ITEM(PacketedCIP {
                        cip_sequence_count: 0x6ae4,
                        cip: CIP {
                            cip_header: CIPHeader {
                                service: 0x0a,
                                operation: CIPHeaderOperation::REQUEST(CIPHeaderRequest {
                                    request_path_size: 0x02,
                                    request_pathes: vec![
                                        PathSegment {
                                            path_segment_type: 0x01,
                                            logical_segment_type: 0x00,
                                            logical_segment_format: 0x00,
                                            data: 0x02,
                                        },
                                        PathSegment {
                                            path_segment_type: 0x01,
                                            logical_segment_type: 0x01,
                                            logical_segment_format: 0x00,
                                            data: 0x01,
                                        }
                                    ],
                                }),
                            },
                            multiple_service_packet: Some(MultipleServicePacket {
                                number_of_services: 0x0002,
                                service_packets: vec![
                                    ServicePacket {
                                        cip_header: CIPHeader {
                                            service: 0x4c,
                                            operation: CIPHeaderOperation::REQUEST(CIPHeaderRequest {
                                                request_path_size: 0x02,
                                                request_pathes: vec![
                                                    PathSegment {
                                                        path_segment_type: 0x01,
                                                        logical_segment_type: 0x00,
                                                        logical_segment_format: 0x00,
                                                        data: 0x72,
                                                    },
                                                    PathSegment {
                                                        path_segment_type: 0x01,
                                                        logical_segment_type: 0x01,
                                                        logical_segment_format: 0x00,
                                                        data: 0x00,
                                                    },
                                                ],
                                            }),
                                        },
                                        command_specific_data: CIPCommandSpecificData::GENERIC(vec![0x00, 0xce, 0x04, 0x00, 0x01, 0x00]),
                                    },
                                    ServicePacket {
                                        cip_header: CIPHeader {
                                            service: 0x4c,
                                            operation: CIPHeaderOperation::REQUEST(CIPHeaderRequest {
                                                request_path_size: 0x02,
                                                request_pathes: vec![
                                                    PathSegment {
                                                        path_segment_type: 0x01,
                                                        logical_segment_type: 0x00,
                                                        logical_segment_format: 0x00,
                                                        data: 0x72,
                                                    },
                                                    PathSegment {
                                                        path_segment_type: 0x01,
                                                        logical_segment_type:0x01,
                                                        logical_segment_format: 0x00,
                                                        data: 0x00,
                                                    },
                                                ],
                                            }),
                                        },
                                        command_specific_data: CIPCommandSpecificData::GENERIC(vec![0x2c, 0x3d, 0x04, 0x00, 0x01, 0x00]),
                                    }
                                ],
                            }),
                        },
                    }),
                });
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_cip_multiple_service_reponse() {
        let pcap = include_bytes!("pcaps/cip/cip_multiple_service_response.pcap");
        let payload = &pcap[24+16+54..];
        match parse_ethernet_ip(payload) {
            Ok((rem, ethernet_ip)) => {
                assert_eq!(rem.len(), 0x00);
                let encapsulation_header = ethernet_ip.encapsulation_header;
                assert_eq!(encapsulation_header, EncapsulationHeader {
                    command: 0x0070,
                    length: 0x0030,
                    session_handle: 0x10020100,
                    status: 0x00000000,
                    sender_context: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    options: 0x00000000,
                });
                let command_specific_data = ethernet_ip.command_specific_data;
                assert_eq!(command_specific_data.interface_handle, 0x00000000);
                assert_eq!(command_specific_data.timeout, 0x0000);
                assert_eq!(command_specific_data.item_count, 0x0002);
                assert_eq!(command_specific_data.item_data[0], Item {
                    id: 0x00a1,
                    length: 0x0004,
                    data: ItemData::CONNECTED_ADDRESS_ITEM(0x8000f1d7),
                });
                assert_eq!(command_specific_data.item_data[1], Item {
                    id: 0x00b1,
                    length: 0x001c,
                    data: ItemData::CONNECTED_DATA_ITEM(PacketedCIP {
                        cip_sequence_count: 0x6ae4,
                        cip: CIP {
                            cip_header: CIPHeader {
                                service: 0x8a,
                                operation: CIPHeaderOperation::RESPONSE(CIPHeaderResponse {
                                    status: 0x0000,
                                }),
                            },
                            multiple_service_packet: Some(MultipleServicePacket {
                                number_of_services: 0x0002,
                                service_packets: vec![
                                    ServicePacket {
                                        cip_header: CIPHeader {
                                            service: 0xcc,
                                            operation: CIPHeaderOperation::RESPONSE(CIPHeaderResponse {
                                                status: 0x0000,
                                            }),
                                        },
                                        command_specific_data: CIPCommandSpecificData::GENERIC(vec![0x01, 0x00, 0x00, 0x00]),
                                    },
                                    ServicePacket {
                                        cip_header: CIPHeader {
                                            service: 0xcc,
                                            operation: CIPHeaderOperation::RESPONSE(CIPHeaderResponse {
                                                status: 0x0000, 
                                            }),
                                        },
                                        command_specific_data: CIPCommandSpecificData::GENERIC(vec![0x05, 0x00, 0x00, 0x00]),
                                    }
                                ],
                            }),
                        },
                    }),
                });
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_cip_connetion_manager() {
        let pcap = include_bytes!("pcaps/cip/cip_connection_manager.pcap");
        let payload = &pcap[24+16+54..];
        match parse_ethernet_ip(payload) {
            Ok((rem, ethernet_ip)) => {
                assert_eq!(rem.len(), 0x00);
                let encapsulation_header = ethernet_ip.encapsulation_header;
                assert_eq!(encapsulation_header, EncapsulationHeader {
                    command: 0x006f,
                    length: 0x0026,
                    session_handle: 0x13020500,
                    status: 0x00000000,
                    sender_context: vec![0x6a, 0xc0, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00],
                    options: 0x00000000,
                });
                let command_specific_data = ethernet_ip.command_specific_data;
                assert_eq!(command_specific_data.interface_handle, 0x00000000);
                assert_eq!(command_specific_data.timeout, 0x0014);
                assert_eq!(command_specific_data.item_count, 0x0002);
                assert_eq!(command_specific_data.item_data[0], Item {
                    id: 0x0000,
                    length: 0x0000,
                    data: ItemData::NONE,
                });
                assert_eq!(command_specific_data.item_data[1], Item {
                    id: 0x00b2,
                    length: 0x0016,
                    data: ItemData::UNCONNECTEDD_DATA_ITEM(CIP_CM {
                        cip_header: CIPHeader {
                            service: 0x52,
                            operation: CIPHeaderOperation::REQUEST(CIPHeaderRequest {
                                request_path_size: 0x02,
                                request_pathes: vec![
                                    PathSegment {
                                        path_segment_type: 0x01,
                                        logical_segment_type: 0x00,
                                        logical_segment_format: 0x00,
                                        data: 0x06,
                                    },
                                    PathSegment {
                                        path_segment_type: 0x01,
                                        logical_segment_type: 0x01,
                                        logical_segment_format: 0x00,
                                        data: 0x01,
                                    }
                                ],
                            })
                        },
                        cip_connection_manager: CIPConnectionManager {
                            priority: 0x00,
                            tick_time: 0x07,
                            time_out_ticks: 0xe9,
                            embedded_message_request_size: 0x0008,
                            cip_embedded_message_request: vec![0x01, 0x02, 0x20, 0xac, 0x24, 0x01, 0x01, 0x00],
                            route_path_size: 0x01,
                            route_path: CIPConnectionManagerRoutePath {
                                path_segment_type: 0x00,
                                extended_link_address: false,
                                port: 0x01,
                                link_address: 0x00,
                            }
                        },
                    }),
                });
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }
}
