use nom7::{IResult, Err, sequence::tuple, number::complete::{be_u8, be_u16, be_u32}, bytes::complete::take, combinator::{map_res, rest}, error::{make_error, ErrorKind}};

#[derive(Debug, PartialEq)]
pub struct DoIpHeader {
    version: u8,
    inverse_version: u8,
    payload_type: u16,
    payload_length: u32,
}

#[derive(Debug, PartialEq)]
pub struct VehicleAnnouncementMessage {
    vin: Vec<u8>,
    logical_address: u16,
    eid: Vec<u8>,
    gid: Vec<u8>,
    further_action_required: u8,
}

#[derive(Debug, PartialEq)]
pub struct RoutingActivationRequestMessage {
    source_address: u16,
    activation_type: u16,
    reserved_by_iso: u32,
}

#[derive(Debug, PartialEq)]
pub struct RoutingActivationResponseMessage {
    logical_address_of_external_tester: u16,
    source_address: u16,
    routing_activation_response_code: u8,
    reserved_by_iso: u32,
}

#[derive(Debug, PartialEq)]
pub struct DiagRequestDownload {
    compression_method: u8,
    encrypting_method: u8,
    memory_size_length: u8,
    memory_address_length: u8,
    memory_address: u32,
    memory_size: u32,
}

#[derive(Debug, PartialEq)]
pub struct DiagResponseDownload {
    memory_address_length: u8,
    memory_size: u16,
}

#[derive(Debug, PartialEq)]
pub struct DiagRequestTransferData {
    block_sequence_counter: u8,
    block_data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct DiagRequestTestPresent {
    suppress_reply: u8,
}

#[derive(Debug, PartialEq)]
pub struct DiagResponseTransferData {
    block_sequence_counter: u8,
}

#[derive(Debug, PartialEq)]
pub struct DiagReplyError {
    service_identifier: u8,
    error_code: u8,
}

#[derive(Debug, PartialEq)]
pub enum DiagnosticData {
    RequestDownload(DiagRequestDownload),
    ResponseDownload(DiagResponseDownload),
    RequestTransferData(DiagRequestTransferData),
    ResponseTransferData(DiagResponseTransferData),
    RequestTestPresent(DiagRequestTestPresent),
    RequestTransferExit,
    ResponseTransferExit,
    ReplyError(DiagReplyError),
}

#[derive(Debug, PartialEq)]
pub struct DiagnosticMessage {
    service_identifier: u8,
    service_data: DiagnosticData,
}

#[derive(Debug, PartialEq)]
pub enum UdsPayload {
    DiagnosticMessage(DiagnosticMessage),
    DiagnosticMessageAck(u8),
}

#[derive(Debug, PartialEq)]
pub struct UdsMessage {
    source_address: u16,
    target_address: u16,
    uds_payload: UdsPayload,
}

pub fn parse_doip_header(input: &[u8]) -> IResult<&[u8], DoIpHeader> {
    let (rem, (
        version,
        inverse_version,
        payload_type,
        payload_length
    )) = tuple((
        be_u8,
        be_u8,
        be_u16,
        be_u32,
    ))(input)?;
    Ok((rem, DoIpHeader {
        version,
        inverse_version,
        payload_type,
        payload_length,
    }))
}

const VIN_LENGTH: usize = 17;
const EID_LENGTH: usize = 6;
const GID_LENGTH: usize = 6;

pub fn transform_array_to_vec(data: &[u8]) -> Result<Vec<u8>, String> {
    Ok(data.to_vec())
}

pub fn parse_vehicle_announcement_message(input: &[u8]) -> IResult<&[u8], VehicleAnnouncementMessage> {
    let (rem, vin) = map_res(take(VIN_LENGTH), |data| transform_array_to_vec(data))(input)?;
    let (rem, logical_address) = be_u16(rem)?;
    let (rem, eid) = map_res(take(EID_LENGTH), |data| transform_array_to_vec(data))(rem)?;
    let (rem, gid) = map_res(take(GID_LENGTH), |data| transform_array_to_vec(data))(rem)?;
    let (rem, further_action_required) = be_u8(rem)?;
    Ok((rem, VehicleAnnouncementMessage {
        vin,
        logical_address,
        eid,
        gid,
        further_action_required,
    }))
}

pub fn parse_routing_activation_request(input: &[u8]) -> IResult<&[u8], RoutingActivationRequestMessage> {
    let (rem, (
        source_address,
        activation_type,
        reserved_by_iso,
    )) = tuple((
        be_u16,
        be_u16,
        be_u32,
    ))(input)?;
    Ok((rem, RoutingActivationRequestMessage {
        source_address,
        activation_type,
        reserved_by_iso,
    }))
}

pub fn parse_routing_activation_response_message(input: &[u8]) -> IResult<&[u8], RoutingActivationResponseMessage> {
    let (rem, (
        logical_address_of_external_tester,
        source_address,
        routing_activation_response_code,
        reserved_by_iso
    )) = tuple((
        be_u16,
        be_u16,
        be_u8,
        be_u32,
    ))(input)?;
    Ok((rem, RoutingActivationResponseMessage {
        logical_address_of_external_tester,
        source_address,
        routing_activation_response_code,
        reserved_by_iso,
    }))
}

pub fn parse_diagnostic_data(input: &[u8], service_identifier: u8) -> IResult<&[u8], DiagnosticData> {
    let service_id = (service_identifier & 0x3F) as u8;
    let reply_flag = if service_identifier & 0x40 != 0 {
        true
    } else {
        false
    };
    match service_id {
        0x34 => {
            if reply_flag == false {
                let (rem, (
                    method,
                    memory_length,
                    memory_address,
                    memory_size
                )) = tuple((
                    be_u8,
                    be_u8,
                    be_u32,
                    be_u32
                ))(input)?;
                Ok((rem, DiagnosticData::RequestDownload(DiagRequestDownload {
                    compression_method: ((method >> 0x04) & 0x0F) as u8,
                    encrypting_method: (method & 0x0F) as u8,
                    memory_size_length: ((memory_length >> 0x04) & 0x0F) as u8,
                    memory_address_length: (memory_length & 0x0F) as u8,
                    memory_address,
                    memory_size,
                })))
            } else {
                let (rem, (
                    memory_address_length,
                    memory_size
                )) = tuple((
                    be_u8,
                    be_u16
                ))(input)?;
                Ok((rem, DiagnosticData::ResponseDownload(DiagResponseDownload {
                    memory_address_length,
                    memory_size,
                })))
            }
        },
        0x36 => {
            if reply_flag == false {
                let (rem, block_sequence_counter) = be_u8(input)?;
                let (rem, block_data) = rest(rem)?;
                Ok((rem, DiagnosticData::RequestTransferData(DiagRequestTransferData {
                    block_sequence_counter,
                    block_data: block_data.to_vec(),
                })))
            } else {
                let (rem, block_sequence_counter) = be_u8(input)?;
                Ok((rem, DiagnosticData::ResponseTransferData(DiagResponseTransferData {
                    block_sequence_counter,
                })))
            }
        },
        0x37 => {
            if reply_flag == false {
                Ok((input, DiagnosticData::RequestTransferExit))
            } else {
                Ok((input, DiagnosticData::ResponseTransferExit))
            }
        }
        0x3e => {
            let (rem, suppress_reply) = be_u8(input)?;
            Ok((rem, DiagnosticData::RequestTestPresent(DiagRequestTestPresent {
                suppress_reply,
            })))
        },
        _ => {
            return Err(Err::Error(make_error(input, ErrorKind::Verify)));
        }
    }
}

pub fn parse_diagnostic_message(input: &[u8], payload_type: u16, length: u32) -> IResult<&[u8], UdsPayload> {
    if payload_type == 0x8002 {
        let (rem, ack_code) = be_u8(input)?;
        Ok((rem, UdsPayload::DiagnosticMessageAck(ack_code)))
    } else {
        let (rem, service_identifier) = be_u8(input)?;
        let (_rem, service_data) = map_res(take(length-1), |data| parse_diagnostic_data(data, service_identifier))(rem)?;
        Ok((service_data.0, UdsPayload::DiagnosticMessage(DiagnosticMessage {
            service_identifier,
            service_data: service_data.1
        })))
    }
}

const UDS_SOURCE_ADDRESS_LENGTH: u32 = 2;
const UDS_TARGET_ADDRESS_LENGTH: u32 = 2;
pub fn parse_uds_message(input: &[u8], payload_type: u16, payload_length: u32) -> IResult<&[u8], UdsMessage> {
    let (rem, source_address) = be_u16(input)?;
    let (rem, target_address) = be_u16(rem)?;
    let (rem, uds_payload) = parse_diagnostic_message(rem, payload_type, payload_length - UDS_SOURCE_ADDRESS_LENGTH - UDS_TARGET_ADDRESS_LENGTH)?;
    Ok((rem, UdsMessage {
        source_address,
        target_address,
        uds_payload,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VEHICLE_ANNOUNCEMENT_MESSAGE: &[u8] = &[
                    0x01, 0xfe, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x20, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x10, 0x01, 0x00, 0x01, 0x02,
        0x03, 0x01, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01
    ];
    #[test]
    fn test_parse_doip_header() {
        match parse_doip_header(VEHICLE_ANNOUNCEMENT_MESSAGE) {
            Ok((rem, header)) => {
                assert_eq!(header, DoIpHeader {
                    version: 0x01,
                    inverse_version: 0xfe,
                    payload_type: 0x0004,
                    payload_length: 0x00000020,
                });
                assert_eq!(rem.len(), header.payload_length as usize);
                match parse_vehicle_announcement_message(rem) {
                    Ok((rem, data)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(data, VehicleAnnouncementMessage {
                            vin: vec![0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51],
                            logical_address: 0x1001,
                            eid: vec![0x00, 0x01, 0x02, 0x03, 0x01, 0x62],
                            gid: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
                            further_action_required: 0x01,
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

    const ROUTING_ACTIVATION_REQUEST: &[u8] = &[
                                            0x01, 0xfe,
        0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x0e, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    #[test]
    fn test_parse_doip_routing_activation_request() {
        match parse_doip_header(ROUTING_ACTIVATION_REQUEST) {
            Ok((rem, header)) => {
                assert_eq!(header, DoIpHeader {
                    version: 0x01,
                    inverse_version: 0xfe,
                    payload_type: 0x0005,
                    payload_length: 0x00000008,
                });
                assert_eq!(rem.len(), header.payload_length as usize);
                match parse_routing_activation_request(rem) {
                    Ok((rem, data)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(data, RoutingActivationRequestMessage {
                            source_address: 0x0e80,
                            activation_type: 0x0000,
                            reserved_by_iso: 0x00000000,
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

    const ROUTING_ACTIVATION_RESPONSE: &[u8] = &[
                                            0x01, 0xfe,
        0x00, 0x06, 0x00, 0x00, 0x00, 0x09, 0x0e, 0x80,
        0x10, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00
    ];
    #[test]
    fn test_parse_doip_routing_activation_response() {
        match parse_doip_header(ROUTING_ACTIVATION_RESPONSE) {
            Ok((rem, header)) => {
                assert_eq!(header, DoIpHeader {
                    version: 0x01,
                    inverse_version: 0xfe,
                    payload_type: 0x0006,
                    payload_length: 0x00000009,
                });
                assert_eq!(rem.len(), header.payload_length as usize);
                match parse_routing_activation_response_message(rem) {
                    Ok((rem, data)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(data, RoutingActivationResponseMessage {
                            logical_address_of_external_tester: 0x0e80,
                            source_address: 0x1001,
                            routing_activation_response_code: 0x10,
                            reserved_by_iso: 0x00000000,
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

    const UDS_REQUEST_TEST_PRESENT: &[u8] = &[
                                            0x01, 0xfe,
        0x80, 0x01, 0x00, 0x00, 0x00, 0x06, 0x0e, 0x80,
        0x1f, 0xff, 0x3e, 0x80      
    ];
    #[test]
    fn test_parse_doip_uds_request_test_present() {
        match parse_doip_header(UDS_REQUEST_TEST_PRESENT) {
            Ok((rem, header)) => {
                assert_eq!(header, DoIpHeader {
                    version: 0x01,
                    inverse_version: 0xfe,
                    payload_type: 0x8001,
                    payload_length: 0x00000006,
                });
                assert_eq!(rem.len(), header.payload_length as usize);
                match parse_uds_message(rem, header.payload_type, header.payload_length) {
                    Ok((rem, data)) => {
                        assert_eq!(data, UdsMessage {
                            source_address: 0x0e80,
                            target_address: 0x1fff,
                            uds_payload: UdsPayload::DiagnosticMessage(DiagnosticMessage {
                                service_identifier: 0x3e,
                                service_data: DiagnosticData::RequestTestPresent(DiagRequestTestPresent {
                                    suppress_reply: 0x80,
                                })
                            }),
                        });
                        assert_eq!(rem.len(), 0);
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
    const UDS_DIAGNOSTIC_MESSAGE_ACK: &[u8] = &[
                                            0x01, 0xfe,
        0x80, 0x02, 0x00, 0x00, 0x00, 0x05, 0x1f, 0xff,
        0x0e, 0x80, 0x00
    ];
    #[test]
    fn test_parse_doip_udp_diagnostic_message_ack() {
        match parse_doip_header(UDS_DIAGNOSTIC_MESSAGE_ACK) {
            Ok((rem, header)) => {
                assert_eq!(header, DoIpHeader {
                    version: 0x01,
                    inverse_version: 0xfe,
                    payload_type: 0x8002,
                    payload_length: 0x00000005,
                });
                assert_eq!(rem.len(), header.payload_length as usize);
                match parse_uds_message(rem, header.payload_type, header.payload_length) {
                    Ok((rem, data)) => {
                        assert_eq!(data, UdsMessage {
                            source_address: 0x1fff,
                            target_address: 0x0e80,
                            uds_payload: UdsPayload::DiagnosticMessageAck(0x00),
                        });
                        assert_eq!(rem.len(), 0);
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

    const UDS_DIAGNOSTIC_REQUEST_DOWNLOAD: &[u8] = &[
                                            0x02, 0xfd,
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x0e, 0x80,
        0x10, 0x11, 0x34, 0x00, 0x44, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x57, 0x0fc
    ];
    #[test]
    fn test_parse_doip_uds_diagnostic_request_download() {
        match parse_doip_header(UDS_DIAGNOSTIC_REQUEST_DOWNLOAD) {
            Ok((rem, header)) => {
                assert_eq!(header, DoIpHeader {
                    version: 0x02,
                    inverse_version: 0xfd,
                    payload_type: 0x8001,
                    payload_length: 0x0000000f,
                });
                assert_eq!(rem.len(), header.payload_length as usize);
                match parse_uds_message(rem, header.payload_type, header.payload_length) {
                    Ok((rem, data)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(data, UdsMessage {
                            source_address: 0x0e80,
                            target_address: 0x1011,
                            uds_payload: UdsPayload::DiagnosticMessage(DiagnosticMessage { 
                                service_identifier: 0x34,
                                service_data: DiagnosticData::RequestDownload(DiagRequestDownload {
                                    compression_method: 0x00,
                                    encrypting_method: 0x00,
                                    memory_size_length: 0x04,
                                    memory_address_length: 0x04,
                                    memory_address: 0x10000000,
                                    memory_size: 0x000057fc,
                                }),
                            })
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

    const UDS_DIAGNOSTIC_RESPONSE_DOWNLOAD: &[u8] = &[
                                            0x02, 0xfd,
        0x80, 0x01, 0x00, 0x00, 0x00, 0x08, 0x10, 0x11,
        0x0e, 0x80, 0x74, 0x20, 0x08, 0x00
    ];
    #[test]
    fn test_parse_doip_uds_diagnostic_response_download() {
        match parse_doip_header(UDS_DIAGNOSTIC_RESPONSE_DOWNLOAD) {
            Ok((rem, header)) => {
                assert_eq!(header, DoIpHeader {
                    version: 0x02,
                    inverse_version: 0xfd,
                    payload_type: 0x8001,
                    payload_length: 0x00000008,
                });
                match parse_uds_message(rem, header.payload_type, header.payload_length) {
                    Ok((rem, data)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(data, UdsMessage {
                            source_address: 0x1011,
                            target_address: 0x0e80,
                            uds_payload: UdsPayload::DiagnosticMessage(DiagnosticMessage {
                                service_identifier: 0x74,
                                service_data: DiagnosticData::ResponseDownload(DiagResponseDownload {
                                    memory_address_length: 0x20,
                                    memory_size: 0x0800,
                                })
                            })
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

    const UDS_DIAGNOSTIC_REQUEST_TRANSFER_DATA: &[u8] = &[
        0x02, 0xfd, 0x80, 0x01, 0x00, 0x00, 0x00, 0x18,
        0x0e, 0x80, 0x10, 0x11, 0x36, 0x01, 0x00, 0x0a,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2, 0x1c,
        0x00, 0x00, 0xc2, 0x1c, 0x00, 0x00, 0xc2, 0x1c,
    ];
    #[test]
    fn test_parse_doip_uds_diagnostic_request_transfer_data() {
        match parse_doip_header(UDS_DIAGNOSTIC_REQUEST_TRANSFER_DATA) {
            Ok((rem, header)) => {
                assert_eq!(header, DoIpHeader {
                    version: 0x02,
                    inverse_version: 0xfd,
                    payload_type: 0x8001,
                    payload_length: 0x00000018,
                });
                match parse_uds_message(rem, header.payload_type, header.payload_length) {
                    Ok((rem, data)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(data, UdsMessage {
                            source_address: 0x0e80,
                            target_address: 0x1011,
                            uds_payload: UdsPayload::DiagnosticMessage(DiagnosticMessage {
                                service_identifier: 0x36,
                                service_data: DiagnosticData::RequestTransferData(DiagRequestTransferData {
                                    block_sequence_counter: 0x01,
                                    block_data: vec![
                                        0x00, 0x0a,
                                        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2, 0x1c,
                                        0x00, 0x00, 0xc2, 0x1c, 0x00, 0x00, 0xc2, 0x1c,
                                    ]
                                })
                            })
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

    const UDS_DIAGNOSTIC_RESONSE_TRANSFER_DATA: &[u8] = &[
                                            0x02, 0xfd,
        0x80, 0x01, 0x00, 0x00, 0x00, 0x06, 0x10, 0x11,
        0x0e, 0x80, 0x76, 0x01
    ];
    #[test]
    fn test_parse_doip_uds_diagnostic_response_transfer_data() {
        match parse_doip_header(UDS_DIAGNOSTIC_RESONSE_TRANSFER_DATA) {
            Ok((rem, header)) => {
                assert_eq!(header, DoIpHeader {
                    version: 0x02,
                    inverse_version: 0xfd,
                    payload_type: 0x8001,
                    payload_length: 0x00000006,
                });
                assert_eq!(rem.len(), header.payload_length as usize);
                match parse_uds_message(rem, header.payload_type, header.payload_length) {
                    Ok((rem, data)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(data, UdsMessage {
                            source_address: 0x1011,
                            target_address: 0x0e80,
                            uds_payload: UdsPayload::DiagnosticMessage(DiagnosticMessage {
                                service_identifier: 0x76,
                                service_data: DiagnosticData::ResponseTransferData(DiagResponseTransferData {
                                    block_sequence_counter: 0x01,
                                })
                            })
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

    const UDS_DIAGNOSTIC_REQUEST_TRANFER_EXIT: &[u8] = &[
                                            0x02, 0xfd,
        0x80, 0x01, 0x00, 0x00, 0x00, 0x05, 0x0e, 0x80,
        0x10, 0x11, 0x37
    ];
    #[test]
    fn test_parse_doip_uds_diagnostic_request_transfer_exit() {
        match parse_doip_header(UDS_DIAGNOSTIC_REQUEST_TRANFER_EXIT) {
            Ok((rem, header)) => {
                assert_eq!(header, DoIpHeader {
                    version: 0x02,
                    inverse_version: 0xfd,
                    payload_type: 0x8001,
                    payload_length: 0x00000005,
                });
                assert_eq!(rem.len(), header.payload_length as usize);
                match parse_uds_message(rem, header.payload_type, header.payload_length) {
                    Ok((rem, data)) => {
                        assert_eq!(rem.len(), 0);
                        assert_eq!(data, UdsMessage {
                            source_address:0x0e80,
                            target_address: 0x1011,
                            uds_payload: UdsPayload::DiagnosticMessage(DiagnosticMessage {
                                service_identifier: 0x37,
                                service_data: DiagnosticData::RequestTransferExit,
                            })
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
}