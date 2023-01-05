use nom7::{IResult, sequence::tuple, bytes::complete::take, number::complete::{be_u8, be_u32, be_u16}, combinator::rest};

const SECURITY_ASSOCIATION_PAYLOAD: u8 = 0x21;
const KEY_EXCHANGE_PAYLOAD: u8 = 0x22;
const IDENTIFICATION_INITIATOR: u8 = 0x23;
const IDENTIFICATION_RESPONDER: u8 = 0x24;
const CERTIFICATE_REQUEST_PAYLOAD: u8 = 0x26;
const NONCE_PAYLOAD: u8 = 0x28;
const NOTIFY_PAYLOAD: u8 = 0x29;
const ENCRYPTED_AND_AUTHENTICATED_PAYLOAD: u8 = 0x2e;

const IKE_SA_INIT: u8 = 0x22;
const IKE_AUTH: u8 = 0x23;

#[derive(Debug, PartialEq)]
pub struct IKEv2Header {
    initiator_spi: Vec<u8>,
    responser_spi: Vec<u8>,
    next_payload: u8,
    version: u8,
    exchange_type: u8,
    flags: u8,
    message_id: u32,
    length: u32,
}

#[derive(Debug, PartialEq)]
pub struct IKEv2CommonPayload {
    next_payload: u8,
    flags: u8,
    payload_length: u16,
    payload: IKEv2Payload,
}

#[derive(Debug, PartialEq)]
pub enum IKEv2Payload {
    SECURITY_ASSOCIATION(SecurityAssociationPayload),
    KEY_EXCHANGE(KeyExchangePayload),
    NONCE(NoncePayload),
    NOTIFY(NotifyPayload),
    CERTIFICATE_REQUEST(CertificateRequestPayload),
    ENCRYPTED_AND_AUTHENTICATED(EncryptedAndAuthenticatedPayload),
}

#[derive(Debug, PartialEq)]
pub struct SecurityAssociationPayload {
    payload: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct KeyExchangePayload {
    dh_group: u16,
    key_exchange_data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct NoncePayload {
    nonce_data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct NotifyPayload {
    protocol_id: u8,
    spi_size: u8,
    notify_message_type: u16,
    notification_data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct CertificateRequestPayload {
    certificate_type: u8,
    certificate_authority_data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct EncryptedAndAuthenticatedPayload {
    initialization_vector: Vec<u8>,
    encrypted_data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct ESPPayload {
    spi: u32,
    sequence: u32,
    encrypted_data: Vec<u8>,
}

pub fn parse_ike_v2_header(input: &[u8]) -> IResult<&[u8], IKEv2Header> {
    let (rem, (
        initiator_spi,
        responser_spi,
        next_payload,
        version,
        exchange_type,
        flags,
        message_id,
        length
    )) = tuple((
        take(8usize),
        take(8usize),
        be_u8,
        be_u8,
        be_u8,
        be_u8,
        be_u32,
        be_u32,
    ))(input)?;
    Ok((rem, IKEv2Header {
        initiator_spi: initiator_spi.to_vec(),
        responser_spi: responser_spi.to_vec(),
        next_payload,
        version,
        exchange_type,
        flags,
        message_id,
        length,
    }))
}

pub fn parse_ike_v2_payload(input: &[u8], current_payload: u8, total_payload_length: u32) -> IResult<&[u8], (u8, u32, IKEv2CommonPayload)> {
    let (rem, (
        next_payload,
        flags,
        payload_length
    )) = tuple((
        be_u8,
        be_u8,
        be_u16
    ))(input)?;
    let real_payload_length = payload_length - 4;
    match current_payload {
        SECURITY_ASSOCIATION_PAYLOAD => {
            let (rem, payload) = take(real_payload_length as usize)(rem)?;
            Ok((rem, (next_payload, (total_payload_length - payload_length as u32), IKEv2CommonPayload {
                next_payload,
                flags,
                payload_length,
                payload: IKEv2Payload::SECURITY_ASSOCIATION(SecurityAssociationPayload {
                    payload: payload.to_vec(),
                }),
            })))
        },
        KEY_EXCHANGE_PAYLOAD => {
            let (rem, (
                dh_group,
                _reserved,
                key_exchange_data
            )) = tuple((
                be_u16,
                be_u16,
                take((real_payload_length - 4) as usize),
            ))(rem)?;
            Ok((rem, (next_payload, (total_payload_length - payload_length as u32), IKEv2CommonPayload {
                next_payload,
                flags,
                payload_length,
                payload: IKEv2Payload::KEY_EXCHANGE(KeyExchangePayload {
                    dh_group,
                    key_exchange_data: key_exchange_data.to_vec(),
                }),
            })))
        },
        NONCE_PAYLOAD => {
            let (rem, nonce_data) = take(real_payload_length as usize)(rem)?;
            Ok((rem, (next_payload, (total_payload_length - payload_length as u32), IKEv2CommonPayload {
                next_payload,
                flags,
                payload_length,
                payload: IKEv2Payload::NONCE(NoncePayload {
                    nonce_data: nonce_data.to_vec(),
                }),
            })))
        },
        NOTIFY_PAYLOAD => {
            let (rem, (
                protocol_id,
                spi_size,
                notify_message_type,
                notification_data
            )) = tuple((
                be_u8,
                be_u8,
                be_u16,
                take((real_payload_length - 4) as usize),
            ))(rem)?;
            Ok((rem, (next_payload, (total_payload_length - payload_length as u32), IKEv2CommonPayload {
                next_payload,
                flags,
                payload_length,
                payload: IKEv2Payload::NOTIFY(NotifyPayload {
                    protocol_id,
                    spi_size,
                    notify_message_type,
                    notification_data: notification_data.to_vec(),
                }),
            })))
        },
        CERTIFICATE_REQUEST_PAYLOAD => {
            let (rem, (
                certificate_type,
                certificate_authority_data,
            )) = tuple((
                be_u8,
                take((real_payload_length - 1) as usize),
            ))(rem)?;
            Ok((rem, (next_payload, (total_payload_length - payload_length as u32), IKEv2CommonPayload {
                next_payload,
                flags,
                payload_length,
                payload: IKEv2Payload::CERTIFICATE_REQUEST(CertificateRequestPayload {
                    certificate_type,
                    certificate_authority_data: certificate_authority_data.to_vec(),
                }),
            })))
        },
        ENCRYPTED_AND_AUTHENTICATED_PAYLOAD => {
            let (rem, (
                initialization_vector,
                encrypted_data
            )) = tuple((
                take(4usize),
                take((real_payload_length - 4) as usize),
            ))(rem)?;
            Ok((rem, (next_payload, (total_payload_length - payload_length as u32), IKEv2CommonPayload {
                next_payload,
                flags,
                payload_length,
                payload: IKEv2Payload::ENCRYPTED_AND_AUTHENTICATED(EncryptedAndAuthenticatedPayload {
                    initialization_vector: initialization_vector.to_vec(),
                    encrypted_data: encrypted_data.to_vec(),
                }),
            })))
        },
        _ => {
            unimplemented!();
        }
    }
}

pub fn parse_ike_v2_payloads(input: &[u8], next_payload: u8, payloads_length: u32) -> IResult<&[u8], Vec<IKEv2CommonPayload>> {
    let mut rem = input;
    let mut next_payload = next_payload;
    let mut remain_payload_length = payloads_length;
    let mut ikev2_common_payloads = Vec::new();
    loop {
        if remain_payload_length == 0 || next_payload == 0x00 {
            break;
        }
        let (tmp_rem, (tmp_next_payload, tmp_remain_payload_length, ike_v2_common_payload)) = parse_ike_v2_payload(rem, next_payload, remain_payload_length)?;
        ikev2_common_payloads.push(ike_v2_common_payload);
        next_payload = tmp_next_payload;
        remain_payload_length = tmp_remain_payload_length;
        rem = tmp_rem;
    }
    Ok((rem, ikev2_common_payloads))
}

pub fn parse_esp_payload(input: &[u8]) -> IResult<&[u8], ESPPayload> {
    let (rem, (
        spi,
        sequence,
        encrypted_data
    )) = tuple((
        be_u32,
        be_u32,
        rest,
    ))(input)?;
    Ok((rem, ESPPayload {
        spi,
        sequence,
        encrypted_data: encrypted_data.to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ikev2_initiator_request() {
        let pcap = include_bytes!("pcaps/ikev2/ikev2_initiator_request.pcap");
        let payload = &pcap[24+16+42..];
        match parse_ike_v2_header(payload) {
            Ok((rem, header)) => {
                assert_eq!(header.initiator_spi, vec![0x12, 0xbd, 0x6d, 0x68, 0xf1, 0x99, 0xec, 0x64]);
                assert_eq!(header.responser_spi, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                assert_eq!(header.next_payload, SECURITY_ASSOCIATION_PAYLOAD);
                assert_eq!(header.version, 0x20);
                assert_eq!(header.exchange_type, IKE_SA_INIT);
                assert_eq!(header.flags, 0x08);
                assert_eq!(header.message_id, 0x00000000);
                assert_eq!(header.length, 0x00000330);
                match parse_ike_v2_payloads(rem, header.next_payload, header.length - 28) {
                    Ok((rem, payloads)) => {
                        assert_eq!(rem.len(), 0x00);
                        assert_eq!(payloads.len(), 0x07);
                        assert_eq!(payloads[0], IKEv2CommonPayload {
                            next_payload: KEY_EXCHANGE_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x0198,
                            payload: IKEv2Payload::SECURITY_ASSOCIATION(SecurityAssociationPayload {
                                payload: vec![2, 0, 0, 200, 1, 1, 0, 21, 3, 0, 0, 12, 1, 0, 0, 13, 128, 14, 1, 0, 3, 0, 0, 12, 1, 0, 0, 12, 128, 14, 1, 0, 3, 0, 0, 12, 1, 0, 0, 13, 128, 14, 0, 192, 3, 0, 0, 12, 1, 0, 0, 12, 128, 14, 0, 192, 3, 0, 0, 12, 1, 0, 0, 13, 128, 14, 0, 128, 3, 0, 0, 12, 1, 0, 0, 12, 128, 14, 0, 128, 3, 0, 0, 8, 3, 0, 0, 14, 3, 0, 0, 8, 3, 0, 0, 13, 3, 0, 0, 8, 3, 0, 0, 12, 3, 0, 0, 8, 3, 0, 0, 5, 3, 0, 0, 8, 3, 0, 0, 8, 3, 0, 0, 8, 4, 0, 0, 16, 3, 0, 0, 8, 4, 0, 0, 31, 3, 0, 0, 8, 4, 0, 0, 15, 3, 0, 0, 8, 4, 0, 0, 14, 3, 0, 0, 8, 2, 0, 0, 2, 3, 0, 0, 8, 2, 0, 0, 4, 3, 0, 0, 8, 2, 0, 0, 5, 3, 0, 0, 8, 2, 0, 0, 6, 3, 0, 0, 8, 2, 0, 0, 7, 0, 0, 0, 8, 2, 0, 0, 8, 0, 0, 0, 204, 2, 1, 0, 20, 3, 0, 0, 8, 1, 0, 0, 28, 3, 0, 0, 12, 1, 0, 0, 20, 128, 14, 1, 0, 3, 0, 0, 12, 1, 0, 0, 19, 128, 14, 1, 0, 3, 0, 0, 12, 1, 0, 0, 18, 128, 14, 1, 0, 3, 0, 0, 12, 1, 0, 0, 20, 128, 14, 0, 192, 3, 0, 0, 12, 1, 0, 0, 19, 128, 14, 0, 192, 3, 0, 0, 12, 1, 0, 0, 18, 128, 14, 0, 192, 3, 0, 0, 12, 1, 0, 0, 20, 128, 14, 0, 128, 3, 0, 0, 12, 1, 0, 0, 19, 128, 14, 0, 128, 3, 0, 0, 12, 1, 0, 0, 18, 128, 14, 0, 128, 3, 0, 0, 8, 4, 0, 0, 16, 3, 0, 0, 8, 4, 0, 0, 31, 3, 0, 0, 8, 4, 0, 0, 15, 3, 0, 0, 8, 4, 0, 0, 14, 3, 0, 0, 8, 2, 0, 0, 2, 3, 0, 0, 8, 2, 0, 0, 4, 3, 0, 0, 8, 2, 0, 0, 5, 3, 0, 0, 8, 2, 0, 0, 6, 3, 0, 0, 8, 2, 0, 0, 7, 0, 0, 0, 8, 2, 0, 0, 8], 
                            })
                        });
                        assert_eq!(payloads[1], IKEv2CommonPayload {
                            next_payload: NONCE_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x0108,
                            payload: IKEv2Payload::KEY_EXCHANGE(KeyExchangePayload {
                                dh_group: 0x000e,
                                key_exchange_data: vec![103, 94, 185, 129, 117, 9, 133, 239, 83, 143, 79, 68, 125, 159, 165, 221, 9, 70, 97, 205, 119, 94, 229, 76, 184, 143, 215, 230, 197, 187, 241, 232, 152, 84, 74, 246, 5, 158, 12, 170, 211, 91, 74, 112, 223, 4, 123, 89, 232, 25, 69, 226, 45, 127, 80, 194, 163, 18, 13, 180, 83, 211, 81, 173, 8, 16, 253, 21, 229, 65, 135, 63, 181, 189, 153, 61, 82, 43, 43, 110, 25, 219, 152, 92, 246, 52, 164, 153, 65, 231, 112, 111, 109, 45, 187, 11, 71, 12, 244, 122, 43, 211, 25, 197, 248, 93, 229, 11, 32, 80, 29, 85, 71, 135, 27, 121, 116, 42, 109, 174, 230, 35, 211, 238, 23, 253, 146, 28, 222, 64, 106, 246, 52, 242, 173, 191, 73, 153, 26, 194, 255, 96, 194, 161, 150, 112, 194, 28, 35, 105, 172, 195, 82, 82, 62, 213, 125, 32, 134, 243, 162, 42, 209, 224, 188, 45, 31, 76, 60, 92, 114, 190, 81, 13, 45, 64, 157, 39, 227, 41, 109, 239, 119, 88, 2, 197, 170, 10, 169, 6, 96, 148, 163, 4, 198, 162, 251, 40, 133, 209, 20, 74, 138, 211, 161, 218, 42, 154, 32, 149, 218, 143, 141, 124, 2, 146, 0, 0, 108, 53, 65, 212, 87, 191, 59, 154, 202, 194, 101, 210, 206, 154, 8, 200, 130, 14, 17, 74, 127, 35, 37, 164, 82, 15, 107, 45, 245, 41, 2, 23, 185, 255, 143, 178, 64, 85],
                            }),
                        });
                        assert_eq!(payloads[2], IKEv2CommonPayload {
                            next_payload: NOTIFY_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x0024,
                            payload: IKEv2Payload::NONCE(NoncePayload {
                                nonce_data: vec![240, 38, 212, 244, 131, 154, 56, 4, 97, 157, 168, 184, 95, 227, 232, 1, 156, 243, 88, 171, 49, 30, 172, 123, 186, 255, 63, 120, 195, 237, 207, 255],
                            }),
                        });
                        assert_eq!(payloads[3], IKEv2CommonPayload {
                            next_payload: NOTIFY_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x001c,
                            payload: IKEv2Payload::NOTIFY(NotifyPayload {
                                protocol_id: 0x00,
                                spi_size: 0x00,
                                notify_message_type:0x4004,
                                notification_data: vec![192, 214, 245, 31, 122, 10, 164, 104, 147, 171, 75, 25, 16, 208, 14, 29, 122, 236, 13, 131],
                            }),
                        });
                        assert_eq!(payloads[4], IKEv2CommonPayload {
                            next_payload: NOTIFY_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x001c,
                            payload: IKEv2Payload::NOTIFY(NotifyPayload {
                                protocol_id: 0x00,
                                spi_size: 0x00,
                                notify_message_type:0x4005,
                                notification_data: vec![247, 5, 81, 89, 58, 175, 189, 197, 98, 143, 85, 174, 73, 113, 125, 192, 9, 73, 233, 101],
                            }),
                        });
                        assert_eq!(payloads[5], IKEv2CommonPayload {
                            next_payload: NOTIFY_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x0008,
                            payload: IKEv2Payload::NOTIFY(NotifyPayload {
                                protocol_id: 0x00,
                                spi_size: 0x00,
                                notify_message_type:0x402e,
                                notification_data: vec![],
                            }),
                        });
                        assert_eq!(payloads[6], IKEv2CommonPayload {
                            next_payload: 0x00,
                            flags: 0x00,
                            payload_length: 0x0010,
                            payload: IKEv2Payload::NOTIFY(NotifyPayload {
                                protocol_id: 0x00,
                                spi_size: 0x00,
                                notify_message_type:0x402f,
                                notification_data: vec![0, 1, 0, 2, 0, 3, 0, 4],
                            }),
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

    #[test]
    fn test_parse_ikev2_responder_response() {
        let pcap = include_bytes!("pcaps/ikev2/ikev2_responder_response.pcap");
        let payload = &pcap[24+16+42..];
        match parse_ike_v2_header(payload) {
            Ok((rem, header)) => {
                assert_eq!(header.initiator_spi, vec![0x12, 0xbd, 0x6d, 0x68, 0xf1, 0x99, 0xec, 0x64]);
                assert_eq!(header.responser_spi, vec![0x73, 0xc8, 0x7f, 0xfb, 0xbf, 0xc8, 0x8a, 0x91]);
                assert_eq!(header.next_payload, SECURITY_ASSOCIATION_PAYLOAD);
                assert_eq!(header.version, 0x20);
                assert_eq!(header.exchange_type, IKE_SA_INIT);
                assert_eq!(header.flags, 0x20);
                assert_eq!(header.message_id, 0x00000000);
                assert_eq!(header.length, 0x000001e1);
                match parse_ike_v2_payloads(rem, header.next_payload, header.length - 28) {
                    Ok((rem, payloads)) => {
                        assert_eq!(rem.len(), 0x00);
                        assert_eq!(payloads.len(), 0x08);
                        assert_eq!(payloads[0], IKEv2CommonPayload {
                            next_payload: KEY_EXCHANGE_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x0030,
                            payload: IKEv2Payload::SECURITY_ASSOCIATION(SecurityAssociationPayload {
                                payload: vec![0, 0, 0, 44, 1, 1, 0, 4, 3, 0, 0, 12, 1, 0, 0, 12, 128, 14, 0, 128, 3, 0, 0, 8, 3, 0, 0, 5, 3, 0, 0, 8, 2, 0, 0, 4, 0, 0, 0, 8, 4, 0, 0, 14],
                            }),
                        });
                        assert_eq!(payloads[1], IKEv2CommonPayload {
                            next_payload: NONCE_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x0108,
                            payload: IKEv2Payload::KEY_EXCHANGE(KeyExchangePayload {
                                dh_group: 0x000e,
                                key_exchange_data: vec![202, 213, 72, 34, 12, 56, 85, 158, 17, 171, 51, 53, 212, 74, 235, 165, 40, 211, 6, 227, 154, 251, 111, 103, 8, 41, 50, 157, 122, 37, 166, 162, 154, 48, 222, 119, 47, 132, 224, 161, 92, 132, 61, 206, 193, 45, 74, 161, 165, 249, 120, 70, 218, 145, 23, 36, 81, 45, 64, 30, 130, 36, 218, 127, 176, 214, 207, 158, 156, 191, 44, 35, 249, 79, 197, 147, 146, 128, 110, 89, 33, 59, 64, 202, 115, 63, 169, 58, 40, 183, 227, 127, 73, 140, 132, 221, 185, 39, 143, 60, 146, 250, 66, 236, 18, 48, 65, 124, 207, 224, 115, 255, 123, 203, 239, 59, 144, 77, 1, 96, 28, 176, 224, 118, 28, 251, 112, 13, 245, 92, 47, 104, 4, 48, 51, 91, 181, 20, 224, 172, 141, 247, 69, 30, 226, 181, 83, 59, 3, 94, 223, 187, 227, 64, 43, 206, 187, 218, 5, 58, 198, 42, 122, 234, 203, 137, 196, 235, 172, 112, 245, 89, 65, 35, 28, 23, 239, 97, 99, 140, 4, 19, 18, 72, 145, 59, 33, 170, 236, 149, 202, 86, 90, 222, 49, 19, 55, 15, 114, 9, 70, 44, 162, 228, 171, 70, 89, 251, 124, 185, 20, 220, 251, 75, 148, 114, 113, 228, 85, 38, 24, 205, 115, 150, 94, 253, 69, 168, 21, 142, 108, 5, 1, 82, 162, 202, 211, 10, 51, 204, 54, 200, 43, 7, 150, 249, 222, 255, 222, 90, 229, 99, 230, 125, 55, 121],
                            }),
                        });
                        assert_eq!(payloads[2], IKEv2CommonPayload {
                            next_payload: NOTIFY_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x0024,
                            payload: IKEv2Payload::NONCE(NoncePayload {
                                nonce_data: vec![120, 117, 53, 246, 199, 166, 171, 198, 212, 219, 20, 228, 213, 3, 4, 81, 138, 206, 88, 62, 150, 113, 167, 207, 178, 168, 80, 44, 85, 81, 40, 183],
                            }),
                        });
                        assert_eq!(payloads[3], IKEv2CommonPayload {
                            next_payload: NOTIFY_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x001c,
                            payload: IKEv2Payload::NOTIFY(NotifyPayload {
                                protocol_id: 0x00,
                                spi_size: 0x00,
                                notify_message_type: 0x4004,
                                notification_data: vec![192, 80, 107, 0, 121, 194, 196, 32, 45, 119, 171, 43, 55, 130, 9, 174, 239, 247, 151, 232],
                            }),
                        });
                        assert_eq!(payloads[4], IKEv2CommonPayload {
                            next_payload: CERTIFICATE_REQUEST_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x001c,
                            payload: IKEv2Payload::NOTIFY(NotifyPayload {
                                protocol_id: 0x00,
                                spi_size: 0x00,
                                notify_message_type: 0x4005,
                                notification_data: vec![26, 200, 237, 61, 111, 25, 215, 177, 90, 70, 164, 30, 32, 45, 3, 134, 26, 170, 179, 117],
                            }),
                        });
                        assert_eq!(payloads[5], IKEv2CommonPayload {
                            next_payload: NOTIFY_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x0019,
                            payload: IKEv2Payload::CERTIFICATE_REQUEST(CertificateRequestPayload {
                                certificate_type: 0x04,
                                certificate_authority_data: vec![132, 30, 166, 214, 154, 109, 234, 166, 66, 18, 193, 125, 29, 144, 145, 234, 249, 146, 163, 173],
                            }),
                        });
                        assert_eq!(payloads[6], IKEv2CommonPayload {
                            next_payload: NOTIFY_PAYLOAD,
                            flags: 0x00,
                            payload_length: 0x0010,
                            payload: IKEv2Payload::NOTIFY(NotifyPayload {
                                protocol_id: 0x00,
                                spi_size: 0x00,
                                notify_message_type: 0x402f,
                                notification_data: vec![0, 1, 0, 2, 0, 3, 0, 4],
                            })
                        });
                        assert_eq!(payloads[7], IKEv2CommonPayload {
                           next_payload: 0x00,
                           flags: 0x00,
                           payload_length: 0x0008,
                           payload: IKEv2Payload::NOTIFY(NotifyPayload {
                                protocol_id: 0x00,
                                spi_size: 0x00,
                                notify_message_type: 0x4014,
                                notification_data: vec![],
                           }),
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

    #[test]
    fn test_parse_ikev2_auth_initiator_request() {
        let pcap = include_bytes!("pcaps/ikev2/ikev2_auth_initiator_request.pcap");
        let payload = &pcap[24+16+42+4..];
        match parse_ike_v2_header(payload) {
            Ok((rem, header)) => {
                assert_eq!(header.initiator_spi, vec![0x12, 0xbd, 0x6d, 0x68, 0xf1, 0x99, 0xec, 0x64]);
                assert_eq!(header.responser_spi, vec![0x73, 0xc8, 0x7f, 0xfb, 0xbf, 0xc8, 0x8a, 0x91]);
                assert_eq!(header.next_payload, ENCRYPTED_AND_AUTHENTICATED_PAYLOAD);
                assert_eq!(header.version, 0x20);
                assert_eq!(header.exchange_type, IKE_AUTH);
                assert_eq!(header.flags, 0x08);
                assert_eq!(header.message_id, 0x00000001);
                assert_eq!(header.length, 0x000001ec);
                match parse_ike_v2_payloads(rem, header.next_payload, header.length - 28) {
                    Ok((rem, payloads)) => {
                        assert_eq!(rem.len(), 0x00);
                        assert_eq!(payloads.len(), 0x01);
                        assert_eq!(payloads[0], IKEv2CommonPayload {
                            next_payload: IDENTIFICATION_INITIATOR,
                            flags: 0x00,
                            payload_length: 0x01d0,
                            payload: IKEv2Payload::ENCRYPTED_AND_AUTHENTICATED(EncryptedAndAuthenticatedPayload {
                                initialization_vector: vec![0x03, 0xd7, 0x36, 0xdd],
                                encrypted_data: vec![69, 155, 155, 184, 71, 239, 58, 123, 191, 69, 136, 38, 100, 226, 7, 69, 231, 230, 242, 8, 66, 220, 130, 155, 106, 135, 102, 183, 229, 139, 230, 105, 231, 69, 161, 22, 103, 247, 193, 201, 113, 237, 36, 147, 112, 167, 247, 140, 70, 59, 13, 117, 251, 222, 223, 234, 232, 220, 201, 107, 141, 150, 108, 231, 209, 62, 146, 51, 209, 133, 111, 1, 14, 196, 21, 31, 138, 174, 111, 241, 138, 33, 134, 171, 94, 74, 81, 209, 174, 5, 110, 83, 127, 142, 92, 175, 23, 10, 223, 238, 130, 192, 209, 195, 221, 95, 25, 87, 32, 238, 24, 194, 223, 171, 119, 101, 122, 172, 65, 66, 71, 83, 255, 64, 224, 104, 210, 160, 215, 238, 76, 169, 57, 106, 204, 66, 197, 170, 52, 125, 39, 248, 113, 233, 229, 113, 42, 204, 54, 226, 138, 120, 202, 146, 214, 144, 41, 244, 176, 24, 210, 158, 46, 175, 75, 52, 139, 80, 30, 32, 53, 103, 116, 192, 194, 173, 103, 142, 111, 77, 101, 233, 17, 109, 193, 86, 212, 237, 175, 195, 187, 68, 152, 102, 172, 58, 87, 234, 180, 133, 173, 34, 183, 96, 253, 168, 142, 222, 155, 206, 147, 240, 162, 19, 224, 7, 186, 46, 75, 139, 129, 178, 223, 45, 78, 226, 49, 14, 253, 162, 124, 76, 251, 40, 29, 213, 206, 243, 58, 58, 156, 228, 65, 67, 64, 150, 7, 205, 100, 10, 144, 24, 149, 21, 141, 158, 110, 129, 250, 113, 216, 208, 235, 196, 15, 77, 189, 104, 91, 109, 100, 83, 44, 48, 149, 118, 182, 202, 26, 244, 219, 195, 188, 254, 159, 150, 1, 31, 119, 145, 2, 93, 49, 31, 72, 200, 134, 87, 88, 232, 140, 100, 252, 247, 91, 22, 95, 235, 27, 69, 244, 229, 77, 19, 181, 10, 69, 159, 195, 189, 178, 173, 35, 213, 199, 31, 93, 178, 11, 45, 75, 167, 153, 140, 118, 84, 88, 94, 88, 149, 53, 236, 7, 217, 86, 0, 210, 119, 217, 153, 3, 144, 1, 62, 174, 208, 252, 53, 240, 250, 211, 199, 95, 58, 247, 17, 191, 124, 172, 34, 200, 150, 223, 227, 189, 52, 192, 8, 121, 218, 147, 122, 38, 249, 99, 30, 107, 6, 21, 201, 255, 145, 185, 22, 188, 231, 200, 120, 116, 199, 66, 123, 198, 116, 81, 11, 2, 224, 135, 39, 135, 119, 161, 35, 73, 110, 67, 149, 100, 231, 194, 192, 240, 186, 126, 200, 45, 30, 83, 169, 151, 219, 156, 52, 238, 229, 77, 219, 223, 71, 73, 3, 105, 120, 202, 203, 3, 79, 42, 107, 57, 237, 141, 246, 67, 187],
                            }),
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

    #[test]
    fn test_parse_ikev2_auth_responder_response() {
        let pcap = include_bytes!("pcaps/ikev2/ikev2_auth_responder_reponse.pcap");
        let payload = &pcap[24+16+42+4..];
        match parse_ike_v2_header(payload) {
            Ok((rem, header)) => {
                assert_eq!(header.initiator_spi, vec![0x12, 0xbd, 0x6d, 0x68, 0xf1, 0x99, 0xec, 0x64]);
                assert_eq!(header.responser_spi, vec![0x73, 0xc8, 0x7f, 0xfb, 0xbf, 0xc8, 0x8a, 0x91]);
                assert_eq!(header.next_payload, ENCRYPTED_AND_AUTHENTICATED_PAYLOAD);
                assert_eq!(header.version, 0x20);
                assert_eq!(header.exchange_type, IKE_AUTH);
                assert_eq!(header.flags, 0x20);
                assert_eq!(header.message_id, 0x00000001);
                assert_eq!(header.length, 0x000000dc);
                match parse_ike_v2_payloads(rem, header.next_payload, header.length - 28) {
                    Ok((rem, payloads)) => {
                        assert_eq!(rem.len(), 0x00);
                        assert_eq!(payloads.len(), 0x01);
                        assert_eq!(payloads[0], IKEv2CommonPayload {
                            next_payload: IDENTIFICATION_RESPONDER,
                            flags: 0x00,
                            payload_length: 0x00c0,
                            payload: IKEv2Payload::ENCRYPTED_AND_AUTHENTICATED(EncryptedAndAuthenticatedPayload {
                                initialization_vector: vec![0x63, 0xa4, 0x66, 0x32],
                                encrypted_data: vec![109, 124, 111, 128, 102, 96, 64, 212, 38, 69, 114, 181, 131, 203, 75, 250, 198, 147, 178, 61, 250, 204, 120, 199, 176, 128, 255, 76, 231, 183, 85, 107, 68, 207, 182, 99, 90, 98, 160, 250, 59, 114, 176, 87, 110, 188, 104, 170, 43, 113, 155, 18, 221, 234, 134, 41, 168, 111, 181, 99, 51, 16, 164, 180, 86, 169, 243, 166, 13, 56, 123, 129, 192, 58, 219, 176, 124, 168, 150, 131, 145, 53, 153, 133, 72, 172, 167, 93, 158, 56, 43, 28, 108, 255, 175, 115, 14, 68, 158, 162, 20, 245, 122, 62, 58, 212, 213, 121, 94, 192, 70, 132, 158, 172, 57, 177, 185, 204, 121, 61, 128, 80, 253, 205, 115, 179, 225, 121, 160, 59, 200, 102, 4, 237, 70, 43, 93, 232, 222, 181, 135, 87, 211, 164, 255, 23, 49, 180, 229, 106, 108, 155, 83, 109, 255, 163, 152, 149, 235, 182, 59, 102, 92, 200, 237, 253, 206, 177, 94, 221, 19, 208, 58, 162, 60, 227, 26, 133, 67, 53, 86, 168, 38, 71],
                            }),
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

    #[test]
    fn test_parse_esp_payload() {
        let pcap = include_bytes!("pcaps/ikev2/ikev2_esp_payload.pcap");
        let payload = &pcap[24+16+42..];
        match parse_esp_payload(payload) {
            Ok((rem, payload)) => {
                assert_eq!(rem.len(), 0x00);
                assert_eq!(payload, ESPPayload {
                    spi: 0xc4e50bd0,
                    sequence: 0x00000001,
                    encrypted_data: vec![249, 224, 76, 128, 174, 237, 95, 110, 63, 96, 126, 212, 23, 140, 159, 103, 87, 55, 122, 47, 106, 215, 203, 215, 186, 103, 47, 141, 0, 93, 246, 156, 140, 94, 215, 27, 153, 75, 225, 71, 152, 4, 248, 62, 240, 16, 174, 242, 226, 3, 62, 85, 89, 84, 127, 227, 132, 115, 147, 160, 1, 127, 47, 158, 140, 250, 210, 182, 208, 123, 219, 79, 9, 21, 18, 247, 77, 15, 217, 26, 159, 115, 210, 158, 34, 12, 161, 222, 129, 245, 47, 154, 94, 211, 232, 21],
                })
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }        
    }
}