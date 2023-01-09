use nom7::{IResult, sequence::tuple, bytes::complete::take, number::complete::{le_u8, le_u32, le_u16}, multi::length_data, combinator::rest};

const OPCUA_MESSAGE_TYPE_LENGTH: usize = 3;
const OPCUA_SENDER_CERTIFICATE_LENGTH: usize = 4;
const OPCUA_RECEIVER_CERTIFICATE_THUMBPRINT_LENGTH: usize = 4;

#[derive(Debug, PartialEq)]
pub struct OPCUAHelloHeader {
    message_type: String,
    chunk_type: u8,
    message_size: u32,
    version: u32,
    receive_buffer_size: u32,
    send_buffer_size: u32,
    max_message_size: u32,
    max_chunk_count: u32,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAOpenHeader {
    message_type: String,
    chunk_type: u8,
    message_size: u32,
    secure_channel_id: u32,
    security_policy_uri: String,
    sender_certificate: Vec<u8>,
    receiver_certificate_thumbprint: Vec<u8>,
    sequence_number: u32,
    request_id: u32,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAMessageHeader {
    message_type: String,
    chunk_type: u8,
    message_size: u32,
    security_channel_id: u32,
    security_token_id: u32,
    security_sequence_number: u32,
    security_request_id: u32,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAHelloMessage {
    endpoint_url: String,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAMessageTypeId {
    encoding_mask: u8,
    namespace_index: u8,
    identifier_numeric: u16,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAMessageAdditionalHeader {
    type_id: u16,
    encoding_mask: u8,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAMessageRequestHeader {
    authorization_token: u16,
    timestamp: Vec<u8>,
    request_handle: u32,
    return_diagnostic: u32,
    audit_entry_id: Vec<u8>,
    timeout_hint: u32,
    addition_header: OPCUAMessageAdditionalHeader,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAMessageResponseHeader {
    timestamp: Vec<u8>,
    request_handle: u32,
    service_result: u32,
    service_diagnostics: u8,
    string_table: Vec<u8>,
    additional_header: OPCUAMessageAdditionalHeader,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAOpenMessageSecurityToken {
    channel_id: u32,
    token_id: u32,
    created_at: Vec<u8>,
    revised_lifetime: u32,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAOpenMessageOpenSecureChannelRequest {
    request_header: OPCUAMessageRequestHeader,
    client_protocol_version: u32,
    security_token_request_type: u32,
    message_security_mode: u32,
    client_nonce: u32,
    requested_lifetime: u32,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAOpenMessageOpenSecureChannelResponse {
    response_header: OPCUAMessageResponseHeader,
    server_protocol_version: u32,
    security_token: OPCUAOpenMessageSecurityToken,
    server_nonce: u8,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAOpenMessageRequest {
    open_secure_channel_request: OPCUAOpenMessageOpenSecureChannelRequest,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAOpenMessageResponse {
    open_secure_channel_response: OPCUAOpenMessageOpenSecureChannelResponse,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAGetEndpointRequest {
    request_header: OPCUAMessageRequestHeader,
    endpoint_url: Vec<u8>,
    local_ids: Vec<u8>,
    profile_uris: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct OPCUALocalizedText {
    encoding_mask: u8,
    text: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct OPCUADiscoveryUrls {
    array_size: u32,
    discovery_urls: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAApplicationDescription {
    application_uri: Vec<u8>,
    product_uri: Vec<u8>,
    application_name: OPCUALocalizedText,
    application_type: u32,
    gateway_server_uri: Vec<u8>,
    discovery_profile_uri: Vec<u8>,
    discovery_urls: OPCUADiscoveryUrls,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAUserTokenPolicy {
    policy_id: u8,
    user_token_type: u32,
    issued_token_type: Vec<u8>,
    issuer_endpoint_url: Vec<u8>,
    security_policy_uri: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAUserTokenPolicies {
    array_size: u32,
    user_token_policies: Vec<OPCUAUserTokenPolicy>,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAEndpointDescription {
    endpoint_url: String,
    server: OPCUAApplicationDescription,
    server_certificate: Vec<u8>,
    message_security_mode: u32,
    security_policy_uri: Vec<u8>,
    user_identity_tokens: OPCUAUserTokenPolicies,
    transport_profile_uri: Vec<u8>,
    security_level: u8,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAEndpointsInfo {
    array_size: u32,
    endpoints: Vec<OPCUAEndpointDescription>,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAGetEndpointResponse {
    response_header: OPCUAMessageResponseHeader,
    endpoints: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum OPCUASpecificMessage {
    OPEN_REQUEST(OPCUAOpenMessageRequest),
    OPEN_RESPONSE(OPCUAOpenMessageResponse),
    GET_ENDPOINT_REQUEST(OPCUAGetEndpointRequest),
    GET_ENDPOINT_RESPONSE(OPCUAGetEndpointResponse),
}

#[derive(Debug, PartialEq)]
pub struct OPCUAMessage {
    type_id: OPCUAMessageTypeId,
    message: OPCUASpecificMessage,
}

#[derive(Debug, PartialEq)]
pub enum OPCUAHeader {
    HELLO(OPCUAHelloHeader),
    OPEN(OPCUAOpenHeader),
    MESSAGE(OPCUAMessageHeader),
}

#[derive(Debug, PartialEq)]
pub enum OPCUAContents {
    HELLO(OPCUAHelloMessage),
    OPEN(OPCUAMessage),
    MESSAGE(OPCUAMessage),
    NONE,
}

#[derive(Debug, PartialEq)]
pub struct OPCUA {
    header: OPCUAHeader,
    contents: OPCUAContents,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAErrorMessage {
    message_type: String,
    chunk_type: u8,
    message_size: u32,
    error: Vec<u8>,
    reason: Vec<u8>,
}

pub fn parse_opcua_hello_header(input: &[u8]) -> IResult<&[u8], OPCUAHelloHeader> {
    let (rem, (
        message_type,
        chunk_type,
        message_size,
        version,
        receive_buffer_size,
        send_buffer_size,
        max_message_size,
        max_chunk_count,
    )) = tuple((
        take(OPCUA_MESSAGE_TYPE_LENGTH),
        le_u8,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
    ))(input)?;
    let message_type = String::from_utf8(message_type.to_vec()).unwrap();
    Ok((rem, OPCUAHelloHeader {
        message_type,
        chunk_type,
        message_size,
        version,
        receive_buffer_size,
        send_buffer_size,
        max_message_size,
        max_chunk_count,
    }))
}

pub fn parse_opcua_hello_message(input: &[u8]) -> IResult<&[u8], OPCUAHelloMessage> {
    let (rem, message) = length_data(le_u32)(input)?;
    let endpoint_url = String::from_utf8(message.to_vec()).unwrap();
    Ok((rem, OPCUAHelloMessage {
        endpoint_url,
    }))
}

pub fn parse_opcua_open_header(input: &[u8]) -> IResult<&[u8], OPCUAOpenHeader> {
    let (rem, (
        message_type,
        chunk_type,
        message_size,
        secure_channel_id,
        security_policy_uri,
        sender_certificate,
        receiver_certificate_thumbprint,
        sequence_number,
        request_id,
    )) = tuple((
        take(OPCUA_MESSAGE_TYPE_LENGTH),
        le_u8,
        le_u32,
        le_u32,
        length_data(le_u32),
        take(OPCUA_SENDER_CERTIFICATE_LENGTH),
        take(OPCUA_RECEIVER_CERTIFICATE_THUMBPRINT_LENGTH),
        le_u32,
        le_u32,
    ))(input)?;
    Ok((rem, OPCUAOpenHeader {
        message_type: String::from_utf8(message_type.to_vec()).unwrap(),
        chunk_type,
        message_size,
        secure_channel_id,
        security_policy_uri: String::from_utf8(security_policy_uri.to_vec()).unwrap(),
        sender_certificate: sender_certificate.to_vec(),
        receiver_certificate_thumbprint: receiver_certificate_thumbprint.to_vec(),
        sequence_number,
        request_id,
    }))
}

pub fn parse_opcua_message_header(input: &[u8]) -> IResult<&[u8], OPCUAMessageHeader> {
    let (rem, (
        message_type,
        chunk_type,
        message_size,
        security_channel_id,
        security_token_id,
        security_sequence_number,
        security_request_id,
    )) = tuple((
        take(OPCUA_MESSAGE_TYPE_LENGTH),
        le_u8,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
    ))(input)?;
    Ok((rem, OPCUAMessageHeader {
        message_type: String::from_utf8(message_type.to_vec()).unwrap(),
        chunk_type,
        message_size,
        security_channel_id,
        security_request_id,
        security_sequence_number,
        security_token_id,
    }))
}

pub fn parse_opcua_message_type_id(input: &[u8]) -> IResult<&[u8], OPCUAMessageTypeId> {
    let (rem, (
        encoding_mask,
        namespace_index,
        identifier_numeric,
    )) = tuple((
        le_u8,
        le_u8,
        le_u16,
    ))(input)?;
    Ok((rem, OPCUAMessageTypeId {
        encoding_mask,
        namespace_index,
        identifier_numeric,
    }))
}

pub fn parse_opcua_message_additional_header(input: &[u8]) -> IResult<&[u8], OPCUAMessageAdditionalHeader> {
    let (rem, (
        type_id,
        encoding_mask,
    )) = tuple((
        le_u16,
        le_u8,
    ))(input)?;
    Ok((rem, OPCUAMessageAdditionalHeader {
        type_id,
        encoding_mask,
    }))
}

pub fn parse_opcua_message_security_token(input: &[u8]) -> IResult<&[u8], OPCUAOpenMessageSecurityToken> {
    let (rem, (
        channel_id,
        token_id,
        created_at,
        revised_lifetime,
    )) = tuple((
        le_u32,
        le_u32,
        take(8usize),
        le_u32,
    ))(input)?;
    Ok((rem, OPCUAOpenMessageSecurityToken {
        channel_id,
        token_id,
        created_at: created_at.to_vec(),
        revised_lifetime,
    }))
}

pub fn parse_opcua_message_request_header(input: &[u8]) -> IResult<&[u8], OPCUAMessageRequestHeader> {
    let (rem, (
        authorization_token,
        timestamp,
        request_handle,
        return_diagnostic,
        audit_entry_id,
        timeout_hint,
        addition_header,
    )) = tuple((
        le_u16,
        take(8usize),
        le_u32,
        le_u32,
        take(4usize),
        le_u32,
        parse_opcua_message_additional_header,
    ))(input)?;
    Ok((rem, OPCUAMessageRequestHeader {
        authorization_token,
        timestamp: timestamp.to_vec(),
        request_handle,
        return_diagnostic,
        audit_entry_id: audit_entry_id.to_vec(),
        timeout_hint,
        addition_header,
    }))
}

pub fn parse_opcua_message_open_secure_channel_request(input: &[u8]) -> IResult<&[u8], OPCUAOpenMessageOpenSecureChannelRequest> {
    let (rem, (
        request_header,
        client_protocol_version,
        security_token_request_type,
        message_security_mode,
        client_nonce,
        requested_lifetime,
    )) = tuple((
        parse_opcua_message_request_header,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
        le_u32,
    ))(input)?;
    Ok((rem, OPCUAOpenMessageOpenSecureChannelRequest {
        request_header,
        client_protocol_version,
        security_token_request_type,
        message_security_mode,
        client_nonce,
        requested_lifetime,
    }))
}

pub fn parse_opcua_message_response_header(input: &[u8]) -> IResult<&[u8], OPCUAMessageResponseHeader> {
    let (rem, (
        timestamp,
        request_handle,
        service_result,
        service_diagnostics,
        string_table,
        additional_header,
    )) = tuple((
        take(8usize),
        le_u32,
        le_u32,
        le_u8,
        take(4usize),
        parse_opcua_message_additional_header,
    ))(input)?;
    Ok((rem, OPCUAMessageResponseHeader {
        timestamp: timestamp.to_vec(),
        request_handle,
        service_result,
        service_diagnostics,
        string_table: string_table.to_vec(),
        additional_header,
    }))
}

pub fn parse_opcua_message_open_secure_channel_response(input: &[u8]) -> IResult<&[u8], OPCUAOpenMessageOpenSecureChannelResponse> {
    let (rem, (
        response_header,
        server_protocol_version,
        security_token,
        _,
        server_nonce,
    )) = tuple((
        parse_opcua_message_response_header,
        le_u32,
        parse_opcua_message_security_token,
        take(4usize),
        le_u8,
    ))(input)?;
    Ok((rem, OPCUAOpenMessageOpenSecureChannelResponse {
        response_header,
        server_protocol_version,
        security_token,
        server_nonce,
    }))
}

pub fn parse_opcua_open_message(input: &[u8]) -> IResult<&[u8], OPCUAMessage> {
    let (rem, type_id) = parse_opcua_message_type_id(input)?;
    match type_id.identifier_numeric {
        446 => {
            let (rem, open_secure_channel_request) = parse_opcua_message_open_secure_channel_request(rem)?;
            Ok((rem, OPCUAMessage {
                type_id,
                message: OPCUASpecificMessage::OPEN_REQUEST(OPCUAOpenMessageRequest {
                    open_secure_channel_request,
                }),
            }))
        },
        449 => {
            let (rem, open_secure_channel_response) = parse_opcua_message_open_secure_channel_response(rem)?;
            Ok((rem, OPCUAMessage {
                type_id,
                message: OPCUASpecificMessage::OPEN_RESPONSE(OPCUAOpenMessageResponse {
                    open_secure_channel_response,
                }),
            }))
        },
        _ => {
            unimplemented!();
        }
    }
}

pub fn parse_opcua_msg_get_endpoint_request(input: &[u8]) -> IResult<&[u8], OPCUAGetEndpointRequest> {
    let (rem, (
        request_header,
        endpoint_url,
        local_ids,
        profile_uris,
    )) = tuple((
        parse_opcua_message_request_header,
        take(4usize),
        take(4usize),
        take(4usize),
    ))(input)?;
    Ok((rem, OPCUAGetEndpointRequest {
        request_header,
        endpoint_url: endpoint_url.to_vec(),
        local_ids: local_ids.to_vec(),
        profile_uris: profile_uris.to_vec(),
    }))
}

pub fn parse_opcua_msg_get_endpoint_response(input: &[u8]) -> IResult<&[u8], OPCUAGetEndpointResponse> {
    let (rem, (
        response_header,
        endpoints,
    )) = tuple((
        parse_opcua_message_response_header,
        rest,
    ))(input)?;
    Ok((rem, OPCUAGetEndpointResponse {
        response_header,
        endpoints: endpoints.to_vec(),
    }))
}

pub fn parse_opcua_msg_message(input: &[u8]) -> IResult<&[u8], OPCUAMessage> {
    let (rem, type_id) = parse_opcua_message_type_id(input)?;
    match type_id.identifier_numeric {
        428 => {
            let (rem, get_endpoint_request) = parse_opcua_msg_get_endpoint_request(rem)?;
            Ok((rem, OPCUAMessage {
                type_id,
                message: OPCUASpecificMessage::GET_ENDPOINT_REQUEST(get_endpoint_request),
            }))
        },
        431 => {
            let (rem, get_endpoint_response) = parse_opcua_msg_get_endpoint_response(rem)?;
            Ok((rem, OPCUAMessage {
                type_id,
                message: OPCUASpecificMessage::GET_ENDPOINT_RESPONSE(get_endpoint_response),
            }))
        },
        _ => {
            unimplemented!();
        }
    }
}

pub fn parse_opcua(input: &[u8]) -> IResult<&[u8], OPCUA> {
    let (_, message_type) = take(OPCUA_MESSAGE_TYPE_LENGTH)(input)?;
    let message_type = String::from_utf8(message_type.to_vec()).unwrap();
    match message_type.as_str() {
        "HEL" => {
            let (rem, header) = parse_opcua_hello_header(input)?;
            let (rem, contents) = parse_opcua_hello_message(rem)?;
            Ok((rem, OPCUA {
                header: OPCUAHeader::HELLO(header),
                contents: OPCUAContents::HELLO(contents), 
            }))
        },
        "ACK" => {
            let (rem, header) = parse_opcua_hello_header(input)?;
            Ok((rem, OPCUA {
                header: OPCUAHeader::HELLO(header),
                contents: OPCUAContents::NONE,
            }))
        },
        "OPN" => {
            let (rem, header) = parse_opcua_open_header(input)?;
            let (rem, message) = parse_opcua_open_message(rem)?;
            Ok((rem, OPCUA {
                header: OPCUAHeader::OPEN(header),
                contents: OPCUAContents::OPEN(message),
            }))
        },
        "MSG" => {
            let (rem, header) = parse_opcua_message_header(input)?;
            let (rem, message) = parse_opcua_msg_message(rem)?;
            Ok((rem, OPCUA {
                header: OPCUAHeader::MESSAGE(header),
                contents: OPCUAContents::MESSAGE(message),
            }))
        },
        _ => {
            unimplemented!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_opcua_hello_message() {
        let pcap = include_bytes!("pcaps/opcua/opcua_hello_message.pcap");
        let payload = &pcap[24+16+66..];
        match parse_opcua(payload) {
            Ok((rem, opc_ua)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(opc_ua, OPCUA {
                    header: OPCUAHeader::HELLO(OPCUAHelloHeader {
                        message_type: String::from("HEL"),
                        chunk_type: b'F',
                        message_size: 79,
                        version: 0x00000000,
                        receive_buffer_size: 65535,
                        send_buffer_size: 65535,
                        max_message_size: 4000,
                        max_chunk_count: 0,
                    }),
                    contents: OPCUAContents::HELLO(OPCUAHelloMessage {
                        endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/UA/StackTestServer"),
                    }),
                });
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_opcua_acknowledge_message() {
        let pcap = include_bytes!("pcaps/opcua/opcua_acknowledge_message.pcap");
        let payload = &pcap[24+16+66..];
        match parse_opcua(payload) {
            Ok((rem, opc_ua)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(opc_ua, OPCUA {
                    header: OPCUAHeader::HELLO(OPCUAHelloHeader {
                        message_type: String::from("ACK"),
                        chunk_type: b'F',
                        message_size: 28,
                        version: 0,
                        receive_buffer_size: 65535,
                        send_buffer_size: 65535,
                        max_message_size: 4000,
                        max_chunk_count: 0,
                    }),
                    contents: OPCUAContents::NONE,
                });
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_opcua_open_secure_channel_request() {
        let pcap = include_bytes!("pcaps/opcua/opcua_open_secure_channel_request.pcap");
        let payload = &pcap[24+16+66..];
        match parse_opcua(payload) {
            Ok((rem, opc_ua)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(opc_ua, OPCUA {
                    header: OPCUAHeader::OPEN(OPCUAOpenHeader {
                        message_type: String::from("OPN"),
                        chunk_type: b'F',
                        message_size: 132,
                        secure_channel_id: 0,
                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#None"),
                        sender_certificate: vec![0xff, 0xff, 0xff, 0xff],
                        receiver_certificate_thumbprint: vec![0xff, 0xff, 0xff, 0xff],
                        sequence_number: 1,
                        request_id: 1,
                    }),
                    contents: OPCUAContents::OPEN(OPCUAMessage {
                        type_id: OPCUAMessageTypeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 446,
                        },
                        message: OPCUASpecificMessage::OPEN_REQUEST(OPCUAOpenMessageRequest {
                            open_secure_channel_request: OPCUAOpenMessageOpenSecureChannelRequest {
                                request_header: OPCUAMessageRequestHeader {
                                    authorization_token: 0,
                                    timestamp: vec![0x00, 0x3c, 0x7d, 0x0c, 0x5c, 0x2b, 0xca, 0x01],
                                    request_handle: 1,
                                    return_diagnostic: 0x000003ff,
                                    audit_entry_id: vec![0xff, 0xff, 0xff, 0xff],
                                    timeout_hint: 0,
                                    addition_header: OPCUAMessageAdditionalHeader {
                                        type_id: 0x0000,
                                        encoding_mask: 0x00,
                                    },
                                },
                                client_protocol_version: 0,
                                security_token_request_type: 0,
                                message_security_mode: 1,
                                client_nonce: 0,
                                requested_lifetime: 6000000,
                            }
                        }),
                    }),
                });
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_opcua_open_secure_channel_response() {
        let pcap = include_bytes!("pcaps/opcua/opcua_open_secure_channel_response.pcap");
        let payload = &pcap[24+16+66..];
        match parse_opcua(payload) {
            Ok((rem, opc_ua)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(opc_ua, OPCUA {
                    header: OPCUAHeader::OPEN(OPCUAOpenHeader {
                        message_type: String::from("OPN"),
                        chunk_type: b'F',
                        message_size: 136,
                        secure_channel_id: 6495,
                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#None"),
                        sender_certificate: vec![0xff, 0xff, 0xff, 0xff],
                        receiver_certificate_thumbprint: vec![0xff, 0xff, 0xff, 0xff],
                        sequence_number: 51,
                        request_id: 1,
                    }),
                    contents: OPCUAContents::OPEN(OPCUAMessage {
                        type_id: OPCUAMessageTypeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 449,
                        },
                        message: OPCUASpecificMessage::OPEN_RESPONSE(OPCUAOpenMessageResponse {
                            open_secure_channel_response: OPCUAOpenMessageOpenSecureChannelResponse {
                                response_header: OPCUAMessageResponseHeader {
                                    timestamp: vec![0xed, 0xd5, 0x60, 0x57, 0x5c, 0x2b, 0xca, 0x01],
                                    request_handle: 1,
                                    service_result: 0x00000000,
                                    service_diagnostics: 0x00,
                                    string_table: vec![0xff, 0xff, 0xff, 0xff],
                                    additional_header: OPCUAMessageAdditionalHeader {
                                        type_id: 0x0000,
                                        encoding_mask: 0x00,
                                    },
                                },
                                server_protocol_version: 0,
                                security_token: OPCUAOpenMessageSecurityToken {
                                    channel_id: 6495,
                                    token_id: 1,
                                    created_at: vec![0xed, 0xd5, 0x60, 0x57, 0x5c, 0x2b, 0xca, 0x01],
                                    revised_lifetime: 3600000,
                                },
                                server_nonce: 1,
                            },
                        }),
                    }),
                })
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_opcua_message_get_endpoint_request() {
        let pcap = include_bytes!("pcaps/opcua/opcua_message_get_endpoint_request.pcap");
        let payload = &pcap[24+16+66..];
        match parse_opcua(payload) {
            Ok((rem, opc_ua)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(opc_ua, OPCUA {
                    header: OPCUAHeader::MESSAGE(OPCUAMessageHeader {
                        message_type: String::from("MSG"),
                        chunk_type: b'F',
                        message_size: 69,
                        security_channel_id: 6495,
                        security_token_id: 1,
                        security_sequence_number: 2,
                        security_request_id: 2,
                    }),
                    contents: OPCUAContents::MESSAGE(OPCUAMessage {
                        type_id: OPCUAMessageTypeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 428,
                        },
                        message: OPCUASpecificMessage::GET_ENDPOINT_REQUEST(OPCUAGetEndpointRequest {
                            request_header: OPCUAMessageRequestHeader {
                                authorization_token: 0x0000,
                                timestamp: vec![0x00, 0x3c, 0x7d, 0x0c, 0x5c, 0x2b, 0xca, 0x01],
                                request_handle: 1,
                                return_diagnostic: 0x000003ff,
                                audit_entry_id: vec![0xff, 0xff, 0xff, 0xff],
                                timeout_hint: 0,
                                addition_header: OPCUAMessageAdditionalHeader {
                                    type_id: 0x0000,
                                    encoding_mask: 0x00,
                                },
                            },
                            endpoint_url: vec![0xff, 0xff, 0xff, 0xff],
                            local_ids: vec![0x00, 0x00, 0x00, 0x00],
                            profile_uris: vec![0x00, 0x00, 0x00, 0x00],
                        }),
                    }),
                })
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_opcua_message_get_endpoint_response() {
        let pcap = include_bytes!("pcaps/opcua/opcua_message_get_endpoint_response.bin");
        let payload = &pcap[..];
        match parse_opcua(payload) {
            Ok((rem, opc_ua)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(opc_ua, OPCUA {
                    header: OPCUAHeader::MESSAGE(OPCUAMessageHeader {
                        message_type: String::from("MSG"),
                        chunk_type: b'F',
                        message_size: 7008,
                        security_channel_id: 6495,
                        security_token_id: 1,
                        security_sequence_number: 52,
                        security_request_id: 2,
                    }),
                    contents: OPCUAContents::MESSAGE(OPCUAMessage {
                        type_id: OPCUAMessageTypeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 431,
                        },
                        message: OPCUASpecificMessage::GET_ENDPOINT_RESPONSE(OPCUAGetEndpointResponse {
                            response_header: OPCUAMessageResponseHeader {
                                timestamp: vec![0xf5, 0x84, 0x90, 0x57, 0x5c, 0x2b, 0xca, 0x01],
                                request_handle: 1,
                                service_result: 0x00000000,
                                service_diagnostics: 0x00,
                                string_table: vec![0x00, 0x00, 0x00, 0x00],
                                additional_header: OPCUAMessageAdditionalHeader {
                                    type_id: 0x0000,
                                    encoding_mask: 0x00,
                                },
                            },
                            endpoints: vec![5, 0, 0, 0, 55, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 58, 49, 50, 48, 48, 49, 47, 83, 116, 97, 99, 107, 84, 101, 115, 116, 83, 101, 114, 118, 101, 114, 47, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 52, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 255, 255, 255, 255, 2, 32, 0, 0, 0, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 1, 0, 0, 0, 55, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 58, 49, 50, 48, 48, 49, 47, 83, 116, 97, 99, 107, 84, 101, 115, 116, 83, 101, 114, 118, 101, 114, 47, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 235, 3, 0, 0, 48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74, 1, 0, 0, 0, 47, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 83, 101, 99, 117, 114, 105, 116, 121, 80, 111, 108, 105, 99, 121, 35, 78, 111, 110, 101, 1, 0, 0, 0, 1, 0, 0, 0, 48, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 51, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 83, 101, 99, 117, 114, 105, 116, 121, 80, 111, 108, 105, 99, 121, 35, 66, 97, 115, 105, 99, 50, 53, 54, 52, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 112, 114, 111, 102, 105, 108, 101, 115, 47, 116, 114, 97, 110, 115, 112, 111, 114, 116, 47, 117, 97, 116, 99, 112, 0, 55, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 58, 49, 50, 48, 48, 49, 47, 83, 116, 97, 99, 107, 84, 101, 115, 116, 83, 101, 114, 118, 101, 114, 47, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 52, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 255, 255, 255, 255, 2, 32, 0, 0, 0, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 1, 0, 0, 0, 55, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 58, 49, 50, 48, 48, 49, 47, 83, 116, 97, 99, 107, 84, 101, 115, 116, 83, 101, 114, 118, 101, 114, 47, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 235, 3, 0, 0, 48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74, 3, 0, 0, 0, 56, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 83, 101, 99, 117, 114, 105, 116, 121, 80, 111, 108, 105, 99, 121, 35, 66, 97, 115, 105, 99, 49, 50, 56, 82, 115, 97, 49, 53, 1, 0, 0, 0, 1, 0, 0, 0, 48, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 52, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 112, 114, 111, 102, 105, 108, 101, 115, 47, 116, 114, 97, 110, 115, 112, 111, 114, 116, 47, 117, 97, 116, 99, 112, 0, 55, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 58, 49, 50, 48, 48, 49, 47, 83, 116, 97, 99, 107, 84, 101, 115, 116, 83, 101, 114, 118, 101, 114, 47, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 52, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 255, 255, 255, 255, 2, 32, 0, 0, 0, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 1, 0, 0, 0, 55, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 58, 49, 50, 48, 48, 49, 47, 83, 116, 97, 99, 107, 84, 101, 115, 116, 83, 101, 114, 118, 101, 114, 47, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 235, 3, 0, 0, 48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74, 2, 0, 0, 0, 56, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 83, 101, 99, 117, 114, 105, 116, 121, 80, 111, 108, 105, 99, 121, 35, 66, 97, 115, 105, 99, 49, 50, 56, 82, 115, 97, 49, 53, 1, 0, 0, 0, 1, 0, 0, 0, 48, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 52, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 112, 114, 111, 102, 105, 108, 101, 115, 47, 116, 114, 97, 110, 115, 112, 111, 114, 116, 47, 117, 97, 116, 99, 112, 0, 55, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 58, 49, 50, 48, 48, 49, 47, 83, 116, 97, 99, 107, 84, 101, 115, 116, 83, 101, 114, 118, 101, 114, 47, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 52, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 255, 255, 255, 255, 2, 32, 0, 0, 0, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 1, 0, 0, 0, 55, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 58, 49, 50, 48, 48, 49, 47, 83, 116, 97, 99, 107, 84, 101, 115, 116, 83, 101, 114, 118, 101, 114, 47, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 235, 3, 0, 0, 48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74, 3, 0, 0, 0, 51, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 83, 101, 99, 117, 114, 105, 116, 121, 80, 111, 108, 105, 99, 121, 35, 66, 97, 115, 105, 99, 50, 53, 54, 1, 0, 0, 0, 1, 0, 0, 0, 48, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 52, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 112, 114, 111, 102, 105, 108, 101, 115, 47, 116, 114, 97, 110, 115, 112, 111, 114, 116, 47, 117, 97, 116, 99, 112, 0, 55, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 58, 49, 50, 48, 48, 49, 47, 83, 116, 97, 99, 107, 84, 101, 115, 116, 83, 101, 114, 118, 101, 114, 47, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 52, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 255, 255, 255, 255, 2, 32, 0, 0, 0, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 1, 0, 0, 0, 55, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 58, 49, 50, 48, 48, 49, 47, 83, 116, 97, 99, 107, 84, 101, 115, 116, 83, 101, 114, 118, 101, 114, 47, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 235, 3, 0, 0, 48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74, 2, 0, 0, 0, 51, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 83, 101, 99, 117, 114, 105, 116, 121, 80, 111, 108, 105, 99, 121, 35, 66, 97, 115, 105, 99, 50, 53, 54, 1, 0, 0, 0, 1, 0, 0, 0, 48, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 52, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 112, 114, 111, 102, 105, 108, 101, 115, 47, 116, 114, 97, 110, 115, 112, 111, 114, 116, 47, 117, 97, 116, 99, 112, 0],
                        }),
                    }),
                })
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }
}