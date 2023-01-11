use nom7::{IResult, sequence::tuple, bytes::complete::take, number::complete::{le_u8, le_u32, le_u16, le_i64}, multi::{length_data, count}, AsBytes};
use chrono::prelude::*;

const OPCUA_MESSAGE_TYPE_LENGTH: usize = 3;
const WINDOWS_TICK: i64 = 10000000;
const SEC_TO_UNIX_EPOCH: i64 = 11644473600;

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
    sender_certificate: String,
    receiver_certificate_thumbprint: String,
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
pub struct OPCUAErrorHeader {
    message_type: String,
    chunk_type: u8,
    message_size: u32,
    error: u32,
    reason: String,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAHelloMessage {
    endpoint_url: String,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAExpandedNodeId {
    encoding_mask: u8,
    namespace_index: u16,
    identifier_numeric: u32,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAMessageAdditionalHeader {
    type_id: OPCUAExpandedNodeId,
    encoding_mask: u8,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAMessageRequestHeader {
    authorization_token: u16,
    timestamp: String,
    request_handle: u32,
    return_diagnostic: u32,
    audit_entry_id: String,
    timeout_hint: u32,
    addition_header: OPCUAMessageAdditionalHeader,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAMessageResponseHeader {
    timestamp: String,
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
    created_at: String,
    revised_lifetime: u32,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAStringArray {
    array_size: u32,
    array_value: Vec<String>,
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
    endpoint_url: String,
    local_ids: OPCUAStringArray,
    profile_uris: OPCUAStringArray,
}

#[derive(Debug, PartialEq)]
pub struct OPCUALocalizedText {
    encoding_mask: u8,
    text: String,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAApplicationDescription {
    application_uri: String,
    product_uri: String,
    application_name: OPCUALocalizedText,
    application_type: u32,
    gateway_server_uri: String,
    discovery_profile_uri: String,
    discovery_urls: OPCUAStringArray,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAUserTokenPolicy {
    policy_id: u8,
    user_token_type: u32,
    issued_token_type: String,
    issuer_endpoint_url: String,
    security_policy_uri: String,
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
    security_policy_uri: String,
    user_identity_tokens: OPCUAUserTokenPolicies,
    transport_profile_uri: String,
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
    endpoints: OPCUAEndpointsInfo,
}

#[derive(Debug, PartialEq)]
pub struct OPCUACreateSessionRequest {
    request_header: OPCUAMessageRequestHeader,
    client_description: OPCUAApplicationDescription,
    server_uri: String,
    endpoint_url: String,
    session_name: String,
    client_nonce: Vec<u8>,
    client_certificate: Vec<u8>,
    requested_session_timeout: Vec<u8>,
    max_response_message_size: u32,
}

#[derive(Debug, PartialEq)]
pub struct OPCUASignatureData {
    algorithm: String,
    signature: String,
}

#[derive(Debug, PartialEq)]
pub struct OPCUASignedSoftwareCertificate {

}

#[derive(Debug, PartialEq)]
pub struct OPCUASignatureSoftwareCertificates {
    array_size: u32,
    signed_software_certificates: Vec<OPCUASignedSoftwareCertificate>,
}

#[derive(Debug, PartialEq)]
pub struct OPCUACreateSessionResponse {
    response_header: OPCUAMessageResponseHeader,
    session_id: OPCUAExpandedNodeId,
    authentication_token: OPCUAExpandedNodeId,
    revised_session_timeout: Vec<u8>,
    server_nonce: Vec<u8>,
    server_certificate: Vec<u8>,
    server_endpoints: OPCUAEndpointsInfo,
    server_software_certificates: OPCUASignatureSoftwareCertificates,
    server_signature: OPCUASignatureData,
    max_request_message_size: u32,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAAnonymousIdentityToken {
    policy_id: u8,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAExtensionObject {
    type_id: OPCUAExpandedNodeId,
    encoding_mask: u8,
    anonymous_identity_token: OPCUAAnonymousIdentityToken,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAActivateSessionRequest {
    request_header: OPCUAMessageRequestHeader,
    client_signature: OPCUASignatureData,
    client_software_certificates: OPCUASignatureSoftwareCertificates,
    locale_ids: OPCUAStringArray,
    user_identity_token: OPCUAExtensionObject,
    user_token_signature: OPCUASignatureData,
}

#[derive(Debug, PartialEq)]
pub struct OPCUAStatusCode {
    array_size: u32,
    status_codes: Vec<i32>,
}

#[derive(Debug, PartialEq)]
pub struct OPCUADignostic {

}

#[derive(Debug, PartialEq)]
pub struct OPCUADiagnosticInfo {
    array_size: u32,
    diagnostic_info: Vec<OPCUADignostic>,
}
#[derive(Debug, PartialEq)]
pub struct OPCUAActivateSessionResponse {
    response_header: OPCUAMessageResponseHeader,
    server_nonce: Vec<u8>,
    result: OPCUAStatusCode,
    diagnostic_infos: OPCUADiagnosticInfo,
}

#[derive(Debug, PartialEq)]
pub enum OPCUASpecificMessage {
    OPEN_REQUEST(OPCUAOpenMessageRequest),
    OPEN_RESPONSE(OPCUAOpenMessageResponse),
    GET_ENDPOINT_REQUEST(OPCUAGetEndpointRequest),
    GET_ENDPOINT_RESPONSE(OPCUAGetEndpointResponse),
    CREATE_SESSION_REQUEST(OPCUACreateSessionRequest),
    CREATE_SESSION_RESPONSE(OPCUACreateSessionResponse),
    ACTIVATE_SESSION_REQUEST(OPCUAActivateSessionRequest),
    ACTIVATE_SESSION_RESPONSE(OPCUAActivateSessionResponse),
}

#[derive(Debug, PartialEq)]
pub struct OPCUAMessage {
    type_id: OPCUAExpandedNodeId,
    message: OPCUASpecificMessage,
}

#[derive(Debug, PartialEq)]
pub enum OPCUAHeader {
    HELLO(OPCUAHelloHeader),
    OPEN(OPCUAOpenHeader),
    MESSAGE(OPCUAMessageHeader),
    ERROR(OPCUAErrorHeader),
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
        parse_opcua_null_string,
        parse_opcua_null_string,
        le_u32,
        le_u32,
    ))(input)?;
    Ok((rem, OPCUAOpenHeader {
        message_type: String::from_utf8(message_type.to_vec()).unwrap(),
        chunk_type,
        message_size,
        secure_channel_id,
        security_policy_uri: String::from_utf8(security_policy_uri.to_vec()).unwrap(),
        sender_certificate,
        receiver_certificate_thumbprint,
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

pub fn parse_opcua_message_expanded_node_id(input: &[u8]) -> IResult<&[u8], OPCUAExpandedNodeId> {
    let (rem, encoding_mask) = le_u8(input)?;
    match encoding_mask {
        0x00 => {
            let (rem, identifier_numeric) = le_u8(rem)?;
            Ok((rem, OPCUAExpandedNodeId {
                encoding_mask,
                namespace_index: 0,
                identifier_numeric: identifier_numeric as u32,
            }))
        },
        0x01 => {
            let (rem, namespace_index) = le_u8(rem)?;
            let (rem, identifier_numeric) = le_u16(rem)?;
            Ok((rem, OPCUAExpandedNodeId {
                encoding_mask,
                namespace_index: namespace_index as u16,
                identifier_numeric: identifier_numeric as u32,
            }))
        },
        0x02 => {
            let (rem, namespace_index) = le_u16(rem)?;
            let (rem, identifier_numeric) = le_u32(rem)?;
            Ok((rem, OPCUAExpandedNodeId {
                encoding_mask,
                namespace_index,
                identifier_numeric,
            }))
        },
        _ => {
            unimplemented!();
        }
    }
}

pub fn parse_opcua_message_additional_header(input: &[u8]) -> IResult<&[u8], OPCUAMessageAdditionalHeader> {
    let (rem, (
        type_id,
        encoding_mask,
    )) = tuple((
        parse_opcua_message_expanded_node_id,
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
        translate_timestamp_to_string,
        le_u32,
    ))(input)?;
    Ok((rem, OPCUAOpenMessageSecurityToken {
        channel_id,
        token_id,
        created_at,
        revised_lifetime,
    }))
}

pub fn parse_opcua_message_identifier_numeric(input: &[u8]) -> IResult<&[u8], u16> {
    let (rem, encoding_mask) = le_u8(input)?;
    let (rem, identifier_numeric) = if encoding_mask == 0 {
        let (rem, data) = le_u8(rem)?;
        (rem, data as u16)
    } else {
        let (rem, _) = le_u8(rem)?;
        let (rem, identifier_numeric) = le_u16(rem)?;
        (rem, identifier_numeric)
    };
    Ok((rem, identifier_numeric))
}

pub fn translate_timestamp_to_string(input: &[u8]) -> IResult<&[u8], String> {
    let (rem, origin_timestamp_millis) = le_i64(input)?;
    let unix_timestamp = origin_timestamp_millis / WINDOWS_TICK - SEC_TO_UNIX_EPOCH;
    let nt = NaiveDateTime::from_timestamp_opt(unix_timestamp, 0).unwrap();
    let utc_datetime: DateTime<Utc> = DateTime::from_utc(nt, Utc);
    let res = utc_datetime.format("%Y-%m-%d %H:%M:%S").to_string();
    Ok((rem, res))
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
        parse_opcua_message_identifier_numeric,
        translate_timestamp_to_string,
        le_u32,
        le_u32,
        parse_opcua_null_string,
        le_u32,
        parse_opcua_message_additional_header,
    ))(input)?;
    Ok((rem, OPCUAMessageRequestHeader {
        authorization_token,
        timestamp,
        request_handle,
        return_diagnostic,
        audit_entry_id,
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
        translate_timestamp_to_string,
        le_u32,
        le_u32,
        le_u8,
        take(4usize),
        parse_opcua_message_additional_header,
    ))(input)?;
    Ok((rem, OPCUAMessageResponseHeader {
        timestamp,
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
    let (rem, type_id) = parse_opcua_message_expanded_node_id(input)?;
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
        parse_opcua_null_string,
        parse_opcua_string_array,
        parse_opcua_string_array,
    ))(input)?;
    Ok((rem, OPCUAGetEndpointRequest {
        request_header,
        endpoint_url,
        local_ids,
        profile_uris,
    }))
}

pub fn parse_opcua_message_application_description_application_name(input: &[u8]) -> IResult<&[u8], OPCUALocalizedText> {
    let (rem, (
        encoding_mask,
        text,
    )) = tuple((
        le_u8,
        length_data(le_u32),
    ))(input)?;
    Ok((rem, OPCUALocalizedText {
        encoding_mask,
        text: String::from_utf8(text.to_vec()).unwrap(),
    }))
}

pub fn parse_opcua_message_application_description_discovery_url(input: &[u8]) -> IResult<&[u8], String> {
    let (rem, discovery_url) = length_data(le_u32)(input)?;
    Ok((rem, String::from_utf8(discovery_url.to_vec()).unwrap()))
}

pub fn parse_opcua_null_string(input: &[u8]) -> IResult<&[u8], String> {
    if input[0] == 0xff && input[1] == 0xff && input[2] == 0xff && input[3] == 0xff {
        Ok((&input[4..], String::new()))
    } else {
        let (rem, data) = length_data(le_u32)(input)?;
        Ok((rem, String::from_utf8(data.to_vec()).unwrap()))
    }
}

pub fn parse_opcua_message_application_description(input: &[u8]) -> IResult<&[u8], OPCUAApplicationDescription> {
    let (rem, (
        application_uri,
        product_uri,
        application_name,
        application_type,
        gateway_server_uri,
        discovery_profile_uri,
        discovery_urls,
    )) = tuple((
        length_data(le_u32),
        parse_opcua_null_string,
        parse_opcua_message_application_description_application_name,
        le_u32,
        parse_opcua_null_string,
        parse_opcua_null_string,
        parse_opcua_string_array,
    ))(input)?;
    Ok((rem, OPCUAApplicationDescription {
        application_uri: String::from_utf8(application_uri.to_vec()).unwrap(),
        product_uri,
        application_name,
        application_type,
        gateway_server_uri,
        discovery_profile_uri,
        discovery_urls,
    }))
}

pub fn parse_opcua_msg_endpoint_user_token_policy(input: &[u8]) -> IResult<&[u8], OPCUAUserTokenPolicy> {
    let (rem, (
        _index,
        policy_id,
        user_token_type,
        issued_token_type,
        issuer_endpoint_url,
        security_policy_uri,
    )) = tuple((
        le_u32,
        le_u8,
        le_u32,
        parse_opcua_null_string,
        parse_opcua_null_string,
        parse_opcua_null_string,
    ))(input)?;
    Ok((rem, OPCUAUserTokenPolicy {
        policy_id,
        user_token_type,
        issued_token_type,
        issuer_endpoint_url,
        security_policy_uri,
    }))
}

pub fn parse_opcua_msg_endpoint_user_identify_tokens(input: &[u8]) -> IResult<&[u8], OPCUAUserTokenPolicies> {
    let (rem, array_size) = le_u32(input)?;
    let (rem, user_token_policies) = count(parse_opcua_msg_endpoint_user_token_policy, array_size as usize)(rem)?;
    Ok((rem, OPCUAUserTokenPolicies {
        array_size,
        user_token_policies,
    }))
}

pub fn parse_opcua_msg_endpoint(input: &[u8]) -> IResult<&[u8], OPCUAEndpointDescription> {
    let (rem, (
        endpoint_url,
        server,
        server_certificate,
        message_security_mode,
        security_policy_uri,
        user_identity_tokens,
        transport_profile_uri,
        security_level,
    )) = tuple((
        length_data(le_u32),
        parse_opcua_message_application_description,
        length_data(le_u32),
        le_u32,
        length_data(le_u32),
        parse_opcua_msg_endpoint_user_identify_tokens,
        length_data(le_u32),
        le_u8,
    ))(input)?;
    Ok((rem, OPCUAEndpointDescription {
        endpoint_url: String::from_utf8(endpoint_url.to_vec()).unwrap(),
        server,
        server_certificate: server_certificate.to_vec(),
        message_security_mode,
        security_policy_uri: String::from_utf8(security_policy_uri.to_vec()).unwrap(),
        user_identity_tokens,
        transport_profile_uri: String::from_utf8(transport_profile_uri.to_vec()).unwrap(),
        security_level,
    }))
}

pub fn parse_opcua_msg_endpoints(input: &[u8]) -> IResult<&[u8], OPCUAEndpointsInfo> {
    let (rem, array_size) = le_u32(input)?;
    let (rem, endpoints) = count(parse_opcua_msg_endpoint, array_size as usize)(rem)?;
    Ok((rem, OPCUAEndpointsInfo {
        array_size,
        endpoints,
    }))
}

pub fn parse_opcua_msg_get_endpoint_response(input: &[u8]) -> IResult<&[u8], OPCUAGetEndpointResponse> {
    let (rem, (
        response_header,
        endpoints,
    )) = tuple((
        parse_opcua_message_response_header,
        parse_opcua_msg_endpoints,
    ))(input)?;
    Ok((rem, OPCUAGetEndpointResponse {
        response_header,
        endpoints,
    }))
}

pub fn parse_opcua_msg_create_session_request(input: &[u8]) -> IResult<&[u8], OPCUACreateSessionRequest> {
    let (rem, (
        request_header,
        client_description,
        server_uri,
        endpoint_url,
        session_name,
        client_nonce,
        client_certificate,
        requested_session_timeout,
        max_response_message_size,
    )) = tuple((
        parse_opcua_message_request_header,
        parse_opcua_message_application_description,
        length_data(le_u32),
        length_data(le_u32),
        length_data(le_u32),
        length_data(le_u32),
        length_data(le_u32),
        take(8usize),
        le_u32,
    ))(input)?;
    Ok((rem, OPCUACreateSessionRequest {
        request_header,
        client_description,
        server_uri: String::from_utf8(server_uri.to_vec()).unwrap(),
        endpoint_url: String::from_utf8(endpoint_url.to_vec()).unwrap(),
        session_name: String::from_utf8(session_name.to_vec()).unwrap(),
        client_nonce: client_nonce.to_vec(),
        client_certificate: client_certificate.to_vec(),
        requested_session_timeout: requested_session_timeout.to_vec(),
        max_response_message_size,
    }))
}

pub fn parse_opcua_msg_create_session_response(input: &[u8]) -> IResult<&[u8], OPCUACreateSessionResponse> {
    let (rem, (
        response_header,
        session_id,
        authentication_token,
        revised_session_timeout,
        server_nonce,
        server_certificate,
        server_endpoints,
        server_software_certificates,
        server_signature,
        max_request_message_size,
    )) = tuple((
        parse_opcua_message_response_header,
        parse_opcua_message_expanded_node_id,
        parse_opcua_message_expanded_node_id,
        take(8usize),
        length_data(le_u32),
        length_data(le_u32),
        parse_opcua_msg_endpoints,
        parse_opcua_message_signature_software_certificates,
        parse_opcua_message_signature_data,
        le_u32,
    ))(input)?;
    Ok((rem, OPCUACreateSessionResponse {
        response_header,
        session_id,
        authentication_token,
        revised_session_timeout: revised_session_timeout.to_vec(),
        server_nonce: server_nonce.to_vec(),
        server_certificate: server_certificate.to_vec(),
        server_endpoints,
        server_software_certificates,
        server_signature,
        max_request_message_size,
    }))
}

pub fn parse_opcua_message_signature_data(input: &[u8]) -> IResult<&[u8], OPCUASignatureData> {
    let (rem, (
        algorithm,
        signature,
    )) = tuple((
        parse_opcua_null_string,
        parse_opcua_null_string,
    ))(input)?;
    Ok((rem, OPCUASignatureData {
        algorithm,
        signature,
    }))
}

pub fn parse_opcua_message_signature_software_certificates(input: &[u8]) -> IResult<&[u8], OPCUASignatureSoftwareCertificates> {
    let (rem, array_size) = le_u32(input)?;
    Ok((rem, OPCUASignatureSoftwareCertificates {
        array_size,
        signed_software_certificates: Vec::new(),
    }))
}

pub fn parse_opcua_message_locale_id(input: &[u8]) -> IResult<&[u8], String> {
    let (rem, locale_id) = length_data(le_u32)(input)?;
    Ok((rem, String::from_utf8(locale_id.to_vec()).unwrap()))
}

pub fn parse_opcua_string_array(input: &[u8]) -> IResult<&[u8], OPCUAStringArray> {
    let (rem, array_size) = le_u32(input)?;
    let (rem, array_value) = count(parse_opcua_message_locale_id, array_size as usize)(rem)?;
    Ok((rem, OPCUAStringArray {
        array_size,
        array_value,
    }))
}

pub fn parse_opcua_message_anonymous_identity_token(input: &[u8]) -> IResult<&[u8], OPCUAAnonymousIdentityToken> {
    let (rem, data) = length_data(le_u32)(input)?;
    let (_, policy_id) = length_data(le_u32)(data)?;
    Ok((rem, OPCUAAnonymousIdentityToken {
        policy_id: policy_id[0],
    }))
}

pub fn parse_opcua_message_extension_object(input: &[u8]) -> IResult<&[u8], OPCUAExtensionObject> {
    let (rem, (
        type_id,
        encoding_mask,
        anonymous_identity_token,
    )) = tuple((
        parse_opcua_message_expanded_node_id,
        le_u8,
        parse_opcua_message_anonymous_identity_token,
    ))(input)?;
    Ok((rem, OPCUAExtensionObject {
        type_id,
        encoding_mask,
        anonymous_identity_token,
    }))
}

pub fn parse_opcua_msg_activate_session_request(input: &[u8]) -> IResult<&[u8], OPCUAActivateSessionRequest> {
    let (rem, (
        request_header,
        client_signature,
        client_software_certificates,
        locale_ids,
        user_identity_token,
        user_token_signature,
    )) = tuple((
        parse_opcua_message_request_header,
        parse_opcua_message_signature_data,
        parse_opcua_message_signature_software_certificates,
        parse_opcua_string_array,
        parse_opcua_message_extension_object,
        parse_opcua_message_signature_data,
    ))(input)?;
    Ok((rem, OPCUAActivateSessionRequest {
        request_header,
        client_signature,
        client_software_certificates,
        locale_ids,
        user_identity_token,
        user_token_signature,
    }))
}

pub fn parse_opcua_message_status_code(input: &[u8]) -> IResult<&[u8], OPCUAStatusCode> {
    let (rem, array_size) = le_u32(input)?;
    let status_codes = vec![];
    Ok((rem, OPCUAStatusCode {
        array_size,
        status_codes,
    }))
}

pub fn parse_opcua_message_diagnostic_infos(input: &[u8]) -> IResult<&[u8], OPCUADiagnosticInfo> {
    let (rem, array_size) = le_u32(input)?;
    let diagnostic_info = vec![];
    Ok((rem, OPCUADiagnosticInfo {
        array_size,
        diagnostic_info,
    }))
}

pub fn parse_opcua_msg_activate_session_response(input: &[u8]) -> IResult<&[u8], OPCUAActivateSessionResponse> {
    let (rem, (
        response_header,
        server_nonce,
        result,
        diagnostic_infos,
    )) = tuple((
        parse_opcua_message_response_header,
        length_data(le_u32),
        parse_opcua_message_status_code,
        parse_opcua_message_diagnostic_infos,
    ))(input)?;
    Ok((rem, OPCUAActivateSessionResponse {
        response_header,
        server_nonce: server_nonce.to_vec(),
        result,
        diagnostic_infos,
    }))
}

pub fn parse_opcua_msg_message(input: &[u8]) -> IResult<&[u8], OPCUAMessage> {
    let (rem, type_id) = parse_opcua_message_expanded_node_id(input)?;
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
        461 => {
            let (rem, create_session_request) = parse_opcua_msg_create_session_request(rem)?;
            Ok((rem, OPCUAMessage {
                type_id,
                message: OPCUASpecificMessage::CREATE_SESSION_REQUEST(create_session_request),
            }))
        },
        464 => {
            let (rem, create_session_response) = parse_opcua_msg_create_session_response(rem)?;
            Ok((rem,OPCUAMessage {
                type_id,
                message: OPCUASpecificMessage::CREATE_SESSION_RESPONSE(create_session_response),
            }))
        },
        467 => {
            let (rem, activate_session_request) = parse_opcua_msg_activate_session_request(rem)?;
            Ok((rem, OPCUAMessage {
                type_id,
                message: OPCUASpecificMessage::ACTIVATE_SESSION_REQUEST(activate_session_request),
            }))
        },
        470 => {
            let (rem, activate_session_response) = parse_opcua_msg_activate_session_response(rem)?;
            Ok((rem, OPCUAMessage {
                type_id,
                message: OPCUASpecificMessage::ACTIVATE_SESSION_RESPONSE(activate_session_response),
            }))
        },
        _ => {
            unimplemented!();
        }
    }
}

pub fn parse_opcua_error_header(input: &[u8]) -> IResult<&[u8], OPCUAErrorHeader> {
    let (rem, (
        message_type,
        chunk_type,
        message_size,
        error,
        reason,
    )) = tuple((
        take(OPCUA_MESSAGE_TYPE_LENGTH),
        le_u8,
        le_u32,
        le_u32,
        parse_opcua_null_string,
    ))(input)?;
    Ok((rem, OPCUAErrorHeader {
        message_type: String::from_utf8(message_type.to_vec()).unwrap(),
        chunk_type,
        message_size,
        error,
        reason,
    }))
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
        "ERR" => {
            let (rem, header) = parse_opcua_error_header(input)?;
            Ok((rem, OPCUA {
                header: OPCUAHeader::ERROR(header),
                contents: OPCUAContents::NONE,
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
                        sender_certificate: String::new(),
                        receiver_certificate_thumbprint: String::new(),
                        sequence_number: 1,
                        request_id: 1,
                    }),
                    contents: OPCUAContents::OPEN(OPCUAMessage {
                        type_id: OPCUAExpandedNodeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 446,
                        },
                        message: OPCUASpecificMessage::OPEN_REQUEST(OPCUAOpenMessageRequest {
                            open_secure_channel_request: OPCUAOpenMessageOpenSecureChannelRequest {
                                request_header: OPCUAMessageRequestHeader {
                                    authorization_token: 0,
                                    timestamp: String::from("2009-09-01 23:29:28"),
                                    request_handle: 1,
                                    return_diagnostic: 0x000003ff,
                                    audit_entry_id: String::new(),
                                    timeout_hint: 0,
                                    addition_header: OPCUAMessageAdditionalHeader {
                                        type_id: OPCUAExpandedNodeId {
                                            encoding_mask: 0,
                                            namespace_index: 0,
                                            identifier_numeric: 0,
                                        },
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
                        sender_certificate: String::new(),
                        receiver_certificate_thumbprint: String::new(),
                        sequence_number: 51,
                        request_id: 1,
                    }),
                    contents: OPCUAContents::OPEN(OPCUAMessage {
                        type_id: OPCUAExpandedNodeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 449,
                        },
                        message: OPCUASpecificMessage::OPEN_RESPONSE(OPCUAOpenMessageResponse {
                            open_secure_channel_response: OPCUAOpenMessageOpenSecureChannelResponse {
                                response_header: OPCUAMessageResponseHeader {
                                    timestamp: String::from("2009-09-01 23:31:33"),
                                    request_handle: 1,
                                    service_result: 0x00000000,
                                    service_diagnostics: 0x00,
                                    string_table: vec![0xff, 0xff, 0xff, 0xff],
                                    additional_header: OPCUAMessageAdditionalHeader {
                                        type_id: OPCUAExpandedNodeId {
                                            encoding_mask: 0,
                                            namespace_index: 0,
                                            identifier_numeric: 0,
                                        },
                                        encoding_mask: 0x00,
                                    },
                                },
                                server_protocol_version: 0,
                                security_token: OPCUAOpenMessageSecurityToken {
                                    channel_id: 6495,
                                    token_id: 1,
                                    created_at: String::from("2009-09-01 23:31:33"),
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
                        type_id: OPCUAExpandedNodeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 428,
                        },
                        message: OPCUASpecificMessage::GET_ENDPOINT_REQUEST(OPCUAGetEndpointRequest {
                            request_header: OPCUAMessageRequestHeader {
                                authorization_token: 0x0000,
                                timestamp: String::from("2009-09-01 23:29:28"),
                                request_handle: 1,
                                return_diagnostic: 0x000003ff,
                                audit_entry_id: String::new(),
                                timeout_hint: 0,
                                addition_header: OPCUAMessageAdditionalHeader {
                                    type_id: OPCUAExpandedNodeId {
                                        encoding_mask: 0,
                                        namespace_index: 0,
                                        identifier_numeric: 0,
                                    },
                                    encoding_mask: 0x00,
                                },
                            },
                            endpoint_url: String::new(),
                            local_ids: OPCUAStringArray {
                                array_size: 0,
                                array_value: vec![],
                            },
                            profile_uris: OPCUAStringArray {
                                array_size: 0,
                                array_value: vec![],
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
                        type_id: OPCUAExpandedNodeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 431,
                        },
                        message: OPCUASpecificMessage::GET_ENDPOINT_RESPONSE(OPCUAGetEndpointResponse {
                            response_header: OPCUAMessageResponseHeader {
                                timestamp: String::from("2009-09-01 23:31:33"),
                                request_handle: 1,
                                service_result: 0x00000000,
                                service_diagnostics: 0x00,
                                string_table: vec![0x00, 0x00, 0x00, 0x00],
                                additional_header: OPCUAMessageAdditionalHeader {
                                    type_id: OPCUAExpandedNodeId {
                                        encoding_mask: 0,
                                        namespace_index: 0,
                                        identifier_numeric: 0,
                                    },
                                    encoding_mask: 0x00,
                                },
                            },
                            endpoints: OPCUAEndpointsInfo {
                                array_size: 5,
                                endpoints: vec![
                                    OPCUAEndpointDescription {
                                        endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                        server: OPCUAApplicationDescription {
                                            application_uri: String::from("http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"),
                                            product_uri: String::new(),
                                            application_name: OPCUALocalizedText {
                                                encoding_mask: 0x02,
                                                text: String::from("UA StackTest Server (AnsiC/2048)"),
                                            },
                                            application_type: 0x00000000,
                                            gateway_server_uri: String::new(),
                                            discovery_profile_uri: String::new(),
                                            discovery_urls: OPCUAStringArray {
                                                array_size: 1,
                                                array_value: vec![
                                                    String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                                ],
                                            },
                                        },
                                        server_certificate: vec![48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74],
                                        message_security_mode: 0x00000001,
                                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#None"),
                                        user_identity_tokens: OPCUAUserTokenPolicies {
                                            array_size: 1,
                                            user_token_policies: vec![
                                                OPCUAUserTokenPolicy {
                                                    policy_id: b'0',
                                                    user_token_type: 0x00000000,
                                                    issued_token_type: String::new(),
                                                    issuer_endpoint_url: String::new(),
                                                    security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#Basic256"),
                                                },
                                            ],
                                        },
                                        transport_profile_uri: String::from("http://opcfoundation.org/UA/profiles/transport/uatcp"),
                                        security_level: 0,
                                    },
                                    OPCUAEndpointDescription {
                                        endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                        server: OPCUAApplicationDescription {
                                            application_uri: String::from("http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"),
                                            product_uri: String::new(),
                                            application_name: OPCUALocalizedText {
                                                encoding_mask: 0x02,
                                                text: String::from("UA StackTest Server (AnsiC/2048)"),
                                            },
                                            application_type: 0x00000000,
                                            gateway_server_uri: String::new(),
                                            discovery_profile_uri: String::new(),
                                            discovery_urls: OPCUAStringArray {
                                                array_size: 1,
                                                array_value: vec![
                                                    String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                                ],
                                            },
                                        },
                                        server_certificate: vec![48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74],
                                        message_security_mode: 0x00000003,
                                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"),
                                        user_identity_tokens: OPCUAUserTokenPolicies {
                                            array_size: 1,
                                            user_token_policies: vec![
                                                OPCUAUserTokenPolicy {
                                                    policy_id: b'0',
                                                    user_token_type: 0x00000000,
                                                    issued_token_type: String::new(),
                                                    issuer_endpoint_url: String::new(),
                                                    security_policy_uri: String::new(),
                                                },
                                            ],
                                        },
                                        transport_profile_uri: String::from("http://opcfoundation.org/UA/profiles/transport/uatcp"),
                                        security_level: 0,
                                    },
                                    OPCUAEndpointDescription {
                                        endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                        server: OPCUAApplicationDescription {
                                            application_uri: String::from("http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"),
                                            product_uri: String::new(),
                                            application_name: OPCUALocalizedText {
                                                encoding_mask: 0x02,
                                                text: String::from("UA StackTest Server (AnsiC/2048)"),
                                            },
                                            application_type: 0x00000000,
                                            gateway_server_uri: String::new(),
                                            discovery_profile_uri: String::new(),
                                            discovery_urls: OPCUAStringArray {
                                                array_size: 1,
                                                array_value: vec![
                                                    String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                                ],
                                            },
                                        },
                                        server_certificate: vec![48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74],
                                        message_security_mode: 0x00000002,
                                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"),
                                        user_identity_tokens: OPCUAUserTokenPolicies {
                                            array_size: 1,
                                            user_token_policies: vec![
                                                OPCUAUserTokenPolicy {
                                                    policy_id: b'0',
                                                    user_token_type: 0x00000000,
                                                    issued_token_type: String::new(),
                                                    issuer_endpoint_url: String::new(),
                                                    security_policy_uri: String::new(),
                                                },
                                            ],
                                        },
                                        transport_profile_uri: String::from("http://opcfoundation.org/UA/profiles/transport/uatcp"),
                                        security_level: 0,
                                    },
                                    OPCUAEndpointDescription {
                                        endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                        server: OPCUAApplicationDescription {
                                            application_uri: String::from("http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"),
                                            product_uri: String::new(),
                                            application_name: OPCUALocalizedText {
                                                encoding_mask: 0x02,
                                                text: String::from("UA StackTest Server (AnsiC/2048)"),
                                            },
                                            application_type: 0x00000000,
                                            gateway_server_uri: String::new(),
                                            discovery_profile_uri: String::new(),
                                            discovery_urls: OPCUAStringArray {
                                                array_size: 1,
                                                array_value: vec![
                                                    String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                                ],
                                            },
                                        },
                                        server_certificate: vec![48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74],
                                        message_security_mode: 0x00000003,
                                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#Basic256"),
                                        user_identity_tokens: OPCUAUserTokenPolicies {
                                            array_size: 1,
                                            user_token_policies: vec![
                                                OPCUAUserTokenPolicy {
                                                    policy_id: b'0',
                                                    user_token_type: 0x00000000,
                                                    issued_token_type: String::new(),
                                                    issuer_endpoint_url: String::new(),
                                                    security_policy_uri: String::new(),
                                                },
                                            ],
                                        },
                                        transport_profile_uri: String::from("http://opcfoundation.org/UA/profiles/transport/uatcp"),
                                        security_level: 0,
                                    },
                                    OPCUAEndpointDescription {
                                        endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                        server: OPCUAApplicationDescription {
                                            application_uri: String::from("http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"),
                                            product_uri: String::new(),
                                            application_name: OPCUALocalizedText {
                                                encoding_mask: 0x02,
                                                text: String::from("UA StackTest Server (AnsiC/2048)"),
                                            },
                                            application_type: 0x00000000,
                                            gateway_server_uri: String::new(),
                                            discovery_profile_uri: String::new(),
                                            discovery_urls: OPCUAStringArray {
                                                array_size: 1,
                                                array_value: vec![
                                                    String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                                ],
                                            },
                                        },
                                        server_certificate: vec![48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74],
                                        message_security_mode: 0x00000002,
                                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#Basic256"),
                                        user_identity_tokens: OPCUAUserTokenPolicies {
                                            array_size: 1,
                                            user_token_policies: vec![
                                                OPCUAUserTokenPolicy {
                                                    policy_id: b'0',
                                                    user_token_type: 0x00000000,
                                                    issued_token_type: String::new(),
                                                    issuer_endpoint_url: String::new(),
                                                    security_policy_uri: String::new(),
                                                },
                                            ],
                                        },
                                        transport_profile_uri: String::from("http://opcfoundation.org/UA/profiles/transport/uatcp"),
                                        security_level: 0,
                                    },
                                ],
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
    fn test_parse_opcua_create_session_request() {
        let pcap = include_bytes!("pcaps/opcua/opcua_message_create_session_request.pcap");
        let payload = &pcap[24+16+66..];
        match parse_opcua(payload) {
            Ok((rem, opc_ua)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(opc_ua, OPCUA {
                    header: OPCUAHeader::MESSAGE(OPCUAMessageHeader {
                        message_type: String::from("MSG"),
                        chunk_type: b'F',
                        message_size: 1113,
                        security_channel_id: 6495,
                        security_token_id: 1,
                        security_sequence_number: 3,
                        security_request_id: 3,
                    }),
                    contents: OPCUAContents::MESSAGE(OPCUAMessage {
                        type_id: OPCUAExpandedNodeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 461,
                        },
                        message: OPCUASpecificMessage::CREATE_SESSION_REQUEST(OPCUACreateSessionRequest {
                            request_header: OPCUAMessageRequestHeader {
                                authorization_token: 0x0000,
                                timestamp: String::from("2009-09-01 23:29:28"),
                                request_handle: 1,
                                return_diagnostic: 0x000003ff,
                                audit_entry_id: String::new(),
                                timeout_hint: 0,
                                addition_header: OPCUAMessageAdditionalHeader {
                                    type_id: OPCUAExpandedNodeId {
                                        encoding_mask: 0,
                                        namespace_index: 0,
                                        identifier_numeric: 0,
                                    },
                                    encoding_mask: 0x00,
                                },
                            },
                            client_description: OPCUAApplicationDescription {
                                application_uri: String::from("uri://AchillesSatellite/Opc.Ua.ServerTestTool/55ea864a-2be8-4bc6-bb73-1123c54d0fc4"),
                                product_uri: String::from("urn:opcfoundation.org/UA/ServerTest"),
                                application_name: OPCUALocalizedText {
                                    encoding_mask: 0x02,
                                    text: String::from("ApplicationName"),
                                },
                                application_type: 0x000000001,
                                gateway_server_uri: String::new(),
                                discovery_profile_uri: String::new(),
                                discovery_urls: OPCUAStringArray {
                                    array_size: 0,
                                    array_value: vec![],
                                },
                            },
                            server_uri: String::from("http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"),
                            endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/UA/StackTestServer"),
                            session_name: String::from("MySession 1"),
                            client_nonce: vec![
                                            0x20, 0x00, 0x00, 0x00, 0x40, 0x6d,
                                0x59, 0x31, 0xba, 0x64, 0x40, 0x41, 0xe1, 0x42,
                                0xa3, 0x90, 0xe8, 0xba, 0xda, 0xc6, 0x82, 0x62,
                                0xb2, 0x4f, 0x0a, 0x30, 0xdc, 0x3d, 0x63, 0x9d,
                                0x88, 0xc0, 0x23, 0x68, 0x41, 0xbf
                            ],
                            client_certificate: vec![48, 130, 2, 201, 48, 130, 2, 54, 160, 3, 2, 1, 2, 2, 16, 30, 89, 53, 107, 11, 128, 1, 167, 69, 232, 14, 248, 215, 164, 210, 35, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 54, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 97, 110, 111, 111, 112, 120, 112, 118, 109, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 85, 65, 32, 83, 97, 109, 112, 108, 101, 32, 67, 108, 105, 101, 110, 116, 48, 30, 23, 13, 48, 57, 48, 55, 50, 52, 49, 54, 50, 48, 49, 56, 90, 23, 13, 49, 57, 48, 55, 50, 52, 49, 54, 50, 48, 49, 56, 90, 48, 54, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 97, 110, 111, 111, 112, 120, 112, 118, 109, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 85, 65, 32, 83, 97, 109, 112, 108, 101, 32, 67, 108, 105, 101, 110, 116, 48, 129, 159, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 129, 141, 0, 48, 129, 137, 2, 129, 129, 0, 168, 33, 158, 185, 195, 221, 85, 128, 132, 237, 213, 150, 54, 126, 213, 49, 208, 26, 28, 188, 80, 206, 146, 228, 11, 135, 138, 5, 208, 78, 74, 71, 242, 132, 244, 250, 114, 136, 212, 80, 158, 13, 236, 186, 219, 25, 30, 218, 71, 104, 178, 42, 122, 232, 82, 178, 1, 34, 52, 231, 56, 63, 8, 90, 25, 35, 70, 152, 178, 175, 104, 199, 68, 25, 43, 139, 67, 64, 41, 11, 198, 155, 220, 37, 159, 117, 96, 99, 24, 71, 50, 246, 240, 166, 109, 0, 203, 208, 234, 79, 196, 221, 204, 72, 241, 95, 220, 70, 205, 15, 156, 23, 66, 67, 223, 127, 139, 22, 89, 100, 9, 126, 103, 155, 175, 209, 77, 255, 2, 3, 1, 0, 1, 163, 129, 223, 48, 129, 220, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 171, 116, 254, 123, 143, 167, 61, 167, 214, 177, 56, 224, 255, 72, 247, 245, 144, 90, 86, 211, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 171, 116, 254, 123, 143, 167, 61, 167, 214, 177, 56, 224, 255, 72, 247, 245, 144, 90, 86, 211, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 90, 6, 3, 85, 29, 7, 4, 83, 48, 81, 134, 68, 117, 114, 105, 58, 47, 47, 86, 49, 55, 48, 48, 47, 79, 112, 99, 46, 85, 97, 46, 83, 97, 109, 112, 108, 101, 67, 108, 105, 101, 110, 116, 47, 50, 49, 54, 57, 98, 56, 97, 99, 45, 56, 56, 101, 52, 45, 52, 56, 51, 49, 45, 57, 51, 99, 52, 45, 97, 51, 50, 53, 97, 49, 97, 98, 100, 49, 57, 98, 130, 9, 97, 110, 111, 111, 112, 120, 112, 118, 109, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 129, 129, 0, 155, 236, 49, 60, 16, 184, 28, 242, 110, 236, 8, 48, 60, 115, 71, 253, 154, 228, 220, 230, 91, 251, 149, 182, 48, 156, 171, 170, 152, 105, 114, 160, 45, 215, 10, 231, 254, 244, 111, 200, 85, 58, 155, 55, 36, 69, 99, 149, 66, 71, 197, 99, 44, 205, 7, 14, 99, 148, 20, 88, 197, 124, 75, 20, 185, 29, 186, 249, 135, 80, 129, 126, 85, 74, 186, 52, 210, 180, 171, 38, 111, 29, 26, 78, 102, 113, 219, 17, 132, 78, 70, 136, 155, 58, 144, 62, 8, 175, 92, 193, 199, 189, 124, 6, 252, 38, 242, 25, 108, 221, 159, 132, 149, 178, 243, 202, 84, 209, 78, 83, 207, 124, 202, 14, 207, 179, 21, 109],
                            requested_session_timeout: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0xed, 0x40],
                            max_response_message_size: 4194304,
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
    fn test_parse_opcua_activate_session_request() {
        let pcap = include_bytes!("pcaps/opcua/opcua_message_activate_session_request.pcap");
        let payload = &pcap[24+16+66..];
        match parse_opcua(payload) {
            Ok((rem, opc_ua)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(opc_ua, OPCUA {
                    header: OPCUAHeader::MESSAGE(OPCUAMessageHeader {
                        message_type: String::from("MSG"),
                        chunk_type: b'F',
                        message_size: 106,
                        security_channel_id: 6495,
                        security_token_id: 1,
                        security_sequence_number: 4,
                        security_request_id: 4,
                    }),
                    contents: OPCUAContents::MESSAGE(OPCUAMessage {
                        type_id: OPCUAExpandedNodeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 467,
                        },
                        message: OPCUASpecificMessage::ACTIVATE_SESSION_REQUEST(OPCUAActivateSessionRequest {
                            request_header: OPCUAMessageRequestHeader {
                                authorization_token: 6527,
                                timestamp: String::from("2009-09-01 23:29:28"),
                                request_handle: 1,
                                return_diagnostic: 0x000003ff,
                                audit_entry_id: String::new(),
                                timeout_hint: 0,
                                addition_header: OPCUAMessageAdditionalHeader {
                                    type_id: OPCUAExpandedNodeId {
                                        encoding_mask: 0,
                                        namespace_index: 0,
                                        identifier_numeric: 0,
                                    },
                                    encoding_mask: 0x00,
                                },
                            },
                            client_signature: OPCUASignatureData {
                                algorithm: String::new(),
                                signature: String::new(),
                            },
                            client_software_certificates: OPCUASignatureSoftwareCertificates {
                                array_size: 0,
                                signed_software_certificates: vec![],
                            },
                            locale_ids: OPCUAStringArray {
                                array_size: 1,
                                array_value: vec![
                                    String::from("en-US"),
                                ],
                            },
                            user_identity_token: OPCUAExtensionObject {
                                type_id: OPCUAExpandedNodeId {
                                    encoding_mask: 1,
                                    namespace_index: 0,
                                    identifier_numeric: 321,
                                },
                                encoding_mask: 0x01,
                                anonymous_identity_token: OPCUAAnonymousIdentityToken {
                                    policy_id: b'0',
                                },
                            },
                            user_token_signature: OPCUASignatureData {
                                algorithm: String::new(),
                                signature: String::new(),
                            },
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
    fn test_parse_opcua_activate_session_response() {
        let pcap = include_bytes!("pcaps/opcua/opcua_message_activate_session_response.pcap");
        let payload = &pcap[24+16+66..];
        match parse_opcua(payload) {
            Ok((rem, opc_ua)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(opc_ua, OPCUA {
                    header: OPCUAHeader::MESSAGE(OPCUAMessageHeader {
                        message_type: String::from("MSG"),
                        chunk_type: b'F',
                        message_size: 96,
                        security_channel_id: 6495,
                        security_token_id: 1,
                        security_sequence_number: 54,
                        security_request_id: 4,
                    }),
                    contents: OPCUAContents::MESSAGE(OPCUAMessage {
                        type_id: OPCUAExpandedNodeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 470,
                        },
                        message: OPCUASpecificMessage::ACTIVATE_SESSION_RESPONSE(OPCUAActivateSessionResponse {
                            response_header: OPCUAMessageResponseHeader {
                                timestamp: String::from("2009-09-01 23:31:34"),
                                request_handle: 1,
                                service_result: 0x00000000,
                                service_diagnostics: 0x00,
                                string_table: vec![0x00, 0x00, 0x00, 0x00],
                                additional_header: OPCUAMessageAdditionalHeader {
                                    type_id: OPCUAExpandedNodeId {
                                        encoding_mask: 0,
                                        namespace_index: 0,
                                        identifier_numeric: 0,
                                    },
                                    encoding_mask: 0x00,
                                },
                            },
                            server_nonce: vec![243, 123, 189, 6, 77, 35, 236, 136, 59, 94, 105, 131, 36, 15, 17, 13, 134, 107, 70, 202, 72, 65, 202, 222, 143, 118, 81, 205, 37, 98, 63, 134],
                            result: OPCUAStatusCode {
                                array_size: 0,
                                status_codes: vec![],
                            },
                            diagnostic_infos: OPCUADiagnosticInfo {
                                array_size: 0,
                                diagnostic_info: vec![],
                            },
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
    fn test_parse_opcua_create_session_response() {
        let pcap = include_bytes!("pcaps/opcua/opcua_message_create_session_response.bin");
        let payload = &pcap[..];
        match parse_opcua(payload) {
            Ok((rem, opc_ua)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(opc_ua, OPCUA {
                    header: OPCUAHeader::MESSAGE(OPCUAMessageHeader {
                        message_type: String::from("MSG"),
                        chunk_type: b'F',
                        message_size: 8086,
                        security_channel_id: 6495,
                        security_token_id: 1,
                        security_sequence_number: 53,
                        security_request_id: 3,
                    }),
                    contents: OPCUAContents::MESSAGE(OPCUAMessage {
                        type_id: OPCUAExpandedNodeId {
                            encoding_mask: 0x01,
                            namespace_index: 0,
                            identifier_numeric: 464,
                        },
                        message: OPCUASpecificMessage::CREATE_SESSION_RESPONSE(OPCUACreateSessionResponse {
                            response_header: OPCUAMessageResponseHeader {
                                timestamp: String::from("2009-09-01 23:31:34"),
                                request_handle: 1,
                                service_result: 0x00000000,
                                service_diagnostics: 0,
                                string_table: vec![0x00, 0x00, 0x00, 0x00],
                                additional_header: OPCUAMessageAdditionalHeader {
                                    type_id: OPCUAExpandedNodeId {
                                        encoding_mask: 0x00,
                                        namespace_index: 0,
                                        identifier_numeric: 0,
                                    },
                                    encoding_mask: 0x00,
                                },
                            },
                            session_id: OPCUAExpandedNodeId {
                                encoding_mask: 0x02,
                                namespace_index: 10,
                                identifier_numeric: 365457,
                            },
                            authentication_token: OPCUAExpandedNodeId {
                                encoding_mask: 0x01,
                                namespace_index: 0,
                                identifier_numeric: 6527,
                            },
                            revised_session_timeout: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0xed, 0x40],
                            server_nonce: vec![193, 173, 147, 16, 117, 10, 42, 196, 204, 6, 64, 233, 98, 108, 15, 29, 146, 35, 226, 211, 22, 63, 193, 109, 74, 83, 133, 114, 1, 151, 53, 132],
                            server_certificate: vec![48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74],
                            server_endpoints: OPCUAEndpointsInfo {
                                array_size: 5,
                                endpoints: vec![
                                    OPCUAEndpointDescription {
                                        endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                        server: OPCUAApplicationDescription {
                                            application_uri: String::from("http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"),
                                            product_uri: String::new(),
                                            application_name: OPCUALocalizedText {
                                                encoding_mask: 0x02,
                                                text: String::from("UA StackTest Server (AnsiC/2048)"),
                                            },
                                            application_type: 0,
                                            gateway_server_uri: String::new(),
                                            discovery_profile_uri: String::new(),
                                            discovery_urls: OPCUAStringArray {
                                                array_size: 1,
                                                array_value: vec![
                                                    String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                                ],
                                            },
                                        },
                                        server_certificate: vec![48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74],
                                        message_security_mode: 0x00000001,
                                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#None"),
                                        user_identity_tokens: OPCUAUserTokenPolicies {
                                            array_size: 1,
                                            user_token_policies: vec![
                                                OPCUAUserTokenPolicy {
                                                    policy_id: b'0',
                                                    user_token_type: 0x00000000,
                                                    issued_token_type: String::new(),
                                                    issuer_endpoint_url: String::new(),
                                                    security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#Basic256"),
                                                },
                                            ],
                                        },
                                        transport_profile_uri: String::from("http://opcfoundation.org/UA/profiles/transport/uatcp"),
                                        security_level: 0,
                                    },
                                    OPCUAEndpointDescription {
                                        endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                        server: OPCUAApplicationDescription {
                                            application_uri: String::from("http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"),
                                            product_uri: String::new(),
                                            application_name: OPCUALocalizedText {
                                                encoding_mask: 0x02,
                                                text: String::from("UA StackTest Server (AnsiC/2048)"),
                                            },
                                            application_type: 0,
                                            gateway_server_uri: String::new(),
                                            discovery_profile_uri: String::new(),
                                            discovery_urls: OPCUAStringArray {
                                                array_size: 1,
                                                array_value: vec![
                                                    String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                                ],
                                            },
                                        },
                                        server_certificate: vec![48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74],
                                        message_security_mode: 0x00000003,
                                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"),
                                        user_identity_tokens: OPCUAUserTokenPolicies {
                                            array_size: 1,
                                            user_token_policies: vec![
                                                OPCUAUserTokenPolicy {
                                                    policy_id: b'0',
                                                    user_token_type: 0x00000000,
                                                    issued_token_type: String::new(),
                                                    issuer_endpoint_url: String::new(),
                                                    security_policy_uri: String::new(),
                                                },
                                            ],
                                        },
                                        transport_profile_uri: String::from("http://opcfoundation.org/UA/profiles/transport/uatcp"),
                                        security_level: 0,
                                    },
                                    OPCUAEndpointDescription {
                                        endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                        server: OPCUAApplicationDescription {
                                            application_uri: String::from("http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"),
                                            product_uri: String::new(),
                                            application_name: OPCUALocalizedText {
                                                encoding_mask: 0x02,
                                                text: String::from("UA StackTest Server (AnsiC/2048)"),
                                            },
                                            application_type: 0,
                                            gateway_server_uri: String::new(),
                                            discovery_profile_uri: String::new(),
                                            discovery_urls: OPCUAStringArray {
                                                array_size: 1,
                                                array_value: vec![
                                                    String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                                ],
                                            },
                                        },
                                        server_certificate: vec![48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74],
                                        message_security_mode: 0x00000002,
                                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"),
                                        user_identity_tokens: OPCUAUserTokenPolicies {
                                            array_size: 1,
                                            user_token_policies: vec![
                                                OPCUAUserTokenPolicy {
                                                    policy_id: b'0',
                                                    user_token_type: 0x00000000,
                                                    issued_token_type: String::new(),
                                                    issuer_endpoint_url: String::new(),
                                                    security_policy_uri: String::new(),
                                                },
                                            ],
                                        },
                                        transport_profile_uri: String::from("http://opcfoundation.org/UA/profiles/transport/uatcp"),
                                        security_level: 0,
                                    },
                                    OPCUAEndpointDescription {
                                        endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                        server: OPCUAApplicationDescription {
                                            application_uri: String::from("http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"),
                                            product_uri: String::new(),
                                            application_name: OPCUALocalizedText {
                                                encoding_mask: 0x02,
                                                text: String::from("UA StackTest Server (AnsiC/2048)"),
                                            },
                                            application_type: 0,
                                            gateway_server_uri: String::new(),
                                            discovery_profile_uri: String::new(),
                                            discovery_urls: OPCUAStringArray {
                                                array_size: 1,
                                                array_value: vec![
                                                    String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                                ],
                                            },
                                        },
                                        server_certificate: vec![48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74],
                                        message_security_mode: 0x00000003,
                                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#Basic256"),
                                        user_identity_tokens: OPCUAUserTokenPolicies {
                                            array_size: 1,
                                            user_token_policies: vec![
                                                OPCUAUserTokenPolicy {
                                                    policy_id: b'0',
                                                    user_token_type: 0x00000000,
                                                    issued_token_type: String::new(),
                                                    issuer_endpoint_url: String::new(),
                                                    security_policy_uri: String::new(),
                                                },
                                            ],
                                        },
                                        transport_profile_uri: String::from("http://opcfoundation.org/UA/profiles/transport/uatcp"),
                                        security_level: 0,
                                    },
                                    OPCUAEndpointDescription {
                                        endpoint_url: String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                        server: OPCUAApplicationDescription {
                                            application_uri: String::from("http://vm-xp-steven/UA StackTest Server (AnsiC/2048)"),
                                            product_uri: String::new(),
                                            application_name: OPCUALocalizedText {
                                                encoding_mask: 0x02,
                                                text: String::from("UA StackTest Server (AnsiC/2048)"),
                                            },
                                            application_type: 0,
                                            gateway_server_uri: String::new(),
                                            discovery_profile_uri: String::new(),
                                            discovery_urls: OPCUAStringArray {
                                                array_size: 1,
                                                array_value: vec![
                                                    String::from("opc.tcp://vm-xp-steven:12001/StackTestServer/AnsiC/2048"),
                                                ],
                                            },
                                        },
                                        server_certificate: vec![48, 130, 3, 231, 48, 130, 2, 211, 160, 3, 2, 1, 2, 2, 16, 7, 51, 173, 50, 89, 170, 156, 131, 75, 107, 220, 132, 126, 188, 151, 86, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 30, 23, 13, 48, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 23, 13, 49, 57, 48, 56, 49, 55, 49, 56, 49, 54, 51, 54, 90, 48, 73, 49, 28, 48, 26, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 49, 41, 48, 39, 6, 3, 85, 4, 3, 19, 32, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 140, 89, 34, 103, 103, 72, 248, 223, 251, 101, 49, 91, 103, 141, 158, 215, 122, 211, 115, 34, 0, 58, 107, 193, 183, 167, 121, 252, 121, 41, 140, 204, 211, 245, 42, 206, 185, 200, 139, 181, 213, 179, 159, 60, 228, 121, 193, 167, 133, 45, 78, 75, 28, 8, 46, 160, 90, 134, 48, 7, 145, 77, 6, 72, 180, 30, 20, 158, 107, 163, 178, 207, 61, 128, 90, 158, 185, 122, 192, 107, 125, 48, 5, 170, 182, 77, 206, 62, 78, 210, 39, 242, 97, 91, 44, 198, 132, 251, 242, 140, 73, 208, 126, 80, 135, 130, 31, 235, 176, 114, 42, 229, 163, 112, 240, 65, 248, 222, 61, 124, 57, 93, 192, 237, 5, 194, 210, 155, 106, 84, 111, 215, 149, 197, 20, 193, 214, 126, 9, 53, 214, 206, 74, 64, 49, 11, 35, 223, 44, 177, 224, 50, 192, 160, 200, 203, 179, 76, 4, 136, 32, 185, 140, 102, 27, 147, 246, 58, 5, 219, 88, 48, 117, 59, 29, 130, 17, 56, 47, 203, 93, 107, 136, 180, 64, 160, 60, 156, 131, 68, 62, 251, 19, 125, 193, 216, 67, 54, 250, 213, 91, 216, 118, 19, 153, 95, 46, 72, 138, 128, 120, 111, 127, 110, 82, 105, 164, 39, 47, 119, 149, 235, 146, 114, 191, 214, 239, 96, 233, 149, 45, 200, 188, 122, 10, 113, 69, 133, 239, 133, 82, 37, 39, 90, 39, 142, 62, 104, 178, 218, 242, 166, 159, 112, 223, 229, 2, 3, 1, 0, 1, 163, 129, 210, 48, 129, 207, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 31, 6, 3, 85, 29, 1, 4, 24, 48, 22, 128, 20, 50, 79, 86, 230, 52, 208, 176, 1, 227, 144, 210, 213, 5, 87, 153, 241, 173, 36, 21, 60, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 244, 48, 32, 6, 3, 85, 29, 37, 1, 1, 255, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 77, 6, 3, 85, 29, 7, 4, 70, 48, 68, 134, 52, 104, 116, 116, 112, 58, 47, 47, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 47, 85, 65, 32, 83, 116, 97, 99, 107, 84, 101, 115, 116, 32, 83, 101, 114, 118, 101, 114, 32, 40, 65, 110, 115, 105, 67, 47, 50, 48, 52, 56, 41, 130, 12, 118, 109, 45, 120, 112, 45, 115, 116, 101, 118, 101, 110, 48, 9, 6, 5, 43, 14, 3, 2, 29, 5, 0, 3, 130, 1, 1, 0, 28, 144, 243, 244, 135, 216, 10, 180, 190, 246, 50, 151, 113, 122, 20, 153, 138, 185, 161, 115, 98, 253, 148, 11, 135, 161, 186, 127, 30, 199, 238, 185, 120, 120, 135, 31, 104, 9, 152, 82, 231, 87, 247, 86, 68, 229, 174, 209, 103, 14, 122, 37, 242, 250, 14, 240, 254, 64, 59, 30, 107, 130, 181, 221, 82, 156, 142, 190, 169, 195, 203, 148, 120, 35, 112, 100, 195, 223, 91, 161, 123, 249, 136, 207, 125, 112, 142, 100, 26, 244, 127, 10, 179, 42, 79, 237, 152, 168, 132, 37, 226, 161, 71, 100, 124, 248, 143, 37, 166, 96, 106, 195, 6, 147, 245, 129, 201, 57, 101, 188, 64, 100, 227, 145, 178, 234, 213, 223, 120, 134, 158, 140, 232, 147, 66, 71, 165, 190, 187, 79, 132, 200, 243, 187, 147, 195, 252, 7, 129, 18, 138, 252, 10, 219, 9, 21, 55, 82, 26, 211, 6, 215, 23, 235, 177, 25, 18, 122, 101, 26, 200, 54, 17, 195, 127, 105, 6, 175, 205, 223, 143, 10, 115, 231, 217, 115, 254, 211, 151, 83, 167, 116, 34, 33, 178, 11, 176, 19, 203, 194, 118, 252, 63, 160, 188, 83, 149, 108, 93, 65, 171, 97, 63, 38, 175, 60, 214, 157, 168, 210, 243, 10, 137, 211, 196, 46, 73, 175, 100, 199, 84, 22, 138, 164, 253, 189, 119, 66, 206, 160, 193, 191, 197, 64, 46, 181, 209, 33, 19, 16, 217, 151, 78, 255, 111, 74],
                                        message_security_mode: 0x00000002,
                                        security_policy_uri: String::from("http://opcfoundation.org/UA/SecurityPolicy#Basic256"),
                                        user_identity_tokens: OPCUAUserTokenPolicies {
                                            array_size: 1,
                                            user_token_policies: vec![
                                                OPCUAUserTokenPolicy {
                                                    policy_id: b'0',
                                                    user_token_type: 0x00000000,
                                                    issued_token_type: String::new(),
                                                    issuer_endpoint_url: String::new(),
                                                    security_policy_uri: String::new(),
                                                },
                                            ],
                                        },
                                        transport_profile_uri: String::from("http://opcfoundation.org/UA/profiles/transport/uatcp"),
                                        security_level: 0,
                                    },
                                ],
                            },
                            server_software_certificates: OPCUASignatureSoftwareCertificates {
                                array_size: 0,
                                signed_software_certificates: vec![],
                            },
                            server_signature: OPCUASignatureData {
                                algorithm: String::new(),
                                signature: String::new(),
                            },
                            max_request_message_size: 4194304,
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
    fn test_parse_opcua_error_message() {
        let pcap = include_bytes!("pcaps/opcua/opcua_error_message.pcap");
        let payload = &pcap[24+16+66..];
        match parse_opcua(payload) {
            Ok((rem, opc_ua)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(opc_ua, OPCUA {
                    header: OPCUAHeader::ERROR(OPCUAErrorHeader {
                        message_type: String::from("ERR"),
                        chunk_type: b'F',
                        message_size: 16,
                        error: 0x80020000,
                        reason: String::new(),
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
    fn test_translate_timestamp_to_string() {
        let raw_timestamp = [0x00, 0x3c, 0x7d, 0x0c, 0x5c, 0x2b, 0xca, 0x01];
        let origin_timestamp_millis= i64::from_le_bytes(raw_timestamp);
        let unix_timestamp = origin_timestamp_millis / WINDOWS_TICK - SEC_TO_UNIX_EPOCH;
        let nt = NaiveDateTime::from_timestamp_opt(unix_timestamp, 0).unwrap();
        let utc_datetime: DateTime<Utc> = DateTime::from_utc(nt, Utc);
        let _res = utc_datetime.format("%Y-%m-%d %H:%M:%S").to_string();
    }
}
