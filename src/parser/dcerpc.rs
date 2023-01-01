use nom7::{IResult, number::{complete::{be_u8, u16, u32}, Endianness}, bytes::complete::{take, take_till}, combinator::rest};

const NTLMSSP_NEGOTIATE: u32 = 0x01;
const NTLMSSP_CHALLENGE: u32 = 0x02;
const NTLMSSP_AUTH: u32 = 0x03;

#[derive(Debug, PartialEq)]
pub struct DCERPCHeader {
    version: u8,
    min_version: u8,
    packet_type: u8,
    packet_flags: u8,
    data_representation: Vec<u8>,
    frag_length: u16,
    auth_length: u16,
    call_id: u32,
}

#[derive(Debug, PartialEq)]
pub struct DCERPCBindCtxItemAbstractSyntax {
    interface_uuid: Vec<u8>,
    interface_ver: u16,
    interface_ver_minor: u16,
}

#[derive(Debug, PartialEq)]
pub struct DCERPCBindCtxItemTransferSyntax {
    transfer_syntax_uuid: Vec<u8>,
    version: u32,
}

#[derive(Debug, PartialEq)]
pub struct DCERPCBindCtxItem {
    context_id: u16,
    num_trans_items: u16,
    abstract_syntax: Vec<DCERPCBindCtxItemAbstractSyntax>,
    transfer_syntax: Vec<DCERPCBindCtxItemTransferSyntax>,
}

#[derive(Debug, PartialEq)]
pub struct DCERPCBindAckCtxItem {
    ack_result: u16,
    bind_time_features: u16,
    transfer_syntax: Vec<u8>,
    syntax_ver: u32,
}

#[derive(Debug, PartialEq)]
pub struct DCERPCBind {
    max_xmit_frag: u16,
    max_recv_frag: u16,
    assoc_group: u32,
    num_ctx_items: u32,
    ctx_items: Vec<DCERPCBindCtxItem>,
    auth_info: Option<DCERPCAuthInfo>,
}

#[derive(Debug, PartialEq)]
pub struct DCERPCBindAck {
    max_xmit_frag: u16,
    max_recv_frag: u16,
    assoc_group: u32,
    scndry_addr_len: u16,
    scndry_addr: Vec<u8>,
    num_results: u32,
    ctx_items: Vec<DCERPCBindAckCtxItem>,
    auth_info: Option<DCERPCAuthInfo>,
}

#[derive(Debug, PartialEq)]
pub struct DCERPCRequest {
    alloc_hint: u32,
    context_id: u16,
    op_num: u16,
    complete_stub_data: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq)]
pub struct DCERPCResponse {
    alloc_hint: u32,
    context_id: u16,
    cancel_count: u8,
    complete_stub_data: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq)]
pub struct DCERPCAuthInfo {
    auth_type: u8,
    auth_level: u8,
    auth_pad_len: u8,
    auth_reserved: u8,
    auth_context_id: u32,
    auth_data: NTLMSecureServiceProvider,
}

#[derive(Debug, PartialEq)]
pub struct AuthMetaInfo {
    length: u16,
    maxlen: u16,
    offset: u32,
}

#[derive(Debug, PartialEq)]
pub struct AuthVersion {
    major_version: u8,
    minor_version: u8,
    build_number: u16,
    ntlm_current_revision: u8,
}

#[derive(Debug, PartialEq)]
pub struct AuthAttribute {
    item_type: u16,
    item_length: u16,
    item_name: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct AuthTargetInfo {
    attributes: Vec<AuthAttribute>,
}

#[derive(Debug, PartialEq)]
pub struct NTLMSSPNegotiate {
    calling_workstation_domain: Vec<u8>,
    calling_workstation_name: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct NTLMSSPChallenge {
    target_name_meta_info: AuthMetaInfo,
    target_info_meta_info: AuthMetaInfo,
    target_name: Vec<u8>,
    target_info: AuthTargetInfo,
    server_challenge: Vec<u8>,
    reserved: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct NTLMAuthResponse {
    nt_proof_str: Vec<u8>,
    response_version: u8,
    hi_response_version: u8,
    time: Vec<u8>,
    ntlm2_client_challenge: Vec<u8>,
    attributes: Vec<AuthAttribute>,
}

#[derive(Debug, PartialEq)]
pub struct NTLMSSPAuth {
    lan_manager_response_meta_info: AuthMetaInfo,
    ntlm_response_meta_info: AuthMetaInfo,
    domain_name_meta_info: AuthMetaInfo,
    user_name_meta_info: AuthMetaInfo,
    host_name_meta_info: AuthMetaInfo,
    session_key_meta_info: AuthMetaInfo,
    mic: Vec<u8>,
    domain_name: Vec<u8>,
    user_name: Vec<u8>,
    host_name: Vec<u8>,
    lan_manager_response: Vec<u8>,
    ntlm_response: NTLMAuthResponse,
    session_key: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum NTLMSSPMessage {
    Negotiate(NTLMSSPNegotiate),
    Challenge(NTLMSSPChallenge),
    Auth(NTLMSSPAuth),
}

#[derive(Debug, PartialEq)]
pub struct NTLMSecureServiceProvider {
    ntlm_identifier: Vec<u8>,
    ntlm_message_type: u32,
    negotiate_flags: u32,
    version: AuthVersion,
    ntlm_message: NTLMSSPMessage,
}

#[derive(Debug, PartialEq)]
pub struct DCERPCResponseFault {
    alloc_hint: u32,
    context_id: u16,
    cancel_count: u8,
    fault_flags: u8,
    status: u32,
    reserved: u32,
}

pub fn parse_dcerpc_header(input: &[u8]) -> IResult<&[u8], DCERPCHeader> {
    let (rem, version) = be_u8(input)?;
    let (rem, min_version) = be_u8(rem)?;
    let (rem, packet_type) = be_u8(rem)?;
    let (rem, packet_flags) = be_u8(rem)?;
    let (rem, data_representation) = take(4usize)(rem)?;
    let endianess = if data_representation[0] & 0x10 == 0 {
        Endianness::Big
    } else {
        Endianness::Little
    };
    let (rem, frag_length) = u16(endianess)(rem)?;
    let (rem, auth_length) = u16(endianess)(rem)?;
    let (rem, call_id) = u32(endianess)(rem)?;
    Ok((rem, DCERPCHeader {
        version,
        min_version,
        packet_type,
        packet_flags,
        data_representation: data_representation.to_vec(),
        frag_length,
        auth_length,
        call_id,
    }))
}

pub fn parse_dcerpc_bind_ctx_items_abstract_syntax(input: &[u8], endianess: Endianness) -> IResult<&[u8], DCERPCBindCtxItemAbstractSyntax> {
    let (rem, interface_uuid) = take(16usize)(input)?;
    let (rem, interface_ver) = u16(endianess)(rem)?;
    let (rem, interface_ver_minor) = u16(endianess)(rem)?;
    Ok((rem, DCERPCBindCtxItemAbstractSyntax {
        interface_uuid: interface_uuid.to_vec(),
        interface_ver,
        interface_ver_minor,
    }))
}

pub fn parse_dcerpc_bind_ctx_items_transfer_syntax(input: &[u8], endianess: Endianness) -> IResult<&[u8], DCERPCBindCtxItemTransferSyntax> {
    let (rem, transfer_syntax_uuid) = take(16usize)(input)?;
    let (rem, version) = u32(endianess)(rem)?;
    Ok((rem, DCERPCBindCtxItemTransferSyntax {
        transfer_syntax_uuid: transfer_syntax_uuid.to_vec(),
        version,
    }))
}

pub fn parse_dcerpc_bind_ctx_items(input: &[u8], endianess: Endianness, num_ctx_items: u32) -> IResult<&[u8], Vec<DCERPCBindCtxItem>> {
    let mut dcerpc_bind_ctx_items = Vec::with_capacity(num_ctx_items as usize);
    let mut rem = input;
    for _ in 0..num_ctx_items {
        let (rem1, context_id) = u16(endianess)(rem)?;
        let (rem2, num_trans_items) = u16(endianess)(rem1)?;
        let mut abstract_syntax = Vec::with_capacity(num_ctx_items as usize);
        let mut transfer_syntax = Vec::with_capacity(num_ctx_items as usize);
        let mut tmp_rem = rem2;
        for _ in 0..num_trans_items {
            let (rem, data) = parse_dcerpc_bind_ctx_items_abstract_syntax(tmp_rem, endianess)?;
            abstract_syntax.push(data);
            let (rem1, transfer) = parse_dcerpc_bind_ctx_items_transfer_syntax(rem, endianess)?;
            transfer_syntax.push(transfer);
            tmp_rem = rem1;
        }
        dcerpc_bind_ctx_items.push(DCERPCBindCtxItem {
            context_id,
            num_trans_items,
            abstract_syntax,
            transfer_syntax,
        });
        rem = tmp_rem;
    }
    Ok((rem, dcerpc_bind_ctx_items))
}

pub fn parse_dcerpc_bind(input: &[u8], endianess: Endianness, has_authinfo: bool) -> IResult<&[u8], DCERPCBind> {
    let (rem, max_xmit_frag) = u16(endianess)(input)?;
    let (rem, max_recv_frag) = u16(endianess)(rem)?;
    let (rem, assoc_group) = u32(endianess)(rem)?;
    let (rem, num_ctx_items) = u32(endianess)(rem)?;
    let (rem, ctx_items) = parse_dcerpc_bind_ctx_items(rem, endianess, num_ctx_items)?;
    let (rem, auth_info) = if has_authinfo {
        let (rem, auth_data) = parse_dcerpc_auth_info(rem, endianess)?;
        let auth_info = Some(auth_data);
        (rem, auth_info)
    } else {
        (rem, None)
    };
    Ok((rem, DCERPCBind {
        max_xmit_frag,
        max_recv_frag,
        assoc_group,
        num_ctx_items,
        ctx_items,
        auth_info,
    }))
}

pub fn parse_dcerpc_bind_ack_ctx_items(input: &[u8], endianess: Endianness, num_results: u32) -> IResult<&[u8], Vec<DCERPCBindAckCtxItem>> {
    let mut dcerpc_bind_ack_ctx_items = Vec::with_capacity(num_results as usize);
    let mut rem = input;
    for _ in 0..num_results {
        let (tmp_rem, ack_result) = u16(endianess)(rem)?;
        let (tmp_rem, bind_time_features) = u16(endianess)(tmp_rem)?;
        let (tmp_rem, transfer_syntax) = take(16usize)(tmp_rem)?;
        let (tmp_rem, syntax_ver) = u32(endianess)(tmp_rem)?;
        dcerpc_bind_ack_ctx_items.push(DCERPCBindAckCtxItem {
            ack_result,
            bind_time_features,
            transfer_syntax: transfer_syntax.to_vec(),
            syntax_ver,
        });
        rem = tmp_rem;
    }
    Ok((rem, dcerpc_bind_ack_ctx_items))
}

pub fn parse_dcerpc_bind_ack(input: &[u8], endianess: Endianness, has_authinfo: bool) -> IResult<&[u8], DCERPCBindAck> {
    let (rem, max_xmit_frag) = u16(endianess)(input)?;
    let (rem, max_recv_frag) = u16(endianess)(rem)?;
    let (rem, assoc_group) = u32(endianess)(rem)?;
    let (rem, scndry_addr_len) = u16(endianess)(rem)?;
    let (rem, scndry_addr) = take(scndry_addr_len as usize)(rem)?;
    let (rem, _) = take(2usize)(rem)?;
    let (rem, num_results) = u32(endianess)(rem)?;
    let (rem, ctx_items) = parse_dcerpc_bind_ack_ctx_items(rem, endianess, num_results)?;
    let (rem, auth_info) = if has_authinfo == true {
        let (rem, auth_data) = parse_dcerpc_auth_info(rem, endianess)?;
        let auth_info = Some(auth_data);
        (rem, auth_info)
    } else {
        (rem, None)
    };
    Ok((rem, DCERPCBindAck {
        max_xmit_frag,
        max_recv_frag,
        assoc_group,
        scndry_addr_len,
        scndry_addr: scndry_addr.to_vec(),
        num_results,
        ctx_items,
        auth_info,
    }))
}

pub fn parse_dcerpc_request(input: &[u8], endianess: Endianness) -> IResult<&[u8], DCERPCRequest> {
    let (rem, alloc_hint) = u32(endianess)(input)?;
    let (rem, context_id) = u16(endianess)(rem)?;
    let (rem, op_num) = u16(endianess)(rem)?;
    let mut rem = rem;
    let mut complete_stub_data: Option<Vec<u8>>= None;
    if op_num != 5 {
        let (tmp_rem, real_stub_data) = rest(rem)?;
        complete_stub_data = Some(real_stub_data.to_vec());
        rem = tmp_rem;
    }
    Ok((rem, DCERPCRequest {
        alloc_hint,
        context_id,
        op_num,
        complete_stub_data,
    }))
}

pub fn parse_dcerpc_response(input: &[u8], endianess: Endianness) -> IResult<&[u8], DCERPCResponse> {
    let (rem, alloc_hint) = u32(endianess)(input)?;
    let (rem, context_id) = u16(endianess)(rem)?;
    let (rem, cancel_count) = be_u8(rem)?;
    let (rem, _) = take(1usize)(rem)?;
    let (rem, real_complete_stub_data) = rest(rem)?;
    Ok((rem, DCERPCResponse {
        alloc_hint,
        context_id,
        cancel_count,
        complete_stub_data: Some(real_complete_stub_data.to_vec()),
    }))
}

pub fn parse_dcerpc_auth_version(input: &[u8], endianess: Endianness) -> IResult<&[u8], AuthVersion> {
    let (rem, major_version) = be_u8(input)?;
    let (rem, minor_version) = be_u8(rem)?;
    let (rem, build_number) = u16(endianess)(rem)?;
    let (rem, _) = take(3usize)(rem)?;
    let (rem, ntlm_current_revision) = be_u8(rem)?;
    Ok((rem, AuthVersion {
        major_version,
        minor_version,
        build_number,
        ntlm_current_revision,
    }))
}

pub fn parse_dcerpc_auth_meta_info(input: &[u8], endianess: Endianness) -> IResult<&[u8], AuthMetaInfo> {
    let (rem, length) = u16(endianess)(input)?;
    let (rem, maxlen) = u16(endianess)(rem)?;
    let (rem, offset) = u32(endianess)(rem)?;
    Ok((rem, AuthMetaInfo {
        length,
        maxlen,
        offset,
    }))
}

pub fn parse_dcerpc_target_info(input: &[u8], endianess: Endianness, length: u16) -> IResult<&[u8], AuthTargetInfo> {
    let mut attributes = Vec::new();
    let mut tmp_length = length;
    let mut rem = input;
    loop {
        if tmp_length == 0 {
            break;
        }
        let (tmp_rem, item_type) = u16(endianess)(rem)?;
        let (tmp_rem, item_length) = u16(endianess)(tmp_rem)?;
        let (tmp_rem, item_name) = take(item_length as usize)(tmp_rem)?;
        attributes.push(AuthAttribute {
            item_type,
            item_length,
            item_name: item_name.to_vec(),
        });
        rem = tmp_rem;
        tmp_length -= (2 + 2 + item_length);
    }
    Ok((rem, AuthTargetInfo {
        attributes,
    }))
}

pub fn parse_dcerpc_auth_ntlm_response(input: &[u8], endianess: Endianness, length: u16) -> IResult<&[u8], NTLMAuthResponse> {
    let (rem, nt_proof_str) = take(16usize)(input)?;
    let (rem, response_version) = be_u8(rem)?;
    let (rem, hi_response_version) = be_u8(rem)?;
    let (rem, _) = take(6usize)(rem)?;
    let (rem, time) = take(8usize)(rem)?;
    let (rem, ntlm2_client_chanllenge) = take(8usize)(rem)?;
    let (rem, _) = take(4usize)(rem)?;
    let mut attributes = Vec::new();
    let mut tmp_length = length - (16 + 1 + 1 + 6 + 8 + 8 + 4);
    let mut tmp_rem = rem;
    loop {
        if tmp_length == 0 {
            break;
        }
        let (tmp_rem1, item_type) = u16(endianess)(tmp_rem)?;
        let (tmp_rem1, item_length) = u16(endianess)(tmp_rem1)?;
        let (tmp_rem1, item_name) = take(item_length as usize)(tmp_rem1)?;
        attributes.push(AuthAttribute {
            item_type,
            item_length,
            item_name: item_name.to_vec(),
        });
        tmp_rem = tmp_rem1;
        tmp_length -= (2 + 2 + item_length);
        if item_type == 0x0000 {
            let (tmp_rem1, _) = take(tmp_length as usize)(tmp_rem)?;
            tmp_rem = tmp_rem1;
            tmp_length = 0;
        }
    }
    Ok((tmp_rem, NTLMAuthResponse {
        nt_proof_str: nt_proof_str.to_vec(),
        response_version,
        hi_response_version,
        time: time.to_vec(),
        ntlm2_client_challenge: ntlm2_client_chanllenge.to_vec(),
        attributes,
    }))

}

pub fn parse_dcerpc_auth_secure_service_provider(input: &[u8], endianess: Endianness) -> IResult<&[u8], NTLMSecureServiceProvider> {
    let (rem, ntlm_identifier) = take_till(|c| c == 0x00)(input)?;
    let (rem, _) = be_u8(rem)?;
    let (rem, ntlm_message_type) = u32(endianess)(rem)?;
    match ntlm_message_type {
        NTLMSSP_NEGOTIATE => {
            let (rem, negotiate_flags) = u32(endianess)(rem)?;
            let (rem, calling_workstation_domain) = take(8usize)(rem)?;
            let (rem, calling_workstation_name) = take(8usize)(rem)?;
            let (rem, version) = parse_dcerpc_auth_version(rem, endianess)?;
            Ok((rem, NTLMSecureServiceProvider {
                ntlm_identifier: ntlm_identifier.to_vec(),
                ntlm_message_type,
                negotiate_flags,
                version,
                ntlm_message: NTLMSSPMessage::Negotiate(NTLMSSPNegotiate {
                    calling_workstation_domain: calling_workstation_domain.to_vec(),
                    calling_workstation_name: calling_workstation_name.to_vec(),
                }),
            }))
        },
        NTLMSSP_CHALLENGE => {
            let (rem, target_name_meta_info) = parse_dcerpc_auth_meta_info(rem, endianess)?;
            let (rem, negotiate_flags) = u32(endianess)(rem)?;
            let (rem, server_challenge) = take(8usize)(rem)?;
            let (rem, reserved) = take(8usize)(rem)?;
            let (rem, target_info_meta_info) = parse_dcerpc_auth_meta_info(rem, endianess)?;
            let (rem, version) = parse_dcerpc_auth_version(rem, endianess)?;
            let (rem, target_name) = take(target_name_meta_info.length as usize)(rem)?;
            let (rem, target_info) = parse_dcerpc_target_info(rem, endianess, target_info_meta_info.length)?;
            Ok((rem, NTLMSecureServiceProvider {
                ntlm_identifier: ntlm_identifier.to_vec(),
                ntlm_message_type,
                negotiate_flags,
                version,
                ntlm_message: NTLMSSPMessage::Challenge(NTLMSSPChallenge {
                    target_name_meta_info,
                    target_info_meta_info,
                    target_name: target_name.to_vec(),
                    target_info,
                    server_challenge: server_challenge.to_vec(),
                    reserved: reserved.to_vec(),
                }),
            }))
        },
        NTLMSSP_AUTH => {
            let (rem, lan_manager_response_meta_info) = parse_dcerpc_auth_meta_info(rem, endianess)?;
            let (rem, ntlm_response_meta_info) = parse_dcerpc_auth_meta_info(rem, endianess)?;
            let (rem, domain_name_meta_info) = parse_dcerpc_auth_meta_info(rem, endianess)?;
            let (rem, user_name_meta_info) = parse_dcerpc_auth_meta_info(rem, endianess)?;
            let (rem, host_name_meta_info) = parse_dcerpc_auth_meta_info(rem, endianess)?;
            let (rem, session_key_meta_info) = parse_dcerpc_auth_meta_info(rem, endianess)?;
            let (rem, negotiate_flags) = u32(endianess)(rem)?;
            let (rem, version) = parse_dcerpc_auth_version(rem, endianess)?;
            let (rem, mic) = take(16usize)(rem)?;
            let (rem, domain_name) = take(domain_name_meta_info.length as usize)(rem)?;
            let (rem, user_name) = take(user_name_meta_info.length as usize)(rem)?;
            let (rem, host_name) = take(host_name_meta_info.length as usize)(rem)?;
            let (rem, lan_manager_response) = take(lan_manager_response_meta_info.length as usize)(rem)?;
            let (rem, ntlm_response) = parse_dcerpc_auth_ntlm_response(rem, endianess, ntlm_response_meta_info.length)?;
            let (rem, session_key) = take(session_key_meta_info.length as usize)(rem)?;
            Ok((rem, NTLMSecureServiceProvider {
                ntlm_identifier: ntlm_identifier.to_vec(),
                ntlm_message_type,
                negotiate_flags,
                version,
                ntlm_message: NTLMSSPMessage::Auth(NTLMSSPAuth {
                    lan_manager_response_meta_info: lan_manager_response_meta_info,
                    ntlm_response_meta_info: ntlm_response_meta_info,
                    domain_name_meta_info: domain_name_meta_info,
                    user_name_meta_info: user_name_meta_info,
                    host_name_meta_info: host_name_meta_info,
                    session_key_meta_info: session_key_meta_info,
                    mic: mic.to_vec(),
                    domain_name: domain_name.to_vec(),
                    user_name: user_name.to_vec(),
                    host_name: host_name.to_vec(),
                    lan_manager_response: lan_manager_response.to_vec(),
                    ntlm_response: ntlm_response,
                    session_key: session_key.to_vec(),
                }),
            }))
        },
        _ => {
            unimplemented!()
        }
    }
}

pub fn parse_dcerpc_auth_info(input: &[u8], endianess: Endianness) -> IResult<&[u8], DCERPCAuthInfo> {
    let (rem, auth_type) = be_u8(input)?;
    let (rem, auth_level) = be_u8(rem)?;
    let (rem, auth_pad_len) = be_u8(rem)?;
    let (rem, auth_reserved) = be_u8(rem)?;
    let (rem, auth_context_id) = u32(endianess)(rem)?;
    let (rem, auth_data) = parse_dcerpc_auth_secure_service_provider(rem, endianess)?;
    Ok((rem, DCERPCAuthInfo {
        auth_type,
        auth_level,
        auth_pad_len,
        auth_reserved,
        auth_context_id,
        auth_data,
    }))
}

pub fn parse_dcerpc_fault(input: &[u8], endianess: Endianness) -> IResult<&[u8], DCERPCResponseFault> {
    let (rem, alloc_hint) = u32(endianess)(input)?;
    let (rem, context_id) = u16(endianess)(rem)?;
    let (rem, cancel_count) = be_u8(rem)?;
    let (rem, fault_flags) = be_u8(rem)?;
    let (rem, status) = u32(endianess)(rem)?;
    let (rem, reserved) = u32(endianess)(rem)?;
    Ok((rem, DCERPCResponseFault {
        alloc_hint,
        context_id,
        cancel_count,
        fault_flags,
        status,
        reserved,
    }))
}

#[cfg(test)]
mod tests {
use super::*;

   const DCERPC_BIND: &[u8] = &[
                                            0x05, 0x00,
        0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x74, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xd0, 0x16,
        0xd0, 0x16, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc4, 0xfe,
        0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb,
        0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
        0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
        0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x00, 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52,
        0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21,
        0x34, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x1c,
        0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00,
   ];
   #[test]
   fn test_parse_dcerpc_bind() {
    match parse_dcerpc_header(DCERPC_BIND) {
        Ok((rem, header)) => {
            assert_eq!(header, DCERPCHeader {
                version: 0x05,
                min_version: 0x00,
                packet_type: 0x0b,
                packet_flags: 0x03,
                data_representation: vec![0x10, 0x00, 0x00, 0x00],
                frag_length: 0x0074,
                auth_length: 0x0000,
                call_id: 0x00000002,
            });
            match parse_dcerpc_bind(rem, Endianness::Little, header.auth_length != 0) {
                Ok((rem, data)) => {
                    assert_eq!(data, DCERPCBind {
                        max_xmit_frag: 0x16d0,
                        max_recv_frag: 0x16d0,
                        assoc_group: 0x00000000,
                        num_ctx_items: 0x02,
                        ctx_items: vec![DCERPCBindCtxItem {
                            context_id: 0x0000,
                            num_trans_items: 0x01,
                            abstract_syntax: vec![DCERPCBindCtxItemAbstractSyntax {
                                interface_uuid: vec![0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a],
                                interface_ver: 0x0000,
                                interface_ver_minor: 0x0000,
                            }],
                            transfer_syntax: vec![DCERPCBindCtxItemTransferSyntax {
                                transfer_syntax_uuid: vec![0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60],
                                version: 0x00000002,
                            }],
                        }, DCERPCBindCtxItem {
                            context_id: 0x0001,
                            num_trans_items: 0x01,
                            abstract_syntax: vec![DCERPCBindCtxItemAbstractSyntax {
                                interface_uuid: vec![0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a],
                                interface_ver: 0x0000,
                                interface_ver_minor: 0x0000,
                            }],
                            transfer_syntax: vec![DCERPCBindCtxItemTransferSyntax {
                                transfer_syntax_uuid: vec![0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                                version: 0x00000001,
                            }],
                        }],
                        auth_info: None,
                    })
                },
                Err(_) => {
                    panic!("should not reach here");
                }
            }
        },
        Err(_) => {
            panic!("should not reach here")
        }
    }
   }

   const DCERPC_BIND_ACK: &[u8] = &[
                                        0x05, 0x00,
    0x0c, 0x03, 0x10, 0x00, 0x00, 0x00, 0x54, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xd0, 0x16,
    0xd0, 0x16, 0xaf, 0x50, 0x00, 0x00, 0x04, 0x00,
    0x31, 0x33, 0x35, 0x00, 0x01, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5d,
    0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
    0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
   ];
   #[test]
   fn test_parse_dcerpc_bind_ack() {
    match parse_dcerpc_header(DCERPC_BIND_ACK) {
        Ok((rem, header)) => {
            assert_eq!(header, DCERPCHeader {
                version: 0x05,
                min_version: 0x00,
                packet_type: 0x0c,
                packet_flags: 0x03,
                data_representation: vec![0x10, 0x00, 0x00, 0x00],
                frag_length: 0x0054,
                auth_length: 0x0000,
                call_id: 0x00000002,
            });
            match parse_dcerpc_bind_ack(rem, Endianness::Little, header.auth_length != 0) {
                Ok((rem, data)) => {
                    assert_eq!(data, DCERPCBindAck {
                        max_xmit_frag: 0x16d0,
                        max_recv_frag: 0x16d0,
                        assoc_group: 0x000050af,
                        scndry_addr_len: 0x0004,
                        scndry_addr: vec![0x31, 0x33, 0x35, 0x00],
                        num_results: 0x00000002,
                        ctx_items: vec![
                            DCERPCBindAckCtxItem {
                                ack_result: 0x0000,
                                bind_time_features: 0x0000,
                                transfer_syntax: vec![0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60],
                                syntax_ver: 0x00000002,
                            },
                            DCERPCBindAckCtxItem {
                                ack_result: 0x0003,
                                bind_time_features:0x0003,
                                transfer_syntax: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                                syntax_ver: 0x00000000,
                            }
                        ],
                        auth_info: None,
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

   const DCERPC_REQUEST_1: &[u8] = &[
                                        0x05, 0x00,
    0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x18, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x00
   ];
   #[test]
   fn test_parse_dcerpc_request_1() {
    match parse_dcerpc_header(DCERPC_REQUEST_1) {
        Ok((rem, header)) => {
            assert_eq!(header, DCERPCHeader {
                version: 0x05,
                min_version: 0x00,
                packet_type: 0x00,
                packet_flags: 0x03,
                data_representation: vec![0x10, 0x00, 0x00, 0x00],
                frag_length: 0x0018,
                auth_length: 0x0000,
                call_id: 0x00000002,
            });
            match parse_dcerpc_request(rem, Endianness::Little) {
                Ok((rem, data)) => {
                    assert_eq!(data, DCERPCRequest {
                        alloc_hint: 0x00000000,
                        context_id: 0x0000,
                        op_num: 0x0005,
                        complete_stub_data: None,
                    });
                },
                Err(_) => {
                    panic!("should not reach here");
                }
            }
        },
        Err(_) => {
            panic!("should not reach here")
        }
    }
   }

   const DCERPC_RESPONSE_1: &[u8] = &[
    0x05, 0x00,
    0x02, 0x03, 0x10, 0x00, 0x00, 0x00, 0x94, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x7c, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
   ];
   #[test]
   fn test_parse_dcerpc_response_1() {
    match parse_dcerpc_header(DCERPC_RESPONSE_1) {
        Ok((rem, header)) => {
            assert_eq!(header, DCERPCHeader {
                version: 0x05,
                min_version: 0x00,
                packet_type: 0x02,
                packet_flags: 0x03,
                data_representation: vec![0x10, 0x00, 0x00, 0x00],
                frag_length: 0x0094,
                auth_length: 0x0000,
                call_id: 0x00000002,
            });
            match parse_dcerpc_response(rem, Endianness::Little) {
                Ok((rem, data)) => {
                    assert_eq!(data, DCERPCResponse {
                        alloc_hint: 0x0000007c,
                        context_id: 0x0000,
                        cancel_count: 0x0000,
                        complete_stub_data: Some(vec![0x05, 0x00]),
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

   #[test]
   fn test_parse_dcerpc_auth_info() {
    let pcap = include_bytes!("pcaps/dcerpc/dcerpc_auth3.pcap");
    let payloads = &pcap[24+16+54..];
    match parse_dcerpc_header(payloads) {
        Ok((rem, header)) => {
            assert_eq!(header, DCERPCHeader {
                version: 0x05,
                min_version: 0x00,
                packet_type: 0x10,
                packet_flags: 0x03,
                data_representation: vec![0x10, 0x00, 0x00, 0x00],
                frag_length: 0x01d6,
                auth_length: 0x01ba,
                call_id: 0x00000003,
            });
            match parse_dcerpc_auth_info(&rem[4..], Endianness::Little) {
                Ok((rem, data)) => {
                    assert_eq!(data, DCERPCAuthInfo {
                        auth_type: 0x0a,
                        auth_level: 0x02,
                        auth_pad_len: 0x00,
                        auth_reserved: 0x00,
                        auth_context_id: 0x00000000,
                        auth_data: NTLMSecureServiceProvider {
                            ntlm_identifier: vec![0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50],
                            ntlm_message_type: 0x00000003,
                            negotiate_flags: 0xe2888215,
                            version: AuthVersion {
                                major_version: 0x06,
                                minor_version: 0x01,
                                build_number: 0x1db1,
                                ntlm_current_revision: 0x0f,
                            },
                            ntlm_message: NTLMSSPMessage::Auth(NTLMSSPAuth {
                                lan_manager_response_meta_info: AuthMetaInfo {
                                    length: 0x18,
                                    maxlen: 0x18,
                                    offset: 0x00000082,
                                },
                                ntlm_response_meta_info: AuthMetaInfo {
                                    length: 0x0110,
                                    maxlen: 0x0110,
                                    offset: 0x0000009a,
                                },
                                domain_name_meta_info: AuthMetaInfo {
                                    length: 0x0010,
                                    maxlen: 0x0010,
                                    offset: 0x00000058,
                                },
                                user_name_meta_info: AuthMetaInfo {
                                    length: 0x000a,
                                    maxlen: 0x000a,
                                    offset: 0x00000068,
                                },
                                host_name_meta_info: AuthMetaInfo {
                                    length: 0x0010,
                                    maxlen: 0x0010,
                                    offset: 0x00000072,
                                },
                                session_key_meta_info: AuthMetaInfo {
                                    length: 0x0010,
                                    maxlen: 0x0010,
                                    offset: 0x000001aa,
                                },
                                mic: vec![0x79, 0x86, 0x88, 0x32, 0x43, 0x3e, 0x47, 0x3d, 0xf0, 0x3f, 0x35, 0x3d, 0xec, 0xe3, 0x89, 0xdd],
                                domain_name: vec![0x6c, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00],
                                user_name: vec![0x6c, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x78, 0x00],
                                host_name: vec![0x4c, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x55, 0x00, 0x58, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00],
                                lan_manager_response: vec![
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                ],
                                ntlm_response: NTLMAuthResponse {
                                    nt_proof_str: vec![0xe7, 0xad, 0x1d, 0xf9, 0x7f, 0xc5, 0xc8, 0x13, 0x5c, 0x4e, 0x0f, 0xef, 0xa4, 0xc0, 0x91, 0x65],
                                    response_version: 0x01,
                                    hi_response_version: 0x01,
                                    time: vec![0x40, 0x74, 0x09, 0xac, 0x38, 0x71, 0xd2, 0x01],
                                    ntlm2_client_challenge: vec![0x07, 0xa5, 0x62, 0xdb, 0xd4, 0xfa, 0xc8, 0x9a],
                                    attributes: vec![
                                        AuthAttribute {
                                            item_type: 0x0002,
                                            item_length: 0x0010,
                                            item_name: vec![0x4c, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x55, 0x00, 0x58, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00],
                                        },
                                        AuthAttribute {
                                            item_type: 0x0001,
                                            item_length: 0x0010,
                                            item_name: vec![0x4c, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x55, 0x00, 0x58, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00],
                                        },
                                        AuthAttribute {
                                            item_type: 0x0004,
                                            item_length: 0x0010,
                                            item_name: vec![0x6c, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00],
                                        },
                                        AuthAttribute {
                                            item_type: 0x0003,
                                            item_length: 0x0010,
                                            item_name: vec![0x6c, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00],
                                        },
                                        AuthAttribute {
                                            item_type: 0x0007,
                                            item_length: 0x0008,
                                            item_name: vec![0x40, 0x74, 0x09, 0xac, 0x38, 0x71, 0xd2, 0x01],
                                        },
                                        AuthAttribute {
                                            item_type: 0x0006,
                                            item_length: 0x0004,
                                            item_name: vec![0x02, 0x00, 0x00, 0x00],
                                        },
                                        AuthAttribute {
                                            item_type: 0x0008,
                                            item_length: 0x0030,
                                            item_name: vec![
                                                0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
                                                0xb9, 0x49, 0x64, 0xd1, 0xf6, 0xfc, 0x5d, 0x2f,
                                                0xb7, 0xfa, 0xd1, 0x00, 0xb5, 0x77, 0x6e, 0xd6,
                                                0xc4, 0xbe, 0xfb, 0xc5, 0x80, 0xc5, 0xa3, 0x50,
                                                0x14, 0xa0, 0x15, 0x6e, 0x2b, 0x2a, 0x80, 0x47
                                            ],
                                        },
                                        AuthAttribute {
                                            item_type: 0x000a,
                                            item_length: 0x0010,
                                            item_name: vec![
                                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                                            ],
                                        },
                                        AuthAttribute {
                                            item_type: 0x0009,
                                            item_length: 0x0028,
                                            item_name: vec![
                                                0x52, 0x00, 0x50, 0x00, 0x43, 0x00, 0x53, 0x00,
                                                0x53, 0x00, 0x2f, 0x00, 0x31, 0x00, 0x39, 0x00,
                                                0x32, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x36, 0x00,
                                                0x38, 0x00, 0x2e, 0x00, 0x37, 0x00, 0x30, 0x00,
                                                0x2e, 0x00, 0x31, 0x00, 0x33, 0x00, 0x30, 0x00,
                                            ],
                                        },
                                        AuthAttribute {
                                            item_type: 0x0000,
                                            item_length: 0x0000,
                                            item_name: vec![],
                                        }
                                    ],
                                },
                                session_key: vec![0x26, 0xd2, 0x20, 0xad, 0x95, 0xdd, 0x77, 0x8f, 0x19, 0x22, 0x73, 0xf0, 0x07, 0x04, 0x7b, 0x87],
                            }),
                        },
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

   const DCERPC_RESPONSE_FAULT: &[u8] = &[
                                        0x05, 0x00,
    0x03, 0x03, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00,
    0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x20, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   ];
   #[test]
   fn test_parse_dcerpc_response_fault() {
    match parse_dcerpc_header(DCERPC_RESPONSE_FAULT) {
        Ok((rem, header)) => {
            assert_eq!(header, DCERPCHeader {
                version: 0x05,
                min_version: 0x00,
                packet_type: 0x03,
                packet_flags: 0x03,
                data_representation: vec![0x10, 0x00, 0x00, 0x00],
                frag_length: 0x0020,
                auth_length: 0x0000,
                call_id: 0x00000003,
            });
            match parse_dcerpc_fault(rem, Endianness::Little) {
                Ok((rem, data)) => {
                    assert_eq!(data, DCERPCResponseFault {
                        alloc_hint: 0x00000020,
                        context_id: 0x0001,
                        cancel_count: 0x00,
                        fault_flags: 0x00,
                        status: 0x00000005,
                        reserved: 0x00000000,
                    });
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

   #[test]
   fn test_parse_dcerpc_bind_with_auth_info() {
    let pcap = include_bytes!("pcaps/dcerpc/dcerpc_bind_with_auth.pcap");
    let payloads = &pcap[24+16+54..];
    match parse_dcerpc_header(payloads) {
        Ok((rem, header)) => {
            assert_eq!(header, DCERPCHeader {
                version: 0x05,
                min_version: 0x00,
                packet_type: 0x0b,
                packet_flags: 0x03,
                data_representation: vec![0x10, 0x00, 0x00, 0x00],
                frag_length: 0x0078,
                auth_length: 0x0028,
                call_id: 0x00000003,
            });
            match parse_dcerpc_bind(rem, Endianness::Little, header.auth_length != 0) {
                Ok((rem, data)) => {
                    assert_eq!(data, DCERPCBind {
                        max_xmit_frag: 0x16d0,
                        max_recv_frag: 0x16d0,
                        assoc_group: 0x000050af,
                        num_ctx_items: 0x00000001,
                        ctx_items: vec![
                            DCERPCBindCtxItem {
                                context_id: 0x0001,
                                num_trans_items: 0x0001,
                                abstract_syntax: vec![
                                    DCERPCBindCtxItemAbstractSyntax {
                                        interface_uuid: vec![0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
                                        interface_ver: 0x0000,
                                        interface_ver_minor: 0x0000,
                                    }
                                ],
                                transfer_syntax: vec![
                                    DCERPCBindCtxItemTransferSyntax {
                                        transfer_syntax_uuid: vec![0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60],
                                        version: 0x00000002,
                                    }
                                ],
                            }
                        ],
                        auth_info: Some(DCERPCAuthInfo {
                            auth_type: 0x0a,
                            auth_level: 0x02,
                            auth_pad_len: 0x00,
                            auth_reserved: 0x00,
                            auth_context_id: 0x00000000,
                            auth_data: NTLMSecureServiceProvider {
                                ntlm_identifier: vec![0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50],
                                ntlm_message_type: 0x00000001,
                                negotiate_flags: 0xe2088297,
                                version: AuthVersion {
                                    major_version: 0x06,
                                    minor_version: 0x01,
                                    build_number: 0x1db1,
                                    ntlm_current_revision: 0x0f,
                                },
                                ntlm_message: NTLMSSPMessage::Negotiate(NTLMSSPNegotiate {
                                    calling_workstation_domain: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                                    calling_workstation_name: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                                }),
                            },
                        }),
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

    #[test]
   fn test_parse_dcerpc_bind_ack_with_auth_info() {
    let pcap = include_bytes!("pcaps/dcerpc/dcerpc_bind_ack_with_auth.pcap");
    let payloads = &pcap[24+16+54..];
    match parse_dcerpc_header(payloads) {
        Ok((rem, header)) => {
            assert_eq!(header, DCERPCHeader {
                version: 0x05,
                min_version: 0x00,
                packet_type: 0x0c,
                packet_flags: 0x03,
                data_representation: vec![0x10, 0x00, 0x00, 0x00],
                frag_length: 0x00ec,
                auth_length: 0x00a8,
                call_id: 0x00000003,
            });
            match parse_dcerpc_bind_ack(rem, Endianness::Little, header.auth_length != 0) {
                Ok((rem, data)) => {
                    assert_eq!(data, DCERPCBindAck {
                        max_xmit_frag: 0x16d0,
                        max_recv_frag: 0x16d0,
                        assoc_group: 0x000050af,
                        scndry_addr_len: 0x0004,
                        scndry_addr: vec![0x31, 0x33, 0x35, 0x00],
                        num_results: 0x00000001,
                        ctx_items: vec![
                            DCERPCBindAckCtxItem {
                                ack_result: 0x0000,
                                bind_time_features: 0x0000,
                                transfer_syntax: vec![0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60],
                                syntax_ver: 0x00000002,
                            },
                        ],
                        auth_info: Some(DCERPCAuthInfo {
                            auth_type: 0x0a,
                            auth_level: 0x02,
                            auth_pad_len: 0x00,
                            auth_reserved: 0x00,
                            auth_context_id: 0x00000000,
                            auth_data: NTLMSecureServiceProvider {
                                ntlm_identifier: vec![0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50],
                                ntlm_message_type: 0x00000002,
                                negotiate_flags: 0xe28a8215,
                                version: AuthVersion {
                                    major_version: 0x06,
                                    minor_version: 0x01,
                                    build_number: 0x1db1,
                                    ntlm_current_revision: 0x0f,
                                },
                                ntlm_message: NTLMSSPMessage::Challenge(NTLMSSPChallenge {
                                    target_name_meta_info: AuthMetaInfo {
                                        length: 0x0010,
                                        maxlen: 0x0010,
                                        offset: 0x00000038,
                                    },
                                    target_info_meta_info: AuthMetaInfo {
                                        length: 0x0060,
                                        maxlen: 0x0060,
                                        offset: 0x00000048,
                                    },
                                    target_name: vec![0x4c, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x55, 0x00, 0x58, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00],
                                    target_info: AuthTargetInfo {
                                        attributes: vec![
                                            AuthAttribute {
                                                item_type: 0x0002,
                                                item_length: 0x0010,
                                                item_name: vec![0x4c, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x55, 0x00, 0x58, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00],
                                            },
                                            AuthAttribute {
                                                item_type: 0x0001,
                                                item_length: 0x0010,
                                                item_name: vec![0x4c, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x55, 0x00, 0x58, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00],
                                            },
                                            AuthAttribute {
                                                item_type: 0x0004,
                                                item_length: 0x0010,
                                                item_name: vec![0x6c, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00],
                                            },
                                            AuthAttribute {
                                                item_type: 0x0003,
                                                item_length: 0x0010,
                                                item_name: vec![0x6c, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x43, 0x00],
                                            },
                                            AuthAttribute {
                                                item_type: 0x0007,
                                                item_length: 0x0008,
                                                item_name: vec![0x40, 0x74, 0x09, 0xac, 0x38, 0x71, 0xd2, 0x01],
                                            },
                                            AuthAttribute {
                                                item_type: 0x0000,
                                                item_length: 0x0000,
                                                item_name: vec![],
                                            },
                                        ],
                                    },
                                    server_challenge: vec![0xc1, 0xdb, 0x10, 0x85, 0x97, 0xf8, 0x09, 0x64],
                                    reserved: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                                }),
                            },
                        }),

                    });
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
}
