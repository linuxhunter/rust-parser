use nom7::{IResult, number::{complete::{be_u8, u16, u32}, Endianness}, bytes::complete::take, combinator::rest};

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
    auth_data: Vec<u8>,
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

pub fn parse_dcerpc_bind(input: &[u8], endianess: Endianness) -> IResult<&[u8], DCERPCBind> {
    let (rem, max_xmit_frag) = u16(endianess)(input)?;
    let (rem, max_recv_frag) = u16(endianess)(rem)?;
    let (rem, assoc_group) = u32(endianess)(rem)?;
    let (rem, num_ctx_items) = u32(endianess)(rem)?;
    let (rem, ctx_items) = parse_dcerpc_bind_ctx_items(rem, endianess, num_ctx_items)?;
    Ok((rem, DCERPCBind {
        max_xmit_frag,
        max_recv_frag,
        assoc_group,
        num_ctx_items,
        ctx_items,
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

pub fn parse_dcerpc_bind_ack(input: &[u8], endianess: Endianness) -> IResult<&[u8], DCERPCBindAck> {
    let (rem, max_xmit_frag) = u16(endianess)(input)?;
    let (rem, max_recv_frag) = u16(endianess)(rem)?;
    let (rem, assoc_group) = u32(endianess)(rem)?;
    let (rem, scndry_addr_len) = u16(endianess)(rem)?;
    let (rem, scndry_addr) = take(scndry_addr_len as usize)(rem)?;
    let (rem, _) = take(2usize)(rem)?;
    let (rem, num_results) = u32(endianess)(rem)?;
    let (rem, ctx_items) = parse_dcerpc_bind_ack_ctx_items(rem, endianess, num_results)?;
    Ok((rem, DCERPCBindAck {
        max_xmit_frag,
        max_recv_frag,
        assoc_group,
        scndry_addr_len,
        scndry_addr: scndry_addr.to_vec(),
        num_results,
        ctx_items,
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

pub fn parse_dcerpc_auth_info(input: &[u8], endianess: Endianness) -> IResult<&[u8], DCERPCAuthInfo> {
    let (rem, _) = take(4usize)(input)?;
    let (rem, auth_type) = be_u8(rem)?;
    let (rem, auth_level) = be_u8(rem)?;
    let (rem, auth_pad_len) = be_u8(rem)?;
    let (rem, auth_reserved) = be_u8(rem)?;
    let (rem, auth_context_id) = u32(endianess)(rem)?;
    let (rem, auth_data) = rest(rem)?;
    Ok((rem, DCERPCAuthInfo {
        auth_type,
        auth_level,
        auth_pad_len,
        auth_reserved,
        auth_context_id,
        auth_data: auth_data.to_vec(),
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
            match parse_dcerpc_bind(rem, Endianness::Little) {
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
            match parse_dcerpc_bind_ack(rem, Endianness::Little) {
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

   const DCERPC_AUTH_INFO: &[u8] = &[
                                        0x05, 0x00,
    0x10, 0x03, 0x10, 0x00, 0x00, 0x00, 0xd6, 0x01,
    0xba, 0x01, 0x03, 0x00, 0x00, 0x00, 0xd0, 0x16,
    0xd0, 0x16, 0x0a, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53,
   ];
   #[test]
   fn test_parse_dcerpc_auth_info() {
    match parse_dcerpc_header(DCERPC_AUTH_INFO) {
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
            match parse_dcerpc_auth_info(rem, Endianness::Little) {
                Ok((rem, data)) => {
                    assert_eq!(data, DCERPCAuthInfo {
                        auth_type: 0x0a,
                        auth_level: 0x02,
                        auth_pad_len: 0x00,
                        auth_reserved: 0x00,
                        auth_context_id: 0x00000000,
                        auth_data: vec![0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53],
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
}