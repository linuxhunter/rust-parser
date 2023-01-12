use std::net::Ipv4Addr;

use nom7::{IResult, sequence::tuple, bytes::complete::take, number::complete::be_u32, combinator::map_res};

const TRDP_PROTOCOL_VERSION_LENGTH: usize = 2;
const TRDP_MSG_TYPE_LENGTH: usize = 2;

#[derive(Debug, PartialEq)]
pub struct TrdpHeader {
    sequence_counter: u32,
    protocol_version: String,
    msg_type: String,
    com_id: u32,
    etb_topo_cnt: u32,
    op_trn_topo_cnt: u32,
    dataset_length: u32,
    reserved: u32,
    reply_com_id: u32,
    reply_ip_address: Ipv4Addr,
    header_fcs: u32,
}

pub fn parse_trdp_protocol_version(input: &[u8]) -> Result<String, String> {
    Ok(format!("{}.{}", input[0], input[1]))
}

pub fn parse_trdp_header(input: &[u8]) -> IResult<&[u8], TrdpHeader> {
    let (rem, (
        sequence_counter,
        protocol_version,
        msg_type,
        com_id,
        etb_topo_cnt,
        op_trn_topo_cnt,
        dataset_length,
        reserved,
        reply_com_id,
        reply_ip_address,
        header_fcs,
    )) = tuple((
        be_u32,
        map_res(take(TRDP_PROTOCOL_VERSION_LENGTH),  parse_trdp_protocol_version),
        map_res(take(TRDP_MSG_TYPE_LENGTH), |v: &[u8]| String::from_utf8(v.to_vec())),
        be_u32,
        be_u32,
        be_u32,
        be_u32,
        be_u32,
        be_u32,
        be_u32,
        be_u32,
    ))(input)?;
    let reply_ip_address = Ipv4Addr::from(reply_ip_address);
    Ok((rem, TrdpHeader {
        sequence_counter,
        protocol_version,
        msg_type,
        com_id,
        etb_topo_cnt,
        op_trn_topo_cnt,
        dataset_length,
        reserved,
        reply_com_id,
        reply_ip_address,
        header_fcs,
    }))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_parse_trdp_pd_data() {
        let pcap = include_bytes!("pcaps/trdp/trdp_pd_data.pcap");
        let payload = &pcap[24+16+42..];
        match parse_trdp_header(payload) {
            Ok((rem, trdp_header)) => {
                assert_eq!(trdp_header, TrdpHeader {
                    sequence_counter: 81,
                    protocol_version: String::from("1.0"),
                    msg_type: String::from("Pd"),
                    com_id: 20149,
                    etb_topo_cnt: 0,
                    op_trn_topo_cnt: 0,
                    dataset_length: 1432,
                    reserved: 0,
                    reply_com_id: 0,
                    reply_ip_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
                    header_fcs: 0x65874c45,
                });
                assert_eq!(rem.len(), trdp_header.dataset_length as usize);
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_trdp_pd_request() {
        let pcap = include_bytes!("pcaps/trdp/trdp_pd_request.pcap");
        let payload = &pcap[24+16+42..];
        match parse_trdp_header(payload) {
            Ok((rem, trdp_header)) => {
                assert_eq!(trdp_header, TrdpHeader {
                    sequence_counter: 9,
                    protocol_version: String::from("1.0"),
                    msg_type: String::from("Pr"),
                    com_id: 30106,
                    etb_topo_cnt: 0,
                    op_trn_topo_cnt: 0,
                    dataset_length: 256,
                    reserved: 0,
                    reply_com_id: 40106,
                    reply_ip_address: Ipv4Addr::from_str("224.1.1.1").unwrap(),
                    header_fcs: 0xfaf4d958,
                });
                assert_eq!(rem.len(), trdp_header.dataset_length as usize);
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_trdp_pd_reply() {
        let pcap = include_bytes!("pcaps/trdp/trdp_pd_reply.pcap");
        let payload = &pcap[24+16+42..];
        match parse_trdp_header(payload) {
            Ok((rem, trdp_header)) => {
                assert_eq!(trdp_header, TrdpHeader {
                    sequence_counter: 9,
                    protocol_version: String::from("1.0"),
                    msg_type: String::from("Pp"),
                    com_id: 40006,
                    etb_topo_cnt: 0,
                    op_trn_topo_cnt: 0,
                    dataset_length: 1432,
                    reserved: 0,
                    reply_com_id: 0,
                    reply_ip_address: Ipv4Addr::from_str("0.0.0.0").unwrap(),
                    header_fcs: 0x822de12,
                });
                assert_eq!(rem.len(), trdp_header.dataset_length as usize);
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }
}