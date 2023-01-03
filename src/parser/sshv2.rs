use nom7::{IResult, bytes::complete::{is_not, tag, take}, character::streaming::char, combinator::{complete, rest}, branch::alt, number::complete::{be_u32, be_u8}, multi::length_data};

#[derive(Debug, PartialEq)]
pub struct SSHBanner {
    version: Vec<u8>,
    software_version: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct SSHKeyExchangeAlgorithm {
    cookie: Vec<u8>,
    kex_algorithms_string: Vec<u8>,
    server_host_key_algorithms_string: Vec<u8>,
    encryption_algorithms_client_to_server_string: Vec<u8>,
    encryption_algorithms_server_to_server_string: Vec<u8>,
    mac_algorithms_client_to_server_string: Vec<u8>,
    mac_algorithms_server_to_server_string: Vec<u8>,
    compression_algorithms_client_to_server_string: Vec<u8>,
    compression_algorithms_server_to_server_string: Vec<u8>,
    language_client_to_server_string: Vec<u8>,
    language_server_to_server_string: Vec<u8>,
    first_kex_packet_follows: u8,
    reserved: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct MultiPrecisionValue {
    data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct KexHostKeyOrSignature {
    host_length: u32,
    host_type: Vec<u8>,
    multi_precision_values: Vec<MultiPrecisionValue>,
}

#[derive(Debug, PartialEq)]
pub struct SSHKeyExchangeReply {
    kex_host_key: KexHostKeyOrSignature,
    dh_server_f: Vec<u8>,
    kex_host_signature: KexHostKeyOrSignature,
}

#[derive(Debug, PartialEq)]
pub enum SSHKeyExchangeMessageData {
    ALGORITHM(SSHKeyExchangeAlgorithm),
    KEY_EXCHANGE_REPLY(SSHKeyExchangeReply),
}

#[derive(Debug, PartialEq)]
pub struct SSHKeyExchange {
    message_code: u8,
    algorithm: SSHKeyExchangeMessageData,
}

#[derive(Debug, PartialEq)]
pub struct SSHVersion2 {
    packet_length: u32,
    padding_length: u8,
    key_exchange: SSHKeyExchange,
    padding_string: Vec<u8>,
}

pub fn is_not_ending(b: u8) -> bool {
    if b == 0x0a || b == 0x0d {
        false
    } else {
        true
    }
}

pub fn parse_ssh_banner(input: &[u8]) -> IResult<&[u8], SSHBanner> {
    let (rem, _) = tag("SSH-")(input)?;
    let (rem, version) = is_not("-")(rem)?;
    let (rem, _) = char('-')(rem)?;
    let (rem, software_version) = alt((complete(is_not("\r\n")), rest))(rem)?;
    Ok((rem, SSHBanner {
        version: version.to_vec(),
        software_version: software_version.to_vec(),
    }))
}

pub fn parse_ssh_v2_key_exchange_algorithm(input: &[u8]) -> IResult<&[u8], SSHKeyExchangeAlgorithm> {
    let (rem, cookie) = take(16usize)(input)?;
    let (rem, kex_algorithms_string) = length_data(be_u32)(rem)?;
    let (rem, server_host_key_algorithms_string) = length_data(be_u32)(rem)?;
    let (rem, encryption_algorithms_client_to_server_string) = length_data(be_u32)(rem)?;
    let (rem, encryption_algorithms_server_to_client_string) = length_data(be_u32)(rem)?;
    let (rem, mac_algorithms_client_to_server_string) = length_data(be_u32)(rem)?;
    let (rem, mac_algorithms_server_to_client_string) = length_data(be_u32)(rem)?;
    let (rem, compress_algorithms_client_to_server_string) = length_data(be_u32)(rem)?;
    let (rem, compress_algorithms_server_to_client_string) = length_data(be_u32)(rem)?;
    let (rem, language_client_to_server_string) = length_data(be_u32)(rem)?;
    let (rem, language_server_to_client_string) = length_data(be_u32)(rem)?;
    let (rem, first_kex_packet_follows) = be_u8(rem)?;
    let (rem, reserved) = take(4usize)(rem)?;
    Ok((rem, SSHKeyExchangeAlgorithm {
        cookie: cookie.to_vec(),
        kex_algorithms_string: kex_algorithms_string.to_vec(),
        server_host_key_algorithms_string: server_host_key_algorithms_string.to_vec(),
        encryption_algorithms_client_to_server_string: encryption_algorithms_client_to_server_string.to_vec(),
        encryption_algorithms_server_to_server_string: encryption_algorithms_server_to_client_string.to_vec(),
        mac_algorithms_client_to_server_string: mac_algorithms_client_to_server_string.to_vec(),
        mac_algorithms_server_to_server_string: mac_algorithms_server_to_client_string.to_vec(),
        compression_algorithms_client_to_server_string: compress_algorithms_client_to_server_string.to_vec(),
        compression_algorithms_server_to_server_string: compress_algorithms_server_to_client_string.to_vec(),
        language_client_to_server_string: language_client_to_server_string.to_vec(),
        language_server_to_server_string: language_server_to_client_string.to_vec(),
        first_kex_packet_follows,
        reserved: reserved.to_vec(),
    }))
}

pub fn parse_ssh_v2_kex_host_multi_precisions(input: &[u8], multi_precision_length: u32) -> IResult<&[u8], Vec<MultiPrecisionValue>> {
    let mut rem = input;
    let mut rem_length = multi_precision_length;
    let mut multi_precision_value = Vec::new();
    loop {
        if rem_length == 0 {
            break;
        }
        let (tmp_rem, item_length) = be_u32(rem)?;
        let (tmp_rem, item_value) = take(item_length as usize)(tmp_rem)?;
        multi_precision_value.push(MultiPrecisionValue {
            data: item_value.to_vec(),
        });
        rem_length -= (4 + item_length);
        rem = tmp_rem;
    }
    Ok((rem, multi_precision_value))
}

pub fn parse_ssh_v2_kex_host_key_or_signature(input: &[u8]) -> IResult<&[u8], KexHostKeyOrSignature> {
    let (rem, host_length) = be_u32(input)?;
    let (rem, host_type_length) = be_u32(rem)?;
    let (rem, host_type) = take(host_type_length as usize)(rem)?;
    let (rem, multi_precision_values) = parse_ssh_v2_kex_host_multi_precisions(rem, (host_length - 4 - host_type_length) as u32)?;
    Ok((rem, KexHostKeyOrSignature {
        host_length,
        host_type: host_type.to_vec(),
        multi_precision_values,
    }))
}

pub fn parse_ssh_v2_key_exchange_dh_key_exchange_reply(input: &[u8]) -> IResult<&[u8], SSHKeyExchangeReply> {
    let (rem, kex_host_key) = parse_ssh_v2_kex_host_key_or_signature(input)?;
    let (rem, dh_server_f) = length_data(be_u32)(rem)?;
    let (rem, kex_host_signature) = parse_ssh_v2_kex_host_key_or_signature(rem)?;
    Ok((rem, SSHKeyExchangeReply {
        kex_host_key,
        dh_server_f: dh_server_f.to_vec(),
        kex_host_signature,
    }))
}

pub fn parse_ssh_v2_key_exchange(input: &[u8]) -> IResult<&[u8], SSHKeyExchange> {
    let (rem, message_code) = be_u8(input)?;
    match message_code {
        0x14 => {
            let (rem, algorithm) = parse_ssh_v2_key_exchange_algorithm(rem)?;
            Ok((rem, SSHKeyExchange {
                message_code,
                algorithm: SSHKeyExchangeMessageData::ALGORITHM(algorithm),
            }))
        },
        0x1f => {
            let (rem, algorithm) = parse_ssh_v2_key_exchange_dh_key_exchange_reply(rem)?;
            Ok((rem, SSHKeyExchange {
                message_code,
                algorithm: SSHKeyExchangeMessageData::KEY_EXCHANGE_REPLY(algorithm),
            }))
        },
        _ => {
            unimplemented!();
        }
    }
   
}

pub fn parse_ssh_version_2(input: &[u8]) -> IResult<&[u8], SSHVersion2> {
    let (rem, packet_length) = be_u32(input)?;
    let (rem, padding_length) = be_u8(rem)?;
    let (rem, key_exchange) = parse_ssh_v2_key_exchange(rem)?;
    let (rem, padding_string) = take(padding_length as usize)(rem)?;
    Ok((rem, SSHVersion2 {
        packet_length,
        padding_length,
        key_exchange,
        padding_string: padding_string.to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_banner() {
        let pcap = include_bytes!("pcaps/ssh/ssh-server-init.pcap");
        let payload = &pcap[24+16+54..];
        match parse_ssh_banner(payload) {
            Ok((_rem, header)) => {
                assert_eq!(header, SSHBanner {
                    version: vec![0x32, 0x2e, 0x30],
                    software_version: vec![0x43, 0x69, 0x73, 0x63, 0x6f, 0x2d, 0x31, 0x2e, 0x32, 0x35],
                });
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_ssh_banner_2() {
        let pcap = include_bytes!("pcaps/ssh/ssh-client-init.pcap");
        let payload = &pcap[24+16+54..];
        match parse_ssh_banner(payload) {
            Ok((_rem, header)) => {
                assert_eq!(header, SSHBanner {
                    version: vec![0x31, 0x2e, 0x39, 0x39],
                    software_version: vec![0x43, 0x69, 0x73, 0x63, 0x6f, 0x2d, 0x31, 0x2e, 0x32, 0x35],
                });
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    #[test]
    fn test_parse_ssh_version_v2_key_exchange_algorithm() {
        let pcap = include_bytes!("pcaps/ssh/ssh-server-key-exchange-init.pcap");
        let payload = &pcap[24+16+54..];
        match parse_ssh_version_2(payload) {
            Ok((_rem, data)) => {
                assert_eq!(data.packet_length, 0x00000114);
                assert_eq!(data.padding_length, 0x04);
                assert_eq!(data.key_exchange.message_code, 0x14);
                match data.key_exchange.algorithm {
                    SSHKeyExchangeMessageData::ALGORITHM(algorithm) => {
                        assert_eq!(algorithm.cookie, vec![0xeb, 0x3b, 0x3b, 0x7d, 0x54, 0x14, 0x46, 0x5b, 0x41, 0xc0, 0xb8, 0xc4, 0xfd, 0x13, 0xaa, 0x25]);
                        assert_eq!(String::from_utf8(algorithm.kex_algorithms_string).unwrap(), String::from("diffie-hellman-group1-sha1"));
                        assert_eq!(String::from_utf8(algorithm.server_host_key_algorithms_string).unwrap(), String::from("ssh-rsa"));
                        assert_eq!(String::from_utf8(algorithm.encryption_algorithms_client_to_server_string).unwrap(), String::from("aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc"));
                        assert_eq!(String::from_utf8(algorithm.encryption_algorithms_server_to_server_string).unwrap(), String::from("aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc"));
                        assert_eq!(String::from_utf8(algorithm.mac_algorithms_client_to_server_string).unwrap(), String::from("hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96"));
                        assert_eq!(String::from_utf8(algorithm.mac_algorithms_server_to_server_string).unwrap(), String::from("hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96"));
                        assert_eq!(String::from_utf8(algorithm.language_client_to_server_string).unwrap(), String::from(""));
                        assert_eq!(String::from_utf8(algorithm.language_server_to_server_string).unwrap(), String::from(""));
                        assert_eq!(algorithm.first_kex_packet_follows, 0x00);
                        assert_eq!(algorithm.reserved, vec![0x00, 0x00, 0x00, 0x00]);
                    },
                    _ => {
                        unimplemented!();
                    }
                }
                assert_eq!(data.padding_string, vec![0x00, 0x00, 0x00, 0x00]);
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }

    #[test]
    fn test_parse_ssh_verion_v2_dh_key_exchange_reply() {
        let pcap = include_bytes!("pcaps/ssh/ssh-server-dh-key-exchange-reply.pcap");
        let payload = &pcap[24+16+54..];
        match parse_ssh_version_2(payload) {
            Ok((_rem, data)) => {
                assert_eq!(data.packet_length, 0x0000013c);
                assert_eq!(data.padding_length, 0x08);
                assert_eq!(data.key_exchange.message_code, 0x1f);
                match data.key_exchange.algorithm {
                    SSHKeyExchangeMessageData::KEY_EXCHANGE_REPLY(reply) => {
                        assert_eq!(reply.kex_host_key.host_length, 0x00000057);
                        assert_eq!(String::from_utf8(reply.kex_host_key.host_type).unwrap(), String::from("ssh-rsa"));
                        assert_eq!(reply.kex_host_key.multi_precision_values[0].data, vec![0x01, 0x00, 0x01]);
                        assert_eq!(reply.kex_host_key.multi_precision_values[1].data.len(), 65);
                        assert_eq!(reply.dh_server_f.len(), 128);
                        assert_eq!(reply.kex_host_signature.host_length, 0x0000004f);
                        assert_eq!(String::from_utf8(reply.kex_host_signature.host_type).unwrap(), String::from("ssh-rsa"));
                        assert_eq!(reply.kex_host_signature.multi_precision_values[0].data.len(), 64);
                    },
                    _ => {
                        panic!("should not reach here");
                    }
                }
                assert_eq!(data.padding_string, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            },
            Err(_) => {
                panic!("should not reach here");
            }
        }
    }
}
