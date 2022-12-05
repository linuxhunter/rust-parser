use nom7::IResult;
use nom7::bytes::complete::{take_while, tag};
use nom7::combinator::map_res;
use nom7::number::streaming::be_u8;
use nom7::sequence::tuple;
use std::str;


const READREQUEST   :u8 = 1;
const WRITEREQUEST  :u8 = 2;
const DATA          :u8 = 3;
const ACK           :u8 = 4;
const ERROR         :u8 = 5;

#[derive(Debug, PartialEq)]
pub struct TFTP_PDU {
    pub opcode: u8,
    pub filename: String,
    pub mode: String,
}

pub fn tftp_request_parse<'a>(input: &'a [u8]) -> IResult<&'a [u8], TFTP_PDU> {
    let (rem,
        (_,
        opcode,
        filename,
        _,
        mode,
        _)) = tuple((
        tag([0]),
        be_u8,
        map_res(take_while(|c| c != 0), str::from_utf8),
        tag([0]),
        map_res(take_while(|c| c != 0), str::from_utf8),
        tag([0]),
    ))(input)?;
    Ok((rem, TFTP_PDU {
        opcode,
        filename: String::from(filename),
        mode: String::from(mode),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    static READ_REQUEST: [u8; 20] = [
            0x00, 0x01, 0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00,
    ];
    /* filename not terminated */
    static READ_REQUEST_INVALID_1: [u8; 20] = [
            0x00, 0x01, 0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x6e, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00,
    ];
    /* garbage */
    static READ_REQUEST_INVALID_2: [u8; 3] = [
            0xff, 0xff, 0xff,
    ];
    static WRITE_REQUEST: [u8; 20] = [
            0x00, 0x02, 0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00,
    ];
    /* filename not terminated */
    static INVALID_OPCODE: [u8; 20] = [
            0x00, 0x06, 0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x6e, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00,
    ];
    static INVALID_MODE: [u8; 20] = [
            0x00, 0x01, 0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x63, 0x63, 0x63, 0x63, 0x63, 0x00,
    ];

    #[test]
    fn test_tftp_parse_request() {
        let (rem, request) = tftp_request_parse(&READ_REQUEST).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(request, TFTP_PDU {
            opcode: READREQUEST,
            filename: String::from("rfc1350.txt"),
            mode: String::from("octet"),
        });
    }
    #[test]
    fn test_tftp_write_request() {
        match tftp_request_parse(&WRITE_REQUEST) {
            Ok((rem, request)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(request, TFTP_PDU {
                    opcode: WRITEREQUEST,
                    filename: String::from("rfc1350.txt"),
                    mode: String::from("octet"),
                });
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    #[test]
    fn test_tftp_parse_invalid_request_1() {
        match tftp_request_parse(&READ_REQUEST_INVALID_1) {
            Ok((_rem, _request)) => {
                panic!("wrong!!!");
            },
            Err(e) => {
                println!("{:?}", e);
            }
        }
    }
    #[test]
    fn test_tftp_parse_invalid_request_2() {
        match tftp_request_parse(&READ_REQUEST_INVALID_2) {
            Ok((_, _)) => panic!("wrong!!!"),
            Err(e) => println!("{:?}", e),
        }
    }
    #[test]
    fn test_tftp_parse_invalid_opcode() {
        match tftp_request_parse(&INVALID_OPCODE) {
            Ok((_, _)) => panic!("wrong!!!"),
            Err(e) => println!("{:?}", e),
        }
    }
    #[test]
    fn test_tftp_parse_invalid_mode() {
        match tftp_request_parse(&INVALID_MODE) {
            Ok((rem, request)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(request, TFTP_PDU {
                    opcode: READREQUEST,
                    filename: String::from("rfc1350.txt"),
                    mode: String::from("ccccc"),
                })
            }
            Err(e) => println!("{:?}", e),
        }
    }
}