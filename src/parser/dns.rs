use nom7::combinator::{rest, complete};
use nom7::error::ErrorKind;
use nom7::multi::{count, many_m_n};
use nom7::{IResult, multi::length_data, error_position, Err};
use nom7::number::streaming::{be_u8, be_u16, be_u32};

pub const DNS_RECORD_TYPE_A     :u16 = 1;
pub const DNS_RECORD_TYPE_CNAME :u16 = 5;
pub const DNS_RECORD_TYPE_SOA   :u16 = 6;
pub const DNS_RECORD_TYPE_AAAA  :u16 = 28;

#[derive(Debug, PartialEq)]
pub struct DNSHeader {
    pub tx_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answer_rr: u16,
    pub authority_rr: u16,
    pub additional_rr: u16,
}

#[derive(Debug, PartialEq)]
pub struct DNSQueryEntry {
    pub name: Vec<u8>,
    pub rrtype: u16,
    pub rrclass: u16,
}

#[derive(Debug, PartialEq)]
pub enum DNSRData {
    A(Vec<u8>),
    AAAA(Vec<u8>),
    CNAME(Vec<u8>),
    SOA(DNSRDataSOA),
    Unknown(Vec<u8>),
}

#[derive(Debug, PartialEq)]
pub struct DNSRDataSOA {
    pub mname: Vec<u8>,
    pub rname: Vec<u8>,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, PartialEq)]
pub struct DNSAnswerEntry {
    pub name: Vec<u8>,
    pub rrtype: u16,
    pub rrclass: u16,
    pub ttl: u32,
    pub data: DNSRData,
}

#[derive(Debug, PartialEq)]
pub struct DNSRequest {
    pub header: DNSHeader,
    pub queries: Vec<DNSQueryEntry>,
}

pub struct DNSResponse {
    pub header: DNSHeader,
    pub queries: Vec<DNSQueryEntry>,
    pub answers: Vec<DNSAnswerEntry>,
    pub authorities: Vec<DNSAnswerEntry>,
}

pub fn dns_parse_name<'a>(start: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], Vec<u8>> {
    let mut pos = start;
    let mut pivot = start;
    let mut name: Vec<u8> = Vec::with_capacity(32);

    loop {
        if pos.is_empty() {
            break;
        }

        if pos[0] == 0x00 {
            pos = &pos[1..];
            break;
        }
        let len = pos[0];
        if len & 0b1100_0000 == 0 {
            let (rem, label) = length_data(be_u8)(pos)?;
            if !name.is_empty() {
                name.push(b'.');
            }
            name.extend(label);
            pos = rem;
        } else if len & 0b1100_0000 == 0b1100_0000 {
            let (rem, leader) = be_u16(pos)?;
            let offset = usize::from(leader) & 0x3fff;
            if offset > message.len() {
                return Err(Err::Error(error_position!(pos, ErrorKind::OctDigit)));
            }
            pos = &message[offset..];
            if pivot == start {
                pivot = rem;
            }
        } else {
            return Err(Err::Error(error_position!(pos, ErrorKind::OctDigit)));
        }
    }
    if pivot.len() != start.len() {
        return Ok((pivot, name));
    }
    Ok((pos, name))
}

pub fn dns_parse_header(start: &[u8]) -> IResult<&[u8], DNSHeader> {
    let (rem, tx_id) = be_u16(start)?;
    let (rem, flags) = be_u16(rem)?;
    let (rem, questions) = be_u16(rem)?;
    let (rem, answer_rr) = be_u16(rem)?;
    let (rem, authority_rr) = be_u16(rem)?;
    let (rem, additional_rr) = be_u16(rem)?;
    Ok((rem,
        DNSHeader {
            tx_id,
            flags,
            questions,
            answer_rr,
            authority_rr,
            additional_rr,
        }))
}

pub fn dns_parse_query<'a>(start: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], DNSQueryEntry> {
    let (rem, name) = dns_parse_name(start, message)?;
    let (rem, rrtype) = be_u16(rem)?;
    let (rem, rrclass) = be_u16(rem)?;
    Ok((rem,
        DNSQueryEntry {
            name,
            rrtype,
            rrclass,
        }))
}

pub fn dns_parse_request(input: &[u8]) -> IResult<&[u8], DNSRequest> {
    let rem = input;
    let (rem, header) = dns_parse_header(rem)?;
    let (rem, queries) = count(|i| dns_parse_query(i, input), header.questions as usize)(rem)?;
    Ok((rem,
        DNSRequest {
            header,
            queries,
        }))
}

pub fn subparser<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], (Vec<u8>, u16, u16, u32, &'a [u8])> {
    let (input, name) = dns_parse_name(input, message)?;
    let (input, rrtype) = be_u16(input)?;
    let (input, rrclass) = be_u16(input)?;
    let (input, ttl) = be_u32(input)?;
    let (input, data) = length_data(be_u16)(input)?;
    Ok((input,
        (name, rrtype, rrclass, ttl, data)))
}

pub fn dns_parse_rdata_a<'a>(input: &'a [u8]) -> IResult<&'a [u8], DNSRData> {
    rest(input).map(|(input, data)| (input, DNSRData::A(data.to_vec())))
}

pub fn dns_parse_rdata_aaaa<'a>(input: &'a [u8]) -> IResult<&'a [u8], DNSRData> {
    rest(input).map(|(input, data)| (input, DNSRData::AAAA(data.to_vec())))
}

pub fn dns_parse_rdata_cname<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], DNSRData> {
    dns_parse_name(input, message).map(|(input, message)| (input, DNSRData::CNAME(message.to_vec())))
}

pub fn dns_parse_rdata_soa<'a>(input: &'a [u8], message: &'a [u8]) -> IResult<&'a [u8], DNSRData> {
    let (rem, mname) = dns_parse_name(input, message)?;
    let (rem, rname) = dns_parse_name(rem, message)?;
    let (rem, serial) = be_u32(rem)?;
    let (rem, refresh) = be_u32(rem)?;
    let (rem, retry) = be_u32(rem)?;
    let (rem, expire) = be_u32(rem)?;
    let (rem, minimum) = be_u32(rem)?;
    Ok((rem, DNSRData::SOA(DNSRDataSOA {
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    })))
}

pub fn dns_parse_rdata_unknown<'a>(input: &'a [u8]) -> IResult<&'a [u8], DNSRData> {
    rest(input).map(|(input, data)| (input, DNSRData::Unknown(data.to_vec())))
}

pub fn dns_parse_rdata<'a>(input: &'a [u8], message: &'a [u8], rrtype: u16) -> IResult<&'a [u8], DNSRData> {
    match rrtype {
        DNS_RECORD_TYPE_A => dns_parse_rdata_a(input),
        DNS_RECORD_TYPE_CNAME => dns_parse_rdata_cname(input, message),
        DNS_RECORD_TYPE_SOA => dns_parse_rdata_soa(input, message),
        DNS_RECORD_TYPE_AAAA => dns_parse_rdata_aaaa(input),
        _ => dns_parse_rdata_unknown(input),
    }
}

pub fn dns_parse_answer<'a>(input: &'a [u8], message: &'a [u8], count: usize) -> IResult<&'a [u8], Vec<DNSAnswerEntry>> {
    let mut answers = Vec::new();
    let mut rem = input;

    for _ in 0..count {
        match subparser(rem, message) {
            Ok((_rem, val)) => {
                let name = val.0;
                let rrtype = val.1;
                let rrclass = val.2;
                let ttl = val.3;
                let data = val.4;
                let n = 1;
                let result = many_m_n(1, n, complete(|b| dns_parse_rdata(b, message, rrtype)))(data);
                match result {
                    Ok((_, rdatas)) => {
                        for rdata in rdatas {
                            answers.push(DNSAnswerEntry {
                                name: name.clone(),
                                rrtype,
                                rrclass,
                                ttl,
                                data: rdata,
                            });
                        }
                    },
                    Err(e) => {
                        return Err(e);
                    }
                }
                rem = _rem;
            },
            Err(e) => {
                return Err(e);
            }
        }
    }
    Ok((rem, answers))
}

pub fn dns_parse_response(input: &[u8]) -> IResult<&[u8], DNSResponse> {
    let rem = input;
    let (rem, header) = dns_parse_header(rem)?;
    let (rem, queries) = count(|i| dns_parse_query(i, input), header.questions as usize)(rem)?;
    let (rem, answers) = dns_parse_answer(rem, input, header.answer_rr as usize)?;
    let (rem, authorities) = dns_parse_answer(rem, input, header.authority_rr as usize)?;
    Ok((rem, DNSResponse {
        header,
        queries,
        answers,
        authorities,
    }))
}

fn main() {

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_parse_name1() {
        let buf: &[u8] = &[
                                                0x09, 0x63, /* .......c */
            0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x63, 0x66, /* lient-cf */
            0x07, 0x64, 0x72, 0x6f, 0x70, 0x62, 0x6f, 0x78, /* .dropbox */
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, /* .com.... */
        ];
        let expected_remained: &[u8] = &[0x00, 0x01, 0x00];
        let (rem, name) = dns_parse_name(buf, buf).unwrap();
        assert_eq!(name, "client-cf.dropbox.com".as_bytes());
        assert_eq!(rem, expected_remained);
    }
    #[test]
    fn test_dns_parse_name2() {
        let buf: &[u8] = &[
            0xd8, 0xcb, 0x8a, 0xed, 0xa1, 0x46, 0x00, 0x15 /* 0   - .....F.. */,
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00 /* 8   - ......E. */,
            0x00, 0x7b, 0x71, 0x6e, 0x00, 0x00, 0x39, 0x11 /* 16  - .{qn..9. */,
            0xf4, 0xd9, 0x08, 0x08, 0x08, 0x08, 0x0a, 0x10 /* 24  - ........ */,
            0x01, 0x0b, 0x00, 0x35, 0xe1, 0x8e, 0x00, 0x67 /* 32  - ...5...g */,
            0x60, 0x00, 0xef, 0x08, 0x81, 0x80, 0x00, 0x01 /* 40  - `....... */,
            0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77 /* 48  - .......w */,
            0x77, 0x77, 0x0c, 0x73, 0x75, 0x72, 0x69, 0x63 /* 56  - ww.suric */,
            0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, 0x73, 0x03 /* 64  - ata-ids. */,
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01 /* 72  - org..... */,
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00 /* 80  - ........ */,
            0x0e, 0x0f, 0x00, 0x02, 0xc0, 0x10, 0xc0, 0x10 /* 88  - ........ */,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2b /* 96  - .......+ */,
            0x00, 0x04, 0xc0, 0x00, 0x4e, 0x19, 0xc0, 0x10 /* 104 - ....N... */,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2b /* 112 - .......+ */,
            0x00, 0x04, 0xc0, 0x00, 0x4e, 0x18, 0x00, 0x00 /* 120 - ....N... */,
            0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /* 128 - )....... */,
            0x00,                                          /* 136 - . */
        ];
        let message = &buf[42..];

        let start1 = &buf[54..];
        let (_rem, name) = dns_parse_name(start1, message).unwrap();
        assert_eq!(name, "www.suricata-ids.org".as_bytes());

        let start2 = &buf[80..];
        let (_rem, name) = dns_parse_name(start2, message).unwrap();
        assert_eq!(name, "www.suricata-ids.org".as_bytes());

        let start3 = &buf[94..];
        let (_rem, name) = dns_parse_name(start3, message).unwrap();
        assert_eq!(name, "suricata-ids.org".as_bytes());

        let start4 = &buf[110..];
        let (_rem, name) = dns_parse_name(start4, message).unwrap();
        assert_eq!(name, "suricata-ids.org".as_bytes());
    }
    #[test]
    fn test_dns_parse_name3() {
        let buf: &[u8] = &[
            0xd8, 0xcb, 0x8a, 0xed, 0xa1, 0x46, 0x00, 0x15 /* 0:   .....F.. */,
            0x17, 0x0d, 0x06, 0xf7, 0x08, 0x00, 0x45, 0x00 /* 8:   ......E. */,
            0x00, 0x66, 0x5e, 0x20, 0x40, 0x00, 0x40, 0x11 /* 16:  .f^ @.@. */,
            0xc6, 0x3b, 0x0a, 0x10, 0x01, 0x01, 0x0a, 0x10 /* 24:  .;...... */,
            0x01, 0x0b, 0x00, 0x35, 0xc2, 0x21, 0x00, 0x52 /* 32:  ...5.!.R */,
            0x35, 0xc5, 0x0d, 0x4f, 0x81, 0x80, 0x00, 0x01 /* 40:  5..O.... */,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x62 /* 48:  .......b */,
            0x6c, 0x6f, 0x63, 0x6b, 0x07, 0x64, 0x72, 0x6f /* 56:  lock.dro */,
            0x70, 0x62, 0x6f, 0x78, 0x03, 0x63, 0x6f, 0x6d /* 64:  pbox.com */,
            0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00 /* 72:  ........ */,
            0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00 /* 80:  ........ */,
            0x0b, 0x05, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x02 /* 88:  ..block. */,
            0x67, 0x31, 0xc0, 0x12, 0xc0, 0x2f, 0x00, 0x01 /* 96:  g1.../.. */,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04 /* 104: ........ */,
            0x2d, 0x3a, 0x46, 0x21                         /* 112: -:F!     */
        ];
        let message = &buf[42..];
        let start = &buf[100..];
        let (_rem, name) = dns_parse_name(start, message).unwrap();
        assert_eq!(name, "block.g1.dropbox.com".as_bytes());
    }
    #[test]
    fn test_dns_parse_header() {
        let pkt: &[u8] = &[
                        0x8d, 0x32, 0x01, 0x20, 0x00, 0x01, /* ...2. .. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, /* .......w */
            0x77, 0x77, 0x0c, 0x73, 0x75, 0x72, 0x69, 0x63, /* ww.suric */
            0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, 0x73, 0x03, /* ata-ids. */
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01, /* org..... */
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, /* ..)..... */
            0x00, 0x00, 0x00                                /* ... */
        ];
        let (_rem, dns_header) = dns_parse_header(pkt).unwrap();
        assert_eq!(dns_header, DNSHeader {
                    tx_id: 0x8d32,
                    flags: 0x0120,
                    questions: 1,
                    answer_rr: 0,
                    authority_rr: 0,
                    additional_rr: 1,
                    });
    }
    #[test]
    fn test_dns_parse_query() {
        let pkt: &[u8] = &[
                        0x8d, 0x32, 0x01, 0x20, 0x00, 0x01, /* ...2. .. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, /* .......w */
            0x77, 0x77, 0x0c, 0x73, 0x75, 0x72, 0x69, 0x63, /* ww.suric */
            0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, 0x73, 0x03, /* ata-ids. */
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01, /* org..... */
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, /* ..)..... */
            0x00, 0x00, 0x00                                /* ... */
        ];
        let (rem, dns_header) = dns_parse_header(pkt).unwrap();
        let (_rem, dns_query_entry) = dns_parse_query(rem, pkt).unwrap();
        assert_eq!(dns_header, DNSHeader {
                    tx_id: 0x8d32,
                    flags: 0x0120,
                    questions: 1,
                    answer_rr: 0,
                    authority_rr: 0,
                    additional_rr: 1,
                    });
        assert_eq!(dns_query_entry, DNSQueryEntry {
            name: "www.suricata-ids.org".as_bytes().to_vec(),
            rrtype: 1,
            rrclass: 1,
        });
    }
    #[test]
    fn test_dns_parse_request() {
        let pkt: &[u8] = &[
                        0x8d, 0x32, 0x01, 0x20, 0x00, 0x01, /* ...2. .. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, /* .......w */
            0x77, 0x77, 0x0c, 0x73, 0x75, 0x72, 0x69, 0x63, /* ww.suric */
            0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, 0x73, 0x03, /* ata-ids. */
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01, /* org..... */
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, /* ..)..... */
            0x00, 0x00, 0x00                                /* ... */
        ];
        let (_rem, request) = dns_parse_request(pkt).unwrap();
         assert_eq!(request.header, DNSHeader {
                    tx_id: 0x8d32,
                    flags: 0x0120,
                    questions: 1,
                    answer_rr: 0,
                    authority_rr: 0,
                    additional_rr: 1,
                    });
        assert_eq!(request.queries.iter().next(), Some(&DNSQueryEntry {
            name: "www.suricata-ids.org".as_bytes().to_vec(),
            rrtype: 1,
            rrclass: 1,
        }));

    }
    #[test]
    fn test_dns_parse_request2() {
        let pkt: &[u8] = &[
                        0x00, 0x03, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f,
            0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
        ];
        let (_rem, request) = dns_parse_request(pkt).unwrap();
        assert_eq!(request.header, DNSHeader {
            tx_id: 0x0003,
            flags: 0x0100,
            questions: 1,
            answer_rr: 0,
            authority_rr: 0,
            additional_rr: 0,
        });
        assert_eq!(request.queries.iter().next(), Some(&DNSQueryEntry {
            name: "google.com".as_bytes().to_vec(),
            rrtype: 1,
            rrclass: 1,
        }));
    }
    #[test]
    fn test_dns_parse_response() {
        let pkt: &[u8] = &[
                        0x8d, 0x32, 0x81, 0xa0, 0x00, 0x01, /* ...2.... */
            0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, /* .......w */
            0x77, 0x77, 0x0c, 0x73, 0x75, 0x72, 0x69, 0x63, /* ww.suric */
            0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, 0x73, 0x03, /* ata-ids. */
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01, /* org..... */
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, /* ........ */
            0x0d, 0xd8, 0x00, 0x12, 0x0c, 0x73, 0x75, 0x72, /* .....sur */
            0x69, 0x63, 0x61, 0x74, 0x61, 0x2d, 0x69, 0x64, /* icata-id */
            0x73, 0x03, 0x6f, 0x72, 0x67, 0x00, 0xc0, 0x32, /* s.org..2 */
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xf4, /* ........ */
            0x00, 0x04, 0xc0, 0x00, 0x4e, 0x18, 0xc0, 0x32, /* ....N..2 */
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xf4, /* ........ */
            0x00, 0x04, 0xc0, 0x00, 0x4e, 0x19              /* ....N. */
        ];
        let (rem, response) = dns_parse_response(pkt).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(response.header, DNSHeader{
                    tx_id: 0x8d32,
                    flags: 0x81a0,
                    questions: 1,
                    answer_rr: 3,
                    authority_rr: 0,
                    additional_rr: 0,
        });
        assert_eq!(response.answers.len(), 3);
        let answer1 = &response.answers[0];
        assert_eq!(answer1.name, "www.suricata-ids.org".as_bytes().to_vec());
        assert_eq!(answer1.rrtype, 5);
        assert_eq!(answer1.rrclass, 1);
        assert_eq!(answer1.ttl, 3544);
        assert_eq!(answer1.data, DNSRData::CNAME("suricata-ids.org".as_bytes().to_vec()));

        let answer2 = &response.answers[1];
        assert_eq!(answer2, &DNSAnswerEntry{
                    name: "suricata-ids.org".as_bytes().to_vec(),
                    rrtype: 1,
                    rrclass: 1,
                    ttl: 244,
                    data: DNSRData::A([192, 0, 78, 24].to_vec()),
        });

        let answer3 = &response.answers[2];
        assert_eq!(answer3, &DNSAnswerEntry{
                    name: "suricata-ids.org".as_bytes().to_vec(),
                    rrtype: 1,
                    rrclass: 1,
                    ttl: 244,
                    data: DNSRData::A([192, 0, 78, 25].to_vec()),
        });
    }
    #[test]
    fn test_dns_parse_response2() {
        let pkt: &[u8] = &[
                        0x82, 0x95, 0x81, 0x83, 0x00, 0x01, /* j....... */
            0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x64, /* .......d */
            0x6e, 0x65, 0x04, 0x6f, 0x69, 0x73, 0x66, 0x03, /* ne.oisf. */
            0x6e, 0x65, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, /* net..... */
            0xc0, 0x10, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, /* ........ */
            0x03, 0x83, 0x00, 0x45, 0x06, 0x6e, 0x73, 0x2d, /* ...E.ns- */
            0x31, 0x31, 0x30, 0x09, 0x61, 0x77, 0x73, 0x64, /* 110.awsd */
            0x6e, 0x73, 0x2d, 0x31, 0x33, 0x03, 0x63, 0x6f, /* ns-13.co */
            0x6d, 0x00, 0x11, 0x61, 0x77, 0x73, 0x64, 0x6e, /* m..awsdn */
            0x73, 0x2d, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, /* s-hostma */
            0x73, 0x74, 0x65, 0x72, 0x06, 0x61, 0x6d, 0x61, /* ster.ama */
            0x7a, 0x6f, 0x6e, 0xc0, 0x3b, 0x00, 0x00, 0x00, /* zon.;... */
            0x01, 0x00, 0x00, 0x1c, 0x20, 0x00, 0x00, 0x03, /* .... ... */
            0x84, 0x00, 0x12, 0x75, 0x00, 0x00, 0x01, 0x51, /* ...u...Q */
            0x80, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, /* ...).... */
            0x00, 0x00, 0x00, 0x00                          /* .... */
        ];
        let (rem, response) = dns_parse_response(pkt).unwrap();
        assert!(!rem.is_empty());
        assert_eq!(response.header, DNSHeader{
                    tx_id: 0x8295,
                    flags: 0x8183,
                    questions: 1,
                    answer_rr: 0,
                    authority_rr: 1,
                    additional_rr: 1,
        });
        assert_eq!(response.authorities.len(), 1);
        let authority = &response.authorities[0];
        assert_eq!(authority.name,
                           "oisf.net".as_bytes().to_vec());
        assert_eq!(authority.rrtype, 6);
        assert_eq!(authority.rrclass, 1);
        assert_eq!(authority.ttl, 899);
        assert_eq!(authority.data,
                           DNSRData::SOA(DNSRDataSOA{
                               mname: "ns-110.awsdns-13.com".as_bytes().to_vec(),
                               rname: "awsdns-hostmaster.amazon.com".as_bytes().to_vec(),
                               serial: 1,
                               refresh: 7200,
                               retry: 900,
                               expire: 1209600,
                               minimum: 86400,
        }));
    }
}
