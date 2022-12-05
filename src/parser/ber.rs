use nom7::combinator::verify;
use nom7::{IResult, ErrorConvert};
use nom7::bytes::complete::{take, take_while_m_n};
use nom7::bits::streaming::take as take_bit;
use nom7::error::{make_error, ErrorKind, ParseError, Error};
use nom7::Err;
use nom7::number::complete::{be_u8, be_u16, be_u24, be_u32, be_i8, be_i16, be_i24, be_i32};
use nom7::sequence::tuple;

const BER_TYPE_BOOLEAN: u8 = 0x01;
const BER_TYPE_INTEGER: u8 = 0x02;
const BER_TYPE_BIT_STRING: u8 = 0x03;
const BER_TYPE_OCTET_STRING: u8 = 0x04;
const BER_TYPE_NULL: u8 = 0x05;
const BER_TYPE_OID: u8 = 0x06;
const BER_TYPE_SEQUENCE: u8 = 0x30;
const BER_TYPE_SNMP_SET: u8 = 0xA3;

#[derive(Debug, PartialEq)]
pub enum BerData {
    BOOLEAN(bool),
    INTEGER(i32),
    BIT_STRING(Vec<u8>),
    OCTET_STRING(String),
    NULL(u8),
    OID(Vec<u32>),
    VAR_LENGHED(Vec<u8>),
}

pub fn parse_ber_type(input: &[u8]) -> IResult<&[u8], u8> {
    if input.is_empty() {
        return Err(Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let (rem, data_type) = be_u8(input)?;
    Ok((rem, data_type))
}

pub fn parse_ber_length(input: &[u8]) -> IResult<&[u8], u32> {
    if input.is_empty() {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    if input[0] & 0x80 == 0 {
        let (rem, length) = be_u8(input)?;
        Ok((rem, length as u32))
    } else {
        let k = input[0] & 0x7F;
        let mut rem = &input[1..];
        let mut length = 0;
        match k {
            0 => {
                if input[input.len() - 1] != 0 || input[input.len() - 2] != 0 {
                    return Err(Err::Error(make_error(input, ErrorKind::Verify)));
                } else {
                    length = (input.len() - 3) as u32;
                }
            }
            1 => {
                let (tmp_rem, tmp_length) = be_u8(rem)?;
                rem = tmp_rem;
                length = tmp_length as u32;
            },
            2 => {
                let (tmp_rem, tmp_length) = be_u16(rem)?;
                rem = tmp_rem;
                length = tmp_length as u32;
            },
            3 => {
                let (tmp_rem, tmp_length) = be_u24(rem)?;
                rem = tmp_rem;
                length = tmp_length as u32;
            },
            4 => {
                let (tmp_rem, tmp_length) = be_u32(rem)?;
                rem = tmp_rem;
                length = tmp_length as u32;
            }
            _ => {
                unimplemented!()
            }
        } 
        Ok((rem, length))
    }
}

pub fn parse_ber_bool(input: &[u8]) -> IResult<&[u8], bool> {
    if input.is_empty() {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    match input[0] {
        0x00 => Ok((&input[1..], false)),
        0xFF => Ok((&input[1..], true)),
        _ => Err(Err::Error(make_error(input, ErrorKind::Verify))),
    }
}

pub fn parse_ber_integer(input: &[u8], length: u32) -> IResult<&[u8], i32> {
    let mut rem = &input[..];
    let mut data: i32 = 0;
    match length {
        0x01 => {
            let (tmp_rem, tmp_data) = be_i8(input)?;
            rem = tmp_rem;
            data = tmp_data as i32;
        },
        0x02 => {
            let (tmp_rem, tmp_data) = be_i16(input)?;
            rem = tmp_rem;
            data = tmp_data as i32;
        },
        0x03 => {
            let (tmp_rem, tmp_data) = be_i24(input)?;
            rem = tmp_rem;
            data = tmp_data as i32;
        },
        0x04 => {
            let (tmp_rem, tmp_data) = be_i32(input)?;
            rem = tmp_rem;
            data = tmp_data as i32;
        },
        _ => {
            unimplemented!()
        }
    }
    Ok((rem, data))
}

pub fn my_bits<'a, O, E, P>(parser: P) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>
    where
        E: ParseError<&'a [u8]>,
        Error<(&'a [u8], usize)>: ErrorConvert<E>,
        P: FnMut((&'a [u8], usize)) -> IResult<(&'a [u8], usize), O, Error<(&'a [u8], usize)>>,
{
    // use full path to disambiguate nom `bits` from this current function name
    nom7::bits::bits(parser)
}

pub fn parse_u8_bit(input: &[u8]) -> IResult<&[u8],(u8, u8, u8, u8, u8, u8, u8, u8)> {
    my_bits(tuple((
        take_bit(1u8),
        take_bit(1u8),
        take_bit(1u8),
        take_bit(1u8),
        take_bit(1u8),
        take_bit(1u8),
        take_bit(1u8),
        take_bit(1u8),
    )))(input)
}

pub fn parse_ber_bit_string(input: &[u8], length: u32) -> IResult<&[u8], Vec<u8>> {
    let padding = input[0];
    let mut rem = &input[1..];
    let mut data_result = Vec::new();
    for _ in 0..length-1 {
        let (tmp_rem, data_bits) = parse_u8_bit(rem)?;
        data_result.push(data_bits.0);
        data_result.push(data_bits.1);
        data_result.push(data_bits.2);
        data_result.push(data_bits.3);
        data_result.push(data_bits.4);
        data_result.push(data_bits.5);
        data_result.push(data_bits.6);
        data_result.push(data_bits.7);
        rem = tmp_rem;
    }
    for _ in 0..padding {
        data_result.pop();
    }
    Ok((rem, data_result))
}

pub fn parse_ber_string(input: &[u8], length: u32) -> IResult<&[u8], String> {
    let (rem, data) = take(length)(input)?;
    Ok((rem, String::from_utf8(data.to_vec()).unwrap()))
}

pub fn is_continue_bit_set(input: u8) -> bool {
    (input & 0x80) != 0
}

pub fn convert_variant(continued_part: Vec<u8>, non_continued_part: u8) -> u32 {
    let mut multiplier = 1u32;
    let mut result = 0u32;

    result = (non_continued_part & 0x7F) as u32 * multiplier;
    for data in continued_part.iter().rev() {
        multiplier *= 0x80;
        result += (data & 0x7F) as u32 * multiplier;
    }
    result
}

pub fn parse_ber_oid(input: &[u8]) -> IResult<&[u8], Vec<u32>> {
    if input.is_empty() {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    let first = input[0];
    let mut rem = &input[1..];
    let mut result: Vec<u32> = Vec::new();

    result.push((first / 40) as u32);
    result.push((first % 40) as u32);
    while !rem.is_empty() {
        let (tmp_rem, continued_part) = take_while_m_n(0, 3, is_continue_bit_set)(rem)?;
        let (tmp_rem2, non_continued_part) = verify(be_u8, |&val| !is_continue_bit_set(val))(tmp_rem)?;
        let data = convert_variant(continued_part.to_vec(), non_continued_part);
        result.push(data);
        rem = tmp_rem2;
    }
    Ok((rem, result))
}

pub fn parse_ber_sequence(input: &[u8]) -> IResult<&[u8], Vec<BerData>> {
    if input.is_empty() {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    let mut rem = input;
    let mut ber_data = Vec::new();
    while !rem.is_empty() {
        let (tmp_rem, data_type) = parse_ber_type(rem)?;
        match data_type {
            BER_TYPE_BOOLEAN => {
                let (tmp_rem2, _data_length) = parse_ber_length(tmp_rem)?;
                let (tmp_rem3, data_value) = parse_ber_bool(tmp_rem2)?;
                ber_data.push(BerData::BOOLEAN(data_value));
                rem = tmp_rem3;
            },
            BER_TYPE_INTEGER => {
                let (tmp_rem2, data_length) = parse_ber_length(tmp_rem)?;
                let (tmp_rem3, data_value) = parse_ber_integer(tmp_rem2, data_length)?;
                ber_data.push(BerData::INTEGER(data_value));
                rem = tmp_rem3;
            },
            BER_TYPE_BIT_STRING => {
                let (tmp_rem2, data_length) = parse_ber_length(tmp_rem)?;
                let (tmp_rem3, data_value) = parse_ber_bit_string(tmp_rem2, data_length)?;
                ber_data.push(BerData::BIT_STRING(data_value));
                rem = tmp_rem3;
            },
            BER_TYPE_OCTET_STRING => {
                let (tmp_rem2, data_length) = parse_ber_length(tmp_rem)?;
                let (tmp_rem3, data_value) = parse_ber_string(tmp_rem2, data_length)?;
                ber_data.push(BerData::OCTET_STRING(data_value));
                rem = tmp_rem3;
            },
            BER_TYPE_NULL => {
                let (tmp_rem2, _data_length) = parse_ber_length(tmp_rem)?;
                ber_data.push(BerData::NULL(0));
                rem = tmp_rem2;
            },
            BER_TYPE_OID => {
                let (tmp_rem2, _data_length) = parse_ber_length(tmp_rem)?;
                let (tmp_rem3, data_value) = parse_ber_oid(tmp_rem2)?;
                ber_data.push(BerData::OID(data_value));
                rem = tmp_rem3;
            },
            _ => {
                unimplemented!()
            }
        }
    }
    Ok((rem, ber_data))
}

pub fn parse_ber_variable_length(input: &[u8], length: u32) -> IResult<&[u8], Vec<u8>> {
    let variable_data = input[0..length as usize].to_vec();
    let rem = &input[(length+1) as usize ..];
    Ok((rem, variable_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BER_BOOL_TRUE: &[u8] = &[0x01,0x01, 0xFF];
    const BER_BOOL_FALSE: &[u8] = &[0x01,0x01, 0x00];
    const BER_INTEGER_POSITIVE: &[u8] = &[0x02, 0x02, 0x05, 0xDC];
    const BER_INTEGER_POSITIVE_2: &[u8] = &[0x02, 0x03, 0x00, 0x9C, 0x40];
    const BER_INTEGER_NEGATIVE: &[u8] = &[0x02, 0x02, 0xFF, 0x7F];
    const BER_BIT_STRING: &[u8] = &[0x03, 0x03, 0x04, 0x8E, 0x90];
    const BER_STRING: &[u8] = &[0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63];
    const BER_NULL: &[u8] = &[0x05, 0x00];
    const BER_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05];
    const BER_SEQUENCE: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x20, 0x01, 0x01, 0xFF];
    const BER_SEQUENCE_ALL: &[u8] = &[
        0x30, 0x20,
        0x01, 0x01, 0xFF,
        0x02, 0x02, 0x05, 0xDC,
        0x03, 0x03, 0x04, 0x8E, 0x90,
        0x04, 0x06, 0x70, 0x75, 0x62, 0x06C, 0x69, 0x63,
        0x05, 0x00,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05
    ];
    const BER_VARIABLE_LENGTH_VALUE: &[u8] = &[0x02, 0x80, 0xFF, 0x00, 0x00];
    const BER_VARIABLE_LENGTH_VALUE2: &[u8] = &[0x02, 0x80, 0x05, 0xDC, 0x00, 0x00];
    const BER_VARIABLE_LENGTH_VALUE3: &[u8] = &[0x02, 0x80, 0x05, 0xDC, 0x00, 0x01];
    #[test]
    fn test_ber_bool_true() {
        let (rem, data_type) = parse_ber_type(BER_BOOL_TRUE).unwrap();
        assert_eq!(data_type, BER_TYPE_BOOLEAN);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 0x01);
        let (rem, data_value) = parse_ber_bool(rem).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(data_value, true);
    }
    #[test]
    fn test_ber_bool_false() {
        let (rem, data_type) = parse_ber_type(BER_BOOL_FALSE).unwrap();
        assert_eq!(data_type, BER_TYPE_BOOLEAN);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 0x01);
        let (rem, data_value) = parse_ber_bool(rem).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(data_value, false);
    }
    #[test]
    fn test_ber_integer_positive() {
        let (rem, data_type) = parse_ber_type(BER_INTEGER_POSITIVE).unwrap();
        assert_eq!(data_type, BER_TYPE_INTEGER);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 0x02);
        let (rem, data_value) = parse_ber_integer(rem, data_length).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(data_value, 1500);
    }
    #[test]
    fn test_ber_integer_positive_2() {
        let (rem, data_type) = parse_ber_type(BER_INTEGER_POSITIVE_2).unwrap();
        assert_eq!(data_type, BER_TYPE_INTEGER);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 0x03);
        let (rem, data_value) = parse_ber_integer(rem, data_length).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(data_value, 40000);
    }
    #[test]
    fn test_ber_integer_negative() {
        let (rem, data_type) = parse_ber_type(BER_INTEGER_NEGATIVE).unwrap();
        assert_eq!(data_type, BER_TYPE_INTEGER);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 0x02);
        let (rem, data_value) = parse_ber_integer(rem, data_length).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(data_value, -129);
    }
    #[test]
    fn test_ber_string() {
        let (rem, data_type) = parse_ber_type(BER_STRING).unwrap();
        assert_eq!(data_type, BER_TYPE_OCTET_STRING);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 0x06);
        let (rem, data_value) = parse_ber_string(rem, data_length).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(data_value, String::from("public"));
    }
    #[test]
    fn test_ber_bit_string() {
        let (rem, data_type) = parse_ber_type(BER_BIT_STRING).unwrap();
        assert_eq!(data_type, BER_TYPE_BIT_STRING);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 0x03);
        let (rem, data_value) = parse_ber_bit_string(rem, data_length).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(data_value, vec![1,0,0,0,1,1,1,0,1,0,0,1]);
    }
    #[test]
    fn test_ber_null() {
        let (rem, data_type) = parse_ber_type(BER_NULL).unwrap();
        assert_eq!(data_type, BER_TYPE_NULL);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(data_length, 0x00);
    }
    #[test]
    fn test_ber_oid() {
        let (rem, data_type) = parse_ber_type(BER_OID).unwrap();
        assert_eq!(data_type, BER_TYPE_OID);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 0x08);
        let (rem, data_value) = parse_ber_oid(rem).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(data_value, vec![1, 2, 840, 113549, 2, 5]);
    }
    #[test]
    fn test_ber_sequence() {
        let (rem, data_type) = parse_ber_type(BER_SEQUENCE).unwrap();
        assert_eq!(data_type, BER_TYPE_SEQUENCE);
        let (rem , data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 0x06);
        let (rem, data_value) = parse_ber_sequence(rem).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(data_value, vec![
            BerData::INTEGER(32),
            BerData::BOOLEAN(true)
        ]);
    }
    #[test]
    fn test_ber_sequence_all() {
        let (rem, data_type) = parse_ber_type(BER_SEQUENCE_ALL).unwrap();
        assert_eq!(data_type, BER_TYPE_SEQUENCE);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 0x20);
        let (rem, data_value) = parse_ber_sequence(rem).unwrap();
        assert_eq!(rem.len(), 0);
        assert_eq!(data_value, vec![
            BerData::BOOLEAN(true),
            BerData::INTEGER(1500),
            BerData::BIT_STRING(vec![1,0,0,0,1,1,1,0,1,0,0,1]),
            BerData::OCTET_STRING(String::from("public")),
            BerData::NULL(0),
            BerData::OID(vec![1, 2, 840, 113549, 2, 5])
        ]);
    }
    #[test]
    fn test_ber_variable_length_value() {
        let (rem, data_type) = parse_ber_type(BER_VARIABLE_LENGTH_VALUE).unwrap();
        assert_eq!(data_type, BER_TYPE_INTEGER);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 1u32);
        let (rem, data_value) = parse_ber_variable_length(rem, data_length).unwrap();
        assert_eq!(data_value, vec![0xFF]);
    }
    #[test]
    fn test_ber_variable_length_value2() {
        let (rem, data_type) = parse_ber_type(BER_VARIABLE_LENGTH_VALUE2).unwrap();
        assert_eq!(data_type, BER_TYPE_INTEGER);
        let (rem, data_length) = parse_ber_length(rem).unwrap();
        assert_eq!(data_length, 2u32);
        let (rem, data_value) = parse_ber_variable_length(rem, data_length).unwrap();
        assert_eq!(data_value, vec![0x05, 0xDC]);
    }
    #[test]
    fn test_ber_variable_length_value3() {
        let (rem, data_type) = parse_ber_type(BER_VARIABLE_LENGTH_VALUE3).unwrap();
        assert_eq!(data_type, BER_TYPE_INTEGER);
        match parse_ber_length(rem) {
            Ok((_, _)) => {
                panic!("should not reach here");
            },
            Err(Err::Error(e)) => {
                assert_eq!(e.code, ErrorKind::Verify);
            },
            _ => {
                panic!("should not reach here")
            }
        }
    }

}