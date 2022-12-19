use nom7::{IResult, bytes::complete::{tag, take_until, self}, sequence::{delimited, tuple}, character::complete::{digit1, multispace0}, combinator::{verify, map_res, opt}};
use std::str::FromStr;
use nom7::combinator::complete;

pub fn parse_u16(input: &[u8]) -> IResult<&[u8], u16> {
    map_res(map_res(digit1, std::str::from_utf8), u16::from_str)(input)
}

// PORT 192,168,0,13,234,10
pub fn parse_active_port(input: &[u8]) -> IResult<&[u8], u16> {
    let (rem, _) = tag("PORT")(input)?;
    let (rem, _) = delimited(multispace0, digit1, multispace0)(rem)?;
    let (rem, _) = tuple((
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(",")
    ))(rem)?;
    let (rem, part1) = verify(parse_u16, |&v| v <= std::u8::MAX as u16)(rem)?;
    let (rem, _) = tag(",")(rem)?;
    let (rem, part2) = verify(parse_u16, |&v| v <= std::u8::MAX as u16)(rem)?;
    Ok((rem, part1 * 256 + part2))
}

// 227 Entering Passive Mode (212,27,32,66,221,243).
pub fn parse_pasv_response(input: &[u8]) -> IResult<&[u8], u16> {
    let (rem, _) = tag("227")(input)?;
    let (rem, _) = take_until("(")(rem)?;
    let (rem, _) = tag("(")(rem)?;
    let (rem, _) = tuple((
        digit1,
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(","),
        digit1,
        tag(","),
    ))(rem)?;
    let (rem, part1) = verify(parse_u16, |&v| v <= std::u8::MAX as u16)(rem)?;
    let (rem, _) = tag(",")(rem)?;
    let (rem, part2) = verify(parse_u16, |&v| v <= std::u8::MAX as u16)(rem)?;
    let (rem, _) = tag(")")(rem)?;
    let (rem, _) = opt(complete(tag(".")))(rem)?;
    Ok((rem, part1 * 256 + part2))
}

// EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|41813|
pub fn parse_active_eprt(input: &[u8]) -> IResult<&[u8], u16> {
    let (rem, _) = tag("EPRT")(input)?;
    let (rem, _) = take_until("|")(rem)?;
    let (rem, _) = tag("|")(rem)?;
    let (rem, _) = take_until("|")(rem)?;
    let (rem, _) = tag("|")(rem)?;
    let (rem, _) = take_until("|")(rem)?;
    let (rem, _) = tag("|")(rem)?;
    let (rem, port) = parse_u16(rem)?;
    let (rem, _) = tag("|")(rem)?;
    Ok((rem, port))
}

// 229 Entering Extended Passive Mode (|||48758|).
pub fn parse_pasv_eprt(input: &[u8]) -> IResult<&[u8], u16> {
    let (rem, _) = tag("229")(input)?;
    let (rem, _) = take_until("(")(rem)?;
    let (rem, _) = tag("(")(rem)?;
    let (rem, _) = tag("|||")(rem)?;
    let (rem, port) = parse_u16(rem)?;
    let (rem, _) = tag("|")(rem)?;
    let (rem, _) = tag(")")(rem)?;
    let (rem, _) = opt(complete(tag(".")))(rem)?;
    Ok((rem, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_active_port() {
        match parse_active_port("PORT 192,168,0,13,234,10".as_bytes()) {
            Ok((rem, port)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(port, (234 * 256 + 10) as u16);
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    #[test]
    fn test_parse_pasv_response() {
        match parse_pasv_response("227 Entering Passive Mode (212,27,32,66,221,243).".as_bytes()) {
            Ok((rem, port)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(port, (221 * 256 + 243) as u16);
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    #[test]
    fn test_parse_active_eprt() {
        match parse_active_eprt("EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|41813|".as_bytes()) {
            Ok((rem, port)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(port, 41813 as u16);
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    #[test]
    fn test_parse_pasv_eprt() {
        match parse_pasv_eprt("229 Entering Extended Passive Mode (|||48758|).".as_bytes()) {
            Ok((rem, port)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(port, 48758 as u16);
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    #[test]
    fn test_active_port_too_large() {
        let port = parse_active_port("PORT 212,27,32,66,257,243".as_bytes());
        assert!(port.is_err());

        let port = parse_active_port("PORT 212,27,32,66,255,65535".as_bytes());
        assert!(port.is_err());
    }

    #[test]
    fn test_active_eprt_too_larg() {
        let port = parse_active_eprt("EPRT |2|2a01:e34:ee97:b130:8c3e:45ea:5ac6:e301|81813|".as_bytes());
        assert!(port.is_err());
    }

    #[test]
    fn test_pasv_response_too_large() {
        let port = parse_pasv_response("227 Entering Passive Mode (212,27,32,66,257,243).".as_bytes());
        assert!(port.is_err());

        let port = parse_pasv_response("227 Entering Passive Mode (212,27,32,66,255,65535).".as_bytes());
        assert!(port.is_err());
    }
}