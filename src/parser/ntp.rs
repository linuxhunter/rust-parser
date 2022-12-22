use nom7::{IResult, sequence::tuple, number::complete::{be_u8, be_u32, be_u64}};
use nom7::bits::streaming::take as take_bit;

use super::common;

#[derive(Debug, PartialEq)]
pub struct NTPFrameFlags {
    leap: u8,
    version: u8,
    mode: u8,
}

#[derive(Debug, PartialEq)]
pub struct NTPFrame {
    flags: NTPFrameFlags,
    stratum: u8,
    poll_interval: u8,
    precision: u8,
    root_delay: u32,
    root_dispersion: u32,
    reference_identifier: u32,
    reference_timestamp: u64,
    originate_timestamp: u64,
    receive_timestamp: u64,
    transmit_timestamp: u64,
    authenticator: Option<Vec<u8>>,
}

pub fn parse_ntp_flags(input: &[u8]) -> IResult<&[u8], NTPFrameFlags> {
    let (rem, (leap, version, mode)) = common::my_bits(tuple((
        take_bit(2u8),
        take_bit(3u8),
        take_bit(3u8),
    )))(input)?;
    Ok((rem, NTPFrameFlags {
        leap,
        version,
        mode,
    }))
}

pub fn parse_ntp_frame(input: &[u8]) -> IResult<&[u8], NTPFrame> {
    let (rem, (
        flags,
        stratum,
        poll_interval,
        precision,
        root_delay,
        root_dispersion,
        reference_identifier,
        reference_timestamp,
        originate_timestamp,
        receive_timestamp,
        transmit_timestamp,
    )) = tuple((
        parse_ntp_flags,
        be_u8,
        be_u8,
        be_u8,
        be_u32,
        be_u32,
        be_u32,
        be_u64,
        be_u64,
        be_u64,
        be_u64,
    ))(input)?;
    let authenticator = if rem.len() > 0 {
        Some(rem.to_vec())
    } else {
        None
    };
    Ok((rem, NTPFrame {
        flags,
        stratum,
        poll_interval,
        precision,
        root_delay,
        root_dispersion,
        reference_identifier,
        reference_timestamp,
        originate_timestamp,
        receive_timestamp,
        transmit_timestamp,
        authenticator,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NTPV3_SYMMETRIC_ACTIVE: &[u8] = &[
                    0xd9, 0x00, 0x0a, 0xfa, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xc6, 0x83, 0x60, 0x6a, 0x5b, 0x6c,
        0x8b, 0x43
    ];
    #[test]
    fn test_parse_ntp_v3_symmeric_active() {
        match parse_ntp_frame(NTPV3_SYMMETRIC_ACTIVE) {
            Ok((rem, frame)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(frame, NTPFrame {
                    flags: NTPFrameFlags {
                        leap: 0x03,
                        version: 0x03,
                        mode: 0x01,
                    },
                    stratum: 0x00,
                    poll_interval: 0x0a,
                    precision: 0xfa,
                    root_delay: 0x00000000,
                    root_dispersion: 0x00010400,
                    reference_identifier: 0x00000000,
                    reference_timestamp: 0x00000000,
                    originate_timestamp: 0x00000000,
                    receive_timestamp: 0x00000000,
                    transmit_timestamp: 0xc683606a5b6c8b43,
                    authenticator: None,
                })
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    const NTPV3_SERVER: &[u8] = &[
                    0x1c, 0x02, 0x0a, 0xfa, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x0b, 0xe3, 0xc0, 0x2b,
        0xf4, 0x12, 0xc6, 0x83, 0x5e, 0xde, 0x9b, 0x65,
        0x3e, 0x48, 0xc6, 0x83, 0x60, 0x6a, 0x5b, 0x6c,
        0x8b, 0x43, 0xc6, 0x83, 0x60, 0x69, 0x33, 0x75,
        0xa0, 0x96, 0xc6, 0x83, 0x60, 0x69, 0x33, 0x75,
        0xa0, 0x96
    ];
    #[test]
    fn test_parse_ntp_v3_server() {
        match parse_ntp_frame(NTPV3_SERVER) {
            Ok((rem, frame)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(frame, NTPFrame {
                    flags: NTPFrameFlags {
                        leap: 0x00,
                        version: 0x03,
                        mode: 0x04,
                    },
                    stratum: 0x02,
                    poll_interval: 0x0a,
                    precision: 0xfa,
                    root_delay: 0x00000800,
                    root_dispersion: 0x00000be3,
                    reference_identifier: 0xc02bf412,
                    reference_timestamp: 0xc6835ede9b653e48,
                    originate_timestamp: 0xc683606a5b6c8b43,
                    receive_timestamp: 0xc68360693375a096,
                    transmit_timestamp: 0xc68360693375a096,
                    authenticator: None,
                });
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }

    const NTPV3_SYMMETRIC_PASSIVE: &[u8] = &[
                    0x1a, 0x03, 0x0a, 0xee, 0x00, 0x00,
        0x1b, 0xf7, 0x00, 0x00, 0x14, 0xec, 0x51, 0xae,
        0x80, 0xb7, 0xc5, 0x02, 0x03, 0x4c, 0x8d, 0x0e,
        0x66, 0xcb, 0xc5, 0x02, 0x04, 0xec, 0xec, 0x42,
        0xee, 0x92, 0xc5, 0x02, 0x04, 0xeb, 0xcf, 0x49,
        0x59, 0xe6, 0xc5, 0x02, 0x04, 0xeb, 0xcf, 0x4c,
        0x6e, 0x6d
    ];
    #[test]
    fn test_parse_ntp_v3_symmeric_passive() {
        match parse_ntp_frame(NTPV3_SYMMETRIC_PASSIVE) {
            Ok((rem, frame)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(frame, NTPFrame {
                    flags: NTPFrameFlags {
                        leap: 0x00,
                        version: 0x03,
                        mode: 0x02,
                    },
                    stratum: 0x03,
                    poll_interval: 0x0a,
                    precision: 0xee,
                    root_delay: 0x00001bf7,
                    root_dispersion: 0x000014ec,
                    reference_identifier: 0x51ae80b7,
                    reference_timestamp: 0xc502034c8d0e66cb,
                    originate_timestamp: 0xc50204ecec42ee92,
                    receive_timestamp: 0xc50204ebcf4959e6,
                    transmit_timestamp: 0xc50204ebcf4c6e6d,
                    authenticator: None,
                })
            },
            Err(_) => {
                panic!("should not reach here")
            }
        }
    }
}