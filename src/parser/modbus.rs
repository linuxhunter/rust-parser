use nom7::{IResult, Err, number::complete::{be_u16, be_u8}, error_position, error::ErrorKind, multi::length_data};

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum FunctionCode {
    RdCoils = 0x01,
    RdDiscreteInputs,
    RdHoldRegs,
    RdInputRegs,
    WrSingleCoil,
    WrSingleReg,
    RdExcStatus,
    Diagnostic,
    Program484,
    Poll484,
    GetCommEventCtr,
    GetCommEventLog,
    ProgramController,
    PollController,
    WrMultCoils,
    WrMultRegs,
    ReportServerID,
    Program884,
    ResetCommLink,
    RdFileRec,
    WrFileRec,
    MaskWrReg,
    RdWrMultRegs,
    RdFIFOQueue,
    MEI = 0x2b,
    Unknown,
}

impl std::fmt::Display for FunctionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<u8> for FunctionCode {
    fn from(val: u8) -> Self {
        match val {
            0x01 => FunctionCode::RdCoils,
            0x02 => FunctionCode::RdDiscreteInputs,
            0x03 => FunctionCode::RdHoldRegs,
            0x04 => FunctionCode::RdInputRegs,
            0x05 => FunctionCode::WrSingleCoil,
            0x06 => FunctionCode::WrSingleReg,
            0x07 => FunctionCode::RdExcStatus,
            0x08 => FunctionCode::Diagnostic,
            0x0B => FunctionCode::GetCommEventCtr,
            0x0C => FunctionCode::GetCommEventLog,
            0x0F => FunctionCode::WrMultCoils,
            0x10 => FunctionCode::WrMultRegs,
            0x11 => FunctionCode::ReportServerID,
            0x14 => FunctionCode::RdFileRec,
            0x15 => FunctionCode::WrFileRec,
            0x16 => FunctionCode::MaskWrReg,
            0x17 => FunctionCode::RdWrMultRegs,
            0x18 => FunctionCode::RdFIFOQueue,
            0x2B => FunctionCode::MEI,
            _ => FunctionCode::Unknown,
           
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct MBAPHeader {
    transaction_id: u16,
    protocol_id: u16,
    length: u16,
    unit_id: u8,
}

#[derive(Debug, PartialEq)]
pub struct CoilRequest {
    start_address: u16,
    quantity: u16,
}

#[derive(Debug, PartialEq)]
pub struct WriteSingleRegRequest {
    register_address: u16,
    register_value: u16,
}

#[derive(Debug, PartialEq)]
pub struct WriteMultiRegRequest {
    start_address: u16,
    quantity: u16,
    register_value: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct MaskWriteRegRequest {
    reference_address: u16,
    and_mask: u16,
    or_mask: u16,
}

#[derive(Debug, PartialEq)]
pub struct ReadWriteMultiRegRequest {
    read_start_address: u16,
    read_quantity: u16,
    write_start_address: u16,
    write_quantity: u16,
    write_register_value: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct CoilResponse {
    coil_status: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct WriteSingleRegResponse {
    register_address: u16,
    register_value: u16,
}

#[derive(Debug, PartialEq)]
pub struct WriteMultiRegResponse {
    start_address: u16,
    quantity: u16,
}

#[derive(Debug, PartialEq)]
pub struct MaskWriteRegResponse {
    reference_address: u16,
    and_mask: u16,
    or_mask: u16,
}

#[derive(Debug, PartialEq)]
pub struct ReadWriteMultiRegResponse {
    read_registers_value: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum ModbusRequestData {
    READ_COIL(CoilRequest),
    WRITE_SINGLE_REG(WriteSingleRegRequest),
    WRITE_MULTI_REG(WriteMultiRegRequest),
    MASK_WRITE_REG(MaskWriteRegRequest),
    READ_WRITE_MULTI_REG(ReadWriteMultiRegRequest),
}

#[derive(Debug, PartialEq)]
pub enum ModbusResponseData {
    READ_COIL(CoilResponse),
    WRITE_SINGLE_REG(WriteSingleRegResponse),
    WRITE_MULTI_REG(WriteMultiRegResponse),
    MASK_WRITE_REG(MaskWriteRegResponse),
    READ_WRITE_MULTI_REG(ReadWriteMultiRegResponse),
}

#[derive(Debug, PartialEq)]
pub struct MBAP_Request_PDU {
    function_code: u8,
    data: ModbusRequestData,
}

#[derive(Debug, PartialEq)]
pub struct MBAP_Response_PDU {
    function_code: u8,
    data: ModbusResponseData,
}

#[derive(Debug, PartialEq)]
pub struct ModbusRequest {
    header: MBAPHeader,
    pdu: MBAP_Request_PDU,
}

#[derive(Debug, PartialEq)]
pub struct ModbusResponse {
    header: MBAPHeader,
    pdu: MBAP_Response_PDU,
}

pub fn modbus_parse_header<'a>(input: &'a [u8]) -> IResult<&'a [u8], MBAPHeader> {
    let (rem, transaction_id) = be_u16(input)?;
    let (rem, protocol_id) = be_u16(rem)?;
    let (rem, length) = be_u16(rem)?;
    let (rem, unit_id) = be_u8(rem)?;
    Ok((rem, MBAPHeader {
        transaction_id,
        protocol_id,
        length,
        unit_id,
    }))
}

pub fn modbus_parse_request_read_coils<'a>(input: &'a [u8]) -> IResult<&'a [u8], ModbusRequestData> {
    let (rem, start_address) = be_u16(input)?;
    let (rem, quantity) = be_u16(rem)?;
    Ok((rem, ModbusRequestData::READ_COIL(CoilRequest {
        start_address,
        quantity,
    })))
}

pub fn modbus_parse_request_write_single_reg<'a>(input: &'a [u8]) -> IResult<&'a [u8], ModbusRequestData> {
    let (rem, register_address) = be_u16(input)?;
    let (rem, register_value) = be_u16(rem)?;
    Ok((rem, ModbusRequestData::WRITE_SINGLE_REG(WriteSingleRegRequest {
        register_address,
        register_value,
    })))
}

pub fn modbus_parse_request_write_multi_reg<'a>(input: &'a [u8]) -> IResult<&'a [u8], ModbusRequestData> {
    let (rem, start_address) = be_u16(input)?;
    let (rem, quantity) = be_u16(rem)?;
    let (rem, data) = length_data(be_u8)(rem)?;
    Ok((rem, ModbusRequestData::WRITE_MULTI_REG(WriteMultiRegRequest {
        start_address,
        quantity,
        register_value: data.to_vec(),
    })))
}

pub fn modbus_parse_request_mask_write_reg<'a>(input: &'a [u8]) -> IResult<&'a [u8], ModbusRequestData> {
    let (rem, reference_address) = be_u16(input)?;
    let (rem, and_mask) = be_u16(rem)?;
    let (rem, or_mask) = be_u16(rem)?;
    Ok((rem, ModbusRequestData::MASK_WRITE_REG(MaskWriteRegRequest {
        reference_address,
        and_mask,
        or_mask,
    })))
}

pub fn modbus_parse_request_read_write_multi_reg<'a>(input: &'a [u8]) -> IResult<&'a [u8], ModbusRequestData> {
    let (rem, read_start_address) = be_u16(input)?;
    let (rem, read_quantity) = be_u16(rem)?;
    let (rem, write_start_address) = be_u16(rem)?;
    let (rem, write_quantity) = be_u16(rem)?;
    let (rem, data) = length_data(be_u8)(rem)?;
    Ok((rem, ModbusRequestData::READ_WRITE_MULTI_REG(ReadWriteMultiRegRequest {
        read_start_address,
        read_quantity,
        write_start_address,
        write_quantity,
        write_register_value: data.to_vec(),
    })))
}

pub fn modbus_parse_request_pdu<'a>(input: &'a [u8]) -> IResult<&'a [u8], MBAP_Request_PDU> {
    let (rem, function_code) = be_u8(input)?;
    match FunctionCode::from(function_code) {
        FunctionCode::RdCoils => {
            let (rem, data) = modbus_parse_request_read_coils(rem)?;
            return Ok((rem, MBAP_Request_PDU {
                function_code,
                data,
            }));
        },
        FunctionCode::WrSingleReg => {
            let (rem, data) = modbus_parse_request_write_single_reg(rem)?;
            return Ok((rem, MBAP_Request_PDU {
                function_code,
                data,
            }));
        },
        FunctionCode::WrMultRegs => {
            let (rem, data) = modbus_parse_request_write_multi_reg(rem)?;
            return Ok((rem, MBAP_Request_PDU {
                function_code,
                data,
            }));
        },
        FunctionCode::MaskWrReg => {
            let (rem, data) = modbus_parse_request_mask_write_reg(rem)?;
            return Ok((rem, MBAP_Request_PDU {
                function_code,
                data,       
            }));
        },
        FunctionCode::RdWrMultRegs => {
            let (rem, data) = modbus_parse_request_read_write_multi_reg(rem)?;
            return Ok((rem, MBAP_Request_PDU {
                function_code,
                data,
            }));
        },
        _ => {
            return Err(Err::Error(error_position!(rem, ErrorKind::OctDigit)));
        }
    }
}

pub fn modbus_parse_response_read_coil<'a>(input: &'a [u8]) -> IResult<&'a [u8], CoilResponse> {
    let (rem, data) = length_data(be_u8)(input)?;
    Ok((rem, CoilResponse {
        coil_status: data.to_vec(),
    }))
}

pub fn modbus_parse_response_write_single_reg<'a>(input: &'a [u8]) -> IResult<&'a [u8], WriteSingleRegResponse> {
    let (rem, register_address) = be_u16(input)?;
    let (rem, register_value) = be_u16(rem)?;
    Ok((rem, WriteSingleRegResponse {
        register_address,
        register_value,
    }))
}

pub fn modbus_parse_response_write_multi_reg<'a>(input: &'a [u8]) -> IResult<&'a [u8], WriteMultiRegResponse> {
    let (rem, start_address) = be_u16(input)?;
    let (rem, quantity) = be_u16(rem)?;
    Ok((rem, WriteMultiRegResponse {
        start_address,
        quantity,
    }))
}

pub fn modbus_parse_response_mask_write_reg<'a>(input: &'a [u8]) -> IResult<&'a [u8], MaskWriteRegResponse> {
    let (rem, reference_address) = be_u16(input)?;
    let (rem, and_mask) = be_u16(rem)?;
    let (rem, or_mask) = be_u16(rem)?;
    Ok((rem, MaskWriteRegResponse {
        reference_address,
        and_mask,
        or_mask,
    }))
}

pub fn modbus_parse_response_read_write_reg<'a>(input: &'a [u8]) -> IResult<&'a [u8], ReadWriteMultiRegResponse> {
    let (rem, data) = length_data(be_u8)(input)?;
    Ok((rem, ReadWriteMultiRegResponse {
        read_registers_value: data.to_vec(),
    }))
}

pub fn modbus_parse_response_pdu<'a>(input: &'a [u8]) -> IResult<&'a [u8], MBAP_Response_PDU> {
    let (rem, function_code) = be_u8(input)?;
    match FunctionCode::from(function_code) {
        FunctionCode::RdCoils => {
            let (rem, data) = modbus_parse_response_read_coil(rem)?;
            Ok((rem, MBAP_Response_PDU {
                function_code,
                data: ModbusResponseData::READ_COIL(data),
            }))
        },
        FunctionCode::WrSingleReg => {
            let (rem, data) = modbus_parse_response_write_single_reg(rem)?;
            Ok((rem, MBAP_Response_PDU {
                function_code,
                data: ModbusResponseData::WRITE_SINGLE_REG(data),
            }))
        },
        FunctionCode::WrMultRegs => {
            let (rem, data) = modbus_parse_response_write_multi_reg(rem)?;
            Ok((rem, MBAP_Response_PDU {
                function_code,
                data: ModbusResponseData::WRITE_MULTI_REG(data),
            }))
        },
        FunctionCode::MaskWrReg => {
            let (rem, data) = modbus_parse_response_mask_write_reg(rem)?;
            Ok((rem, MBAP_Response_PDU {
                function_code,
                data: ModbusResponseData::MASK_WRITE_REG(data),
            }))
        },
        FunctionCode::RdWrMultRegs => {
            let (rem, data) = modbus_parse_response_read_write_reg(rem)?;
            Ok((rem, MBAP_Response_PDU {
                function_code,
                data: ModbusResponseData::READ_WRITE_MULTI_REG(data),
            }))
        },
        _ => {
            return Err(Err::Error(error_position!(rem, ErrorKind::OctDigit)));
        }
    }
}

pub fn modbus_parse_request<'a>(input: &'a [u8]) -> IResult<&'a [u8], ModbusRequest> {
    let (rem, header) = modbus_parse_header(input)?;
    let (rem, pdu) = modbus_parse_request_pdu(rem)?;
    Ok((rem, ModbusRequest {
        header,
        pdu,
    }))
}

pub fn modbus_parse_response<'a>(input: &'a [u8]) -> IResult<&'a [u8], ModbusResponse> {
    let (rem, header) = modbus_parse_header(input)?;
    let (rem, pdu) = modbus_parse_response_pdu(rem)?;
    Ok((rem, ModbusResponse {
        header,
        pdu,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RD_COILS_REQ: &[u8] = &[
        0x00, 0x00, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x01, // Function code
        0x78, 0x90, // Starting Address
        0x00, 0x13, // Quantity of coils
    ];

    #[test]
    fn test_modbus_request_read_coils() {
        match modbus_parse_request(&RD_COILS_REQ) {
            Ok((rem, request)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(request.header, MBAPHeader {
                    transaction_id: 0x0000,
                    protocol_id: 0x0000,
                    length: 0x0006,
                    unit_id: 0x0000,
                });
                assert_eq!(request.pdu, MBAP_Request_PDU {
                    function_code: 0x01,
                    data: ModbusRequestData::READ_COIL(CoilRequest {
                        start_address: 0x7890,
                        quantity: 0x0013,
                    })
                });
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }

    const WR_SINGLE_REG_REQ: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x06, // Function code
        0x00, 0x01, // Register Address
        0x00, 0x03, // Register Value
    ];

    #[test]
    fn test_modbus_request_write_single_register() {
        match modbus_parse_request(&WR_SINGLE_REG_REQ) {
            Ok((rem, request)) => {
                assert_eq!(rem.len() , 0);
                assert_eq!(request.header, MBAPHeader {
                    transaction_id: 0x000A,
                    protocol_id: 0x0000,
                    length: 0x0006,
                    unit_id: 0x00,
                });
                assert_eq!(request.pdu, MBAP_Request_PDU {
                    function_code: 0x06,
                    data: ModbusRequestData::WRITE_SINGLE_REG(WriteSingleRegRequest {
                        register_address: 0x0001,
                        register_value: 0x0003,
                    })
                });
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }

    const WR_MULT_REG_REQ: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x0B, // Length
        0x00, // Unit ID
        0x10, // Function code
        0x00, 0x01, // Starting Address
        0x00, 0x02, // Quantity of Registers
        0x04, // Byte count
        0x00, 0x0A, // Registers Value
        0x01, 0x02,
    ];

    #[test]
    fn test_modbus_request_write_multi_registers() {
        match modbus_parse_request(&WR_MULT_REG_REQ) {
            Ok((rem, request)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(request.header, MBAPHeader {
                    transaction_id: 0x000A,
                    protocol_id: 0x0000,
                    length: 0x000B,
                    unit_id: 0x00,
                });
                assert_eq!(request.pdu, MBAP_Request_PDU {
                    function_code: 0x10,
                    data: ModbusRequestData::WRITE_MULTI_REG(WriteMultiRegRequest {
                        start_address: 0x0001,
                        quantity: 0x0002,
                        register_value: vec![0x00, 0x0A, 0x01, 0x02],
                    })
                });
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }

    const MASK_WR_REG_REQ: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x08, // Length
        0x00, // Unit ID
        0x16, // Function code
        0x00, 0x04, // Reference Address
        0x00, 0xF2, // And_Mask
        0x00, 0x25, // Or_Mask
    ];

    #[test]
    fn test_modbus_request_mask_write_register() {
        match modbus_parse_request(&MASK_WR_REG_REQ) {
            Ok((rem, request)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(request.header, MBAPHeader {
                    transaction_id: 0x000A,
                    protocol_id: 0x0000,
                    length: 0x0008,
                    unit_id: 0x00,
                });
                assert_eq!(request.pdu, MBAP_Request_PDU {
                    function_code: 0x16,
                    data: ModbusRequestData::MASK_WRITE_REG(MaskWriteRegRequest {
                        reference_address: 0x0004,
                        and_mask: 0x00F2,
                        or_mask: 0x0025,
                    })
                });
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }

    const RD_WR_MULT_REG_REQ: &[u8] = &[
        0x12, 0x34, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x11, // Length
        0x00, // Unit ID
        0x17, // Function code
        0x00, 0x03, // Read Starting Address
        0x00, 0x06, // Quantity to Read
        0x00, 0x0E, // Write Starting Address
        0x00, 0x03, // Quantity to Write
        0x06, // Write Byte count
        0x12, 0x34, // Write Registers Value
        0x56, 0x78, 0x9A, 0xBC,
    ];

    #[test]
    fn test_modbus_request_read_write_multi_register() {
        match modbus_parse_request(&RD_WR_MULT_REG_REQ) {
            Ok((rem, request)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(request.header, MBAPHeader {
                    transaction_id: 0x1234,
                    protocol_id: 0x0000,
                    length: 0x0011,
                    unit_id: 0x00,
                });
                assert_eq!(request.pdu, MBAP_Request_PDU {
                    function_code: 0x17,
                    data: ModbusRequestData::READ_WRITE_MULTI_REG(ReadWriteMultiRegRequest {
                        read_start_address: 0x0003,
                        read_quantity: 0x0006,
                        write_start_address: 0x000E,
                        write_quantity: 0x0003,
                        write_register_value: vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
                    })
                });
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }

    const RD_COILS_RESP: &[u8] = &[
        0x00, 0x00, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x01, // Function code
        0x03, // Byte count
        0xCD, 0x6B, 0x05, // Coil Status
    ];

    #[test]
    fn test_modbus_response_read_coils() {
        match modbus_parse_response(&RD_COILS_RESP) {
            Ok((rem, response)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(response.header, MBAPHeader {
                    transaction_id: 0x0000,
                    protocol_id: 0x0000,
                    length: 0x0006,
                    unit_id: 0x00,
                });
                assert_eq!(response.pdu, MBAP_Response_PDU {
                    function_code: 0x01,
                    data: ModbusResponseData::READ_COIL(CoilResponse {
                        coil_status: vec![0xCD, 0x6B, 0x05],
                    })
                });
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }

    const WR_SINGLE_REG_RESP: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x06, // Function code
        0x00, 0x01, // Register Address
        0x00, 0x03, // Register Value
    ];
    #[test]
    fn test_modbus_response_write_single_register() {
        match modbus_parse_response(&WR_SINGLE_REG_RESP) {
            Ok((rem, response)) => {
                assert_eq!(rem.len() , 0);
                assert_eq!(response.header, MBAPHeader {
                    transaction_id: 0x000A,
                    protocol_id: 0x0000,
                    length: 0x0006,
                    unit_id: 0x00,
                });
                assert_eq!(response.pdu, MBAP_Response_PDU {
                    function_code: 0x06,
                    data: ModbusResponseData::WRITE_SINGLE_REG(WriteSingleRegResponse {
                        register_address: 0x0001,
                        register_value: 0x0003,
                    })
                });
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }

    const WR_MULT_REG_RESP: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0x00, // Unit ID
        0x10, // Function code
        0x00, 0x01, // Starting Address
        0x00, 0x02, // Quantity of Registers
    ];
    #[test]
    fn test_modbus_response_write_multi_register() {
        match modbus_parse_response(&WR_MULT_REG_RESP) {
            Ok((rem, response)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(response.header, MBAPHeader {
                    transaction_id: 0x000A,
                    protocol_id: 0x0000,
                    length: 0x0006,
                    unit_id: 0x00,
                });
                assert_eq!(response.pdu, MBAP_Response_PDU {
                    function_code: 0x10,
                    data: ModbusResponseData::WRITE_MULTI_REG(WriteMultiRegResponse {
                        start_address: 0x0001,
                        quantity: 0x0002,
                    })
                });
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }

    const MASK_WR_REG_RESP: &[u8] = &[
        0x00, 0x0A, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x08, // Length
        0x00, // Unit ID
        0x16, // Function code
        0x00, 0x04, // Reference Address
        0x00, 0xF2, // And_Mask
        0x00, 0x25, // Or_Mask
    ];
    #[test]
    fn test_modbus_response_mask_write_register() {
        match modbus_parse_response(&MASK_WR_REG_RESP) {
            Ok((rem, response)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(response.header, MBAPHeader {
                    transaction_id: 0x000A,
                    protocol_id: 0x0000,
                    length: 0x0008,
                    unit_id: 0x00,
                });
                assert_eq!(response.pdu, MBAP_Response_PDU {
                    function_code: 0x16,
                    data: ModbusResponseData::MASK_WRITE_REG(MaskWriteRegResponse {
                        reference_address: 0x00004,
                        and_mask: 0x00F2,
                        or_mask: 0x0025,
                    })
                });
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }

    const RD_WR_MULT_REG_RESP: &[u8] = &[
        0x12, 0x34, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x0E, // Length
        0x00, // Unit ID
        0x17, // Function code
        0x0B, // Byte count
        0x00, 0xFE, // Read Registers Value
        0x0A, 0xCD, 0x00, 0x01, 0x00, 0x03, 0x00, 0x0D, 0x00,
    ];
    #[test]
    fn test_modbus_response_read_write_multi_register() {
        match modbus_parse_response(&RD_WR_MULT_REG_RESP) {
            Ok((rem, response)) => {
                assert_eq!(rem.len(), 0);
                assert_eq!(response.header, MBAPHeader {
                    transaction_id: 0x1234,
                    protocol_id: 0x0000,
                    length: 0x000E,
                    unit_id: 0x00,
                });
                assert_eq!(response.pdu, MBAP_Response_PDU {
                    function_code: 0x17,
                    data: ModbusResponseData::READ_WRITE_MULTI_REG(ReadWriteMultiRegResponse {
                        read_registers_value: vec![0x00, 0xFE, 0x0A, 0xCD, 0x00, 0x01, 0x00, 0x03, 0x00, 0x0D, 0x00],
                    })
                });
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}