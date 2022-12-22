use nom7::{error::{ParseError, Error}, IResult, ErrorConvert};

pub fn my_bits<'a, O, E, P>(parser: P) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>
    where
        E: ParseError<&'a [u8]>,
        Error<(&'a [u8], usize)>: ErrorConvert<E>,
        P: FnMut((&'a [u8], usize)) -> IResult<(&'a [u8], usize), O, Error<(&'a [u8], usize)>>,
{
    // use full path to disambiguate nom `bits` from this current function name
    nom7::bits::bits(parser)
}