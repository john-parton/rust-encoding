// This is a part of rust-encoding.
// Copyright (c) 2013-2015, Kang Seonghoon.
// See README.md and LICENSE.txt for details.

//! Common codec implementation for single-byte encodings.

use std::convert::Into;
use util::{as_char, StrCharIndex};
use types::*;

/// A common framework for single-byte encodings based on ASCII.
#[derive(Copy, Clone)]
pub struct SingleByteEncoding {
    pub name: &'static str,
    pub whatwg_name: Option<&'static str>,
    pub index_forward: extern "Rust" fn(u8) -> u16,
    pub index_backward: extern "Rust" fn(u32) -> u8,
}

impl Encoding for SingleByteEncoding {
    fn name(&self) -> &'static str { self.name }
    fn whatwg_name(&self) -> Option<&'static str> { self.whatwg_name }
    fn raw_encoder(&self) -> Box<RawEncoder> { SingleByteEncoder::new(self.index_backward) }
    fn raw_decoder(&self) -> Box<RawDecoder> { SingleByteDecoder::new(self.index_forward) }
}

/// An encoder for single-byte encodings based on ASCII.
#[derive(Clone, Copy)]
pub struct SingleByteEncoder {
    index_backward: extern "Rust" fn(u32) -> u8,
}

impl SingleByteEncoder {
    pub fn new(index_backward: extern "Rust" fn(u32) -> u8) -> Box<RawEncoder> {
        Box::new(SingleByteEncoder { index_backward: index_backward })
    }
}

impl RawEncoder for SingleByteEncoder {
    fn from_self(&self) -> Box<RawEncoder> { SingleByteEncoder::new(self.index_backward) }
    fn is_ascii_compatible(&self) -> bool { true }

    fn raw_feed(&mut self, input: &str, output: &mut ByteWriter) -> (usize, Option<CodecError>) {
        output.writer_hint(input.len());

        for ((i,j), ch) in input.index_iter() {
            if ch <= '\u{7f}' {
                output.write_byte(ch as u8);
                continue;
            } else {
                let index = (self.index_backward)(ch as u32);
                if index != 0 {
                    output.write_byte(index);
                } else {
                    return (i, Some(CodecError {
                        upto: j as isize, cause: "unrepresentable character".into()
                    }));
                }
            }
        }
        (input.len(), None)
    }

    fn raw_finish(&mut self, _output: &mut ByteWriter) -> Option<CodecError> {
        None
    }
}

/// A decoder for single-byte encodings based on ASCII.
#[derive(Clone, Copy)]
pub struct SingleByteDecoder {
    index_forward: extern "Rust" fn(u8) -> u16,
}

impl SingleByteDecoder {
    pub fn new(index_forward: extern "Rust" fn(u8) -> u16) -> Box<RawDecoder> {
        Box::new(SingleByteDecoder { index_forward: index_forward })
    }
}

impl RawDecoder for SingleByteDecoder {
    fn from_self(&self) -> Box<RawDecoder> { SingleByteDecoder::new(self.index_forward) }
    fn is_ascii_compatible(&self) -> bool { true }

    fn raw_feed(&mut self, input: &[u8], output: &mut StringWriter) -> (usize, Option<CodecError>) {
        output.writer_hint(input.len());

        let mut i = 0;
        let len = input.len();
        while i < len {
            if input[i] <= 0x7f {
                output.write_char(input[i] as char);
            } else {
                let ch = (self.index_forward)(input[i]);
                if ch != 0xffff {
                    output.write_char(as_char(ch as u32));
                } else {
                    return (i, Some(CodecError {
                        upto: i as isize + 1, cause: "invalid sequence".into()
                    }));
                }
            }
            i += 1;
        }
        (i, None)
    }

    fn raw_finish(&mut self, _output: &mut StringWriter) -> Option<CodecError> {
        None
    }
}

/// Algorithmic mapping for ISO 8859-1.
pub mod iso_8859_1 {
    #[inline] pub fn forward(code: u8) -> u16 { code as u16 }
    #[inline] pub fn backward(code: u32) -> u8 { if (code & !0x7f) == 0x80 {code as u8} else {0} }
}

#[cfg(test)]
mod tests {
    use crate::all::{ISO_8859_2, ISO_8859_5};
    use crate::all::{WINDOWS_1252};
    use crate::testutils::{ASCII_TEXT, IRISH_TEXT, RUSSIAN_TEXT};
    use crate::types::*;

    #[test]
    fn test_encoder_non_bmp() {
        let mut e = ISO_8859_2.raw_encoder();
        assert_feed_err!(e, "A", "\u{FFFF}", "B", [0x41]);
        assert_feed_err!(e, "A", "\u{10000}", "B", [0x41]);
    }
        
    #[bench]
    fn bench_encode_english(bencher: &mut test::Bencher) {
        bencher.bytes = ASCII_TEXT.len() as u64;
        bencher.iter(|| {
            test::black_box(
                WINDOWS_1252.encode(&ASCII_TEXT, EncoderTrap::Strict)
            )
        })
    }

    #[bench]
    fn bench_decode_english(bencher: &mut test::Bencher) {
        let bytes = WINDOWS_1252.encode(ASCII_TEXT, EncoderTrap::Strict).unwrap();
        
        bencher.bytes = bytes.len() as u64;
        bencher.iter(|| {
            test::black_box(
                WINDOWS_1252.decode(&bytes, DecoderTrap::Strict)
            )
        })
    }

    #[bench]
    fn bench_roundtrip_english(bencher: &mut test::Bencher) {
        bencher.bytes = ASCII_TEXT.len() as u64;
        bencher.iter(|| {
            let bytes = WINDOWS_1252.encode(&ASCII_TEXT, EncoderTrap::Strict).unwrap();
            test::black_box(
                WINDOWS_1252.decode(&bytes, DecoderTrap::Strict)
            )
        })
    }

    #[bench]
    fn bench_encode_irish(bencher: &mut test::Bencher) {
        bencher.bytes = IRISH_TEXT.len() as u64;
        bencher.iter(|| {
            test::black_box(
                WINDOWS_1252.encode(&ASCII_TEXT, EncoderTrap::Strict)
            )
        })
    }

    #[bench]
    fn bench_decode_irish(bencher: &mut test::Bencher) {
        let bytes = WINDOWS_1252.encode(IRISH_TEXT, EncoderTrap::Strict).unwrap();
        
        bencher.bytes = bytes.len() as u64;
        bencher.iter(|| {
            test::black_box(
                WINDOWS_1252.decode(&bytes, DecoderTrap::Strict)
            )
        })
    }

    #[bench]
    fn bench_roundtrip_irish(bencher: &mut test::Bencher) {
        bencher.bytes = IRISH_TEXT.len() as u64;
        bencher.iter(|| {
            let bytes = WINDOWS_1252.encode(&IRISH_TEXT, EncoderTrap::Strict).unwrap();
            test::black_box(
                WINDOWS_1252.decode(&bytes, DecoderTrap::Strict)
            )
        })
    }

    #[bench]
    fn bench_encode_russian(bencher: &mut test::Bencher) {
        bencher.bytes = RUSSIAN_TEXT.len() as u64;
        bencher.iter(|| {
            test::black_box(
                ISO_8859_5.encode(&RUSSIAN_TEXT, EncoderTrap::Strict)
            )
        })
    }

    #[bench]
    fn bench_decode_russian(bencher: &mut test::Bencher) {
        let bytes = ISO_8859_5.encode(RUSSIAN_TEXT, EncoderTrap::Strict).unwrap();
        
        bencher.bytes = bytes.len() as u64;
        bencher.iter(|| {
            test::black_box(
                ISO_8859_5.decode(&bytes, DecoderTrap::Strict)
            )
        })
    }

    #[bench]
    fn bench_roundtrip_russian(bencher: &mut test::Bencher) {
        bencher.bytes = RUSSIAN_TEXT.len() as u64;
        bencher.iter(|| {
            let bytes = ISO_8859_5.encode(&RUSSIAN_TEXT, EncoderTrap::Strict).unwrap();
            test::black_box(
                ISO_8859_5.decode(&bytes, DecoderTrap::Strict)
            )
        })
    }    
}

