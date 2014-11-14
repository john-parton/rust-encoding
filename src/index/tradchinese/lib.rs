// This is a part of rust-encoding.
//
// Any copyright is dedicated to the Public Domain.
// https://creativecommons.org/publicdomain/zero/1.0/

//! Traditional Chinese index tables for
//! [rust-encoding](https://github.com/lifthrasiir/rust-encoding).

#![feature(phase)]

#[cfg(test)]
#[phase(plugin)]
extern crate encoding_index_tests;

/// Big5 and HKSCS.
///
/// From the Encoding Standard:
///
/// > This matches the Big5 standard
/// > in combination with the Hong Kong Supplementary Character Set and other common extensions.
#[stable] pub mod big5;

