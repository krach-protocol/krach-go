extern crate serde;
extern crate serde_cbor;

use serde::{Deserialize, Serialize};
use std::vec::Vec;

#[derive(Debug)]
pub struct Error {
  code: ErrorCode,
}

#[derive(Debug)]
pub enum ErrorCode {
  Serialization(serde_cbor::error::Error),
  Signature,
}

impl From<serde_cbor::error::Error> for Error {
  fn from(err: serde_cbor::error::Error) -> Error {
    Error {
      code: ErrorCode::Serialization(err),
    }
  }
}

type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Certificate {
  pub serial_number: u64,
  pub issuer: String,
  pub validity: Validity,
  pub subject: String,
  pub public_key: Vec<u8>,
  pub extensions: Vec<Extension>,
  pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Validity {
  pub not_before: u64,
  pub not_after: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Extension {
  pub oid: u64,
  pub critical: bool,
  pub value: Vec<u8>,
}

impl Certificate {
  pub fn new<'a>(
    serial_number: u64,
    issuer: &'a str,
    validity: Validity,
    subject: &'a str,
    pub_key: &'a [u8],
    extensions: Vec<Extension>,
    signature: &'a [u8],
  ) -> Self {
    Certificate {
      serial_number,
      issuer: issuer.to_owned(),
      validity,
      subject: subject.to_owned(),
      public_key: pub_key.to_vec(),
      extensions,
      signature: signature.to_vec(),
    }
  }
}

pub fn to_vec(cert: &Certificate) -> Result<Vec<u8>> {
  let res_vec = serde_cbor::to_vec(cert)?;
  Ok(res_vec)
}

#[cfg(test)]
mod tests {

  use super::*;

  #[test]
  fn certificate_serialize() {
    let pub_key: &[u8] = &[0, 1, 2, 3];
    let signature: &[u8] = &[4, 5, 6, 7];
    let extensions: Vec<Extension> = vec![];

    let cert = Certificate::new(
      12,
      "fooissuer",
      Validity {
        not_after: 13,
        not_before: 2,
      },
      "barsubject",
      &pub_key,
      extensions,
      &signature,
    );

    let res = to_vec(&cert);
    assert!(!res.is_err());
  }

  static EXPECTED_CERT_BYTES: &[u8] = &[
    0x87, 0x0c, 0x67, 0x63, 0x6f, 0x6e, 0x6e, 0x63, 0x74, 0x64, 0x82, 0x1a, 0x5c, 0xd2, 0x0e, 0xa6,
    0x1a, 0x5c, 0xd3, 0x60, 0x26, 0x66, 0x64, 0x65, 0x05, 0x80, 0x43, 0x55, 0x42, 0x07,
  ];
  #[test]
  fn correct_format() {
    let pub_key: &[u8] = &[0x00, 0x42, 0x23, 0x05];
    let signature: &[u8] = &[0x55, 0x42, 0x07];
    let extensions: Vec<Extension> = vec![];

    let cert = Certificate::new(
      12,
      "connctd",
      Validity {
        not_after: 1_557_356_582,
        not_before: 1_557_270_182,
      },
      "device",
      pub_key,
      extensions,
      signature,
    );

    let res = to_vec(&cert);
    assert!(!res.is_err());
  }
}
