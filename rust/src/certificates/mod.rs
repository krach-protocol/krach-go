extern crate serde_derive;

use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Validity {
  pub not_before: u64,
  pub not_after: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Extension<'a> {
  pub oid: u64,
  pub critical: bool,
  pub value: &'a [u8],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Certificate<'a> {
  pub serial_number: u64,
  pub issuer: &'a str,
  pub validity: Validity,
  pub subject: &'a str,
  pub public_key: &'a [u8],
  //pub extensions: &'a [Extension<'a>],
  pub signature: &'a [u8],
}
