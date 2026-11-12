//! Owner-authorized membership and configuration. Content encryption is not implemented yet.
//!
//! An anchor and checkpoint must come from trusted local storage or an authenticated
//! pairing channel. A relay-provided anchor or rollback of local storage defeats the
//! trust boundary. Do not upload these plaintext records to a routing service.
mod authority;

pub use authority::*;
