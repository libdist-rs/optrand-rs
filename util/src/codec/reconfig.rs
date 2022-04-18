use std::io;

use bytes::BytesMut;
use tokio_util::codec::{Decoder, LengthDelimitedCodec};
use types::ReconfigurationMsg;
use types_upstream::WireReady;


#[derive(Debug)]
pub struct Codec(pub LengthDelimitedCodec);

impl Codec {
    pub fn new() -> Self {
        Codec(LengthDelimitedCodec::new())
    }
}

impl Decoder for Codec {
    type Item = ReconfigurationMsg;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.0.decode(src)? {
            Some(in_data) => Ok(Some(ReconfigurationMsg::from_bytes(&in_data))),
            None => Ok(None),
        }
    }
}

impl std::clone::Clone for Codec {
    fn clone(&self) -> Self {
        Codec::new()
    }
}
