pub mod proto;

use tokio_util::codec::LengthDelimitedCodec;

#[derive(Debug)]
pub struct EnCodec(pub LengthDelimitedCodec);

impl EnCodec {
    pub fn new() -> Self {
        EnCodec(LengthDelimitedCodec::new())
    }
}

impl std::clone::Clone for EnCodec {
    fn clone(&self) -> Self {
        EnCodec::new()
    }
}
