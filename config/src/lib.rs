mod node;
pub use node::*;

mod error;
pub use error::*;

mod io;
pub use io::*;

mod gen;
pub use gen::*;

pub(crate) mod cert;

fn is_valid_replica(r: types::Replica, n: usize) -> bool {
    n > r as usize
}

pub const INITIAL_PVSS_BUFFER: usize = 10;