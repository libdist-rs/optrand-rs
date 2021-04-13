mod node;
pub use node::*;

mod error;
pub use error::*;

mod io;
pub use io::*;

fn is_valid_replica(r: types::Replica, n: usize) -> bool {
    n > r as usize
}
