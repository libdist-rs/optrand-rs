use super::{is_valid_replica, ParseError};
use crypto::{AggregatePVSS, DbsContext};
use serde::{Deserialize, Serialize};
use fnv::FnvHashMap as HashMap;
use types::Replica;
use crypto_lib::Algorithm;

#[derive(Serialize, Deserialize, Clone)]
pub struct Node {
    /// Network config - Mapping between node ID and the IP address
    pub net_map: HashMap<Replica, String>,

    // Synchronous protocol details
    /// Delta - Synchrony Worst case delay parameter
    pub delta: u64,
    /// Id of the node between 0 to n-1
    pub id: Replica,
    /// n - the number of nodes
    pub num_nodes: usize,
    /// f - the number of faults tolerated by the system
    /// 0 <= f <= (n-1)/2
    pub num_faults: usize,

    // Authentication primitives
    pub crypto_alg: crypto_lib::Algorithm,
    #[serde(skip)]
    pub pk_map: HashMap<Replica, crypto_lib::PublicKey>,
    #[serde(skip)]
    pub secret_key: Option<crypto_lib::ed25519::SecretKey>,

    /// PVSS configs - Contains the generators, pvss public keys, pvss secret keys, etc.
    pub pvss_ctx: DbsContext,

    // Beacon data structures
    /// Rand_beacon_queue contains shares for already finished sharings
    /// In the paper this is referred to as Q
    /// Q[node id] is the actual queue
    /// Initialized with n aggregate sharings
    pub rand_beacon_queue: HashMap<Replica, std::collections::VecDeque<AggregatePVSS>>,

    // Caches
    my_ip_addr: String,
    pk_map_internal: HashMap<Replica, Vec<u8>>,
    secret_key_bytes_internal: Vec<u8>,
}

impl Node {
    /// Return a new fresh config instance
    /// The defaults are: ED25519 crypto, 50ms delta, id is 0, empty maps and vectors, f is 0, n is 0 (so that is_valid fails)
    pub fn new(sk_bytes: Vec<u8>, dbs_ctx:DbsContext) -> Node {
        Node {
            crypto_alg: crypto_lib::Algorithm::ED25519,
            delta: 50,
            id: 0,
            net_map: HashMap::default(),
            num_faults: 0,
            num_nodes: 1,
            pk_map: HashMap::default(),
            pk_map_internal: HashMap::default(),
            secret_key: None,
            secret_key_bytes_internal: sk_bytes,
            rand_beacon_queue: HashMap::default(),
            my_ip_addr: String::new(),
            pvss_ctx: dbs_ctx,
        }
    }

    /// set public key map data (bytes) - Only to be used when generating configs
    pub fn set_pk_map_data(&mut self, map: HashMap<Replica, Vec<u8>>) {
        self.pk_map_internal = map;
    }

    /// Init intializes all the caches such as my_ip, etc
    pub fn init(mut self) -> Self {
        self.my_ip_addr = self.net_map.get(&self.id)
            .expect("Attempted to init a config without assigning an IP to self")
            .clone();
        for (i,pk) in self.pk_map_internal.iter() {
            let pkey = crypto_lib::ed25519::PublicKey::decode(&pk)
                .expect("Failed to decode ED25519 public key");

            self.pk_map.insert(*i, crypto_lib::PublicKey::Ed25519(pkey));
        }
        self.secret_key = Some(
            crypto_lib::ed25519::SecretKey::from_bytes(
                self.secret_key_bytes_internal.clone()
            ).expect("Failed to extract secret key"));
        self.pvss_ctx = self.pvss_ctx.init(&mut crypto::std_rng());
        self
    }

    /// Checks if the config is valid
    ///
    /// Called when loading a fresh config or checking when generating a new config
    pub fn validate(&self) -> Result<(), ParseError> {
        // a valid config has n > 2f or 2f < n
        if 2 * self.num_faults >= self.num_nodes {
            return Err(ParseError::IncorrectFaults(self.num_faults, self.num_nodes));
        }
        // I hope there are n IP addresses
        if self.net_map.len() != self.num_nodes {
            return Err(ParseError::InvalidMapLen(
                self.num_nodes,
                self.net_map.len(),
            ));
        }
        // We check if every element is a valid id, i.e., < n
        // Since we are using a hash_map if there are n valid elements then there must be n unique elements
        for repl in &self.net_map {
            if !is_valid_replica(*repl.0, self.num_nodes) {
                return Err(ParseError::InvalidMapEntry(*repl.0));
            }
        }
        match self.crypto_alg {
            Algorithm::ED25519 => {
                for repl in &self.pk_map_internal {
                    if !is_valid_replica(*repl.0, self.num_nodes) {
                        return Err(ParseError::InvalidMapEntry(*repl.0));
                    }
                    if repl.1.len() != crypto_lib::ED25519_PK_SIZE {
                        return Err(ParseError::InvalidPkSize(repl.1.len()));
                    }
                }
                if self.secret_key_bytes_internal.len() != crypto_lib::ED25519_PVT_SIZE {
                    return Err(ParseError::InvalidSkSize(self.secret_key_bytes_internal.len()));
                }
            }
            // Intentionally disabled for performance
            Algorithm::SECP256K1 => {
                // Because unimplemented
                return Err(ParseError::Unimplemented("SECP256k1"));
            }
            Algorithm::RSA => {
                // Because unimplemented
                return Err(ParseError::Unimplemented("RSA"));
            }
        }
        Ok(())
    }

    /// A helper function to get my_ip
    /// OPTIMIZATION - Can be cached
    pub fn my_ip(&self) -> String {
        // Small strings, so it is okay to clone
        self.my_ip_addr.clone()
    }
}
