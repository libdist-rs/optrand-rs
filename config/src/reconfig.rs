use types::{Result, error::Error};
use serde::{Deserialize, Serialize};
use fnv::FnvHashMap as HashMap;
use types::{DbsContext, Replica};
use crypto_lib::Algorithm;

#[derive(Serialize, Deserialize, Clone)]
pub struct Reconfig {
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

    /// PVSS configs - Contains the generators, pvss public keys, pvss secret keys, etc.
    pub pvss_ctx: DbsContext,

    // Beacon data structures

    /// OpenSSL Certificate Details
    pub my_cert: Vec<u8>,
    pub my_cert_key: Vec<u8>,
    pub root_cert: Vec<u8>,

    // Caches
    my_ip_addr: String,
    pk_map_internal: HashMap<Replica, Vec<u8>>,
    secret_key_bytes_internal: Vec<u8>,
}

impl Reconfig {
    /// Return a new fresh config instance
    /// The defaults are: ED25519 crypto, 50ms delta, id is 0, empty maps and vectors, f is 0, n is 0 (so that is_valid fails)
    pub fn new(sk_bytes: Vec<u8>, dbs_ctx:DbsContext) -> Self {
        Self {
            crypto_alg: crypto_lib::Algorithm::ED25519,
            delta: 50,
            pvss_ctx: dbs_ctx,
            num_nodes: 1,
            id: usize::default(),
            net_map: HashMap::default(),
            num_faults: usize::default(),
            pk_map_internal: HashMap::default(),
            secret_key_bytes_internal: sk_bytes,
            my_ip_addr: String::default(),
            my_cert:Vec::default(),
            root_cert:Vec::default(),
            my_cert_key:Vec::default(),
        }
    }

    /// set public key map data (bytes) - Only to be used when generating configs
    pub fn set_pk_map_data(&mut self, mut map: HashMap<Replica, Vec<u8>>) {
        std::mem::swap(&mut self.pk_map_internal, &mut map);
    }

    /// Init intializes all the caches such as my_ip, etc
    pub fn init(mut self) -> Self {
        self.pvss_ctx.init(&mut crypto::std_rng());
        self
    }

    /// Returns a copy of the secret key (KEYPAIR) in this config
    pub fn get_secret_key(&self) -> crypto_lib::Keypair {
        let sk = 
        crypto_lib::ed25519::Keypair::decode(&mut self.secret_key_bytes_internal.clone())
            .expect("Failed to recover secret key from config");
        crypto_lib::Keypair::Ed25519(sk)
    }

    /// Returns the public key map from this config
    pub fn get_public_key_map(&self) -> HashMap<Replica, crypto_lib::PublicKey> {
        let mut map = HashMap::default();
        for (id, pk_data) in &self.pk_map_internal {
            let pk = match self.crypto_alg {
                crypto_lib::Algorithm::ED25519 => {
                    let kp = crypto_lib::ed25519::PublicKey::decode(pk_data)
                        .expect("Failed to decode the secret key from the config");
                    crypto_lib::PublicKey::Ed25519(kp)
                }
                _ => panic!("Unimplemented algorithm"),
            };
            map.insert(*id, pk);
        }
        map
    }

    /// Checks if the config is valid
    ///
    /// Called when loading a fresh config or checking when generating a new config
    pub fn validate(&self) -> Result<()> {
        // a valid config has n > 2f or 2f < n
        if 2 * self.num_faults >= self.num_nodes {
            return Err(Error::ParseIncorrectFaults(self.num_faults, self.num_nodes));
        }
        // I hope there are n IP addresses
        if self.net_map.len() < self.num_nodes {
            return Err(Error::ParseInvalidMapLen(self.num_nodes,self.net_map.len()));
        }
        // We check if every element is a valid id, i.e., < n
        // Since we are using a hash_map if there are n valid elements then there must be n unique elements
        // for repl in &self.net_map {
        //     if !is_valid_replica(*repl.0, self.num_nodes) {
        //         return Err(Error::ParseInvalidMapEntry(*repl.0));
        //     }
        // }
        match self.crypto_alg {
            Algorithm::ED25519 => {
                for repl in &self.pk_map_internal {
                    // if !is_valid_replica(*repl.0, self.num_nodes) {
                    //     return Err(Error::ParseInvalidMapEntry(*repl.0));
                    // }
                    if repl.1.len() != crypto_lib::ED25519_PK_SIZE {
                        return Err(Error::ParseInvalidPkSize(repl.1.len()));
                    }
                }
                if self.secret_key_bytes_internal.len() != crypto_lib::ED25519_PVT_SIZE {
                    return Err(Error::ParseInvalidSkSize(self.secret_key_bytes_internal.len()));
                }
            }
            // Intentionally disabled for performance
            Algorithm::SECP256K1 => {
                // Because unimplemented
                return Err(Error::ParseUnimplemented("SECP256k1"));
            }
            Algorithm::RSA => {
                // Because unimplemented
                return Err(Error::ParseUnimplemented("RSA"));
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

    /// DEPRECATED.
    /// FIX for a Bug in libchatter-rs where u16 is used for Replica
    #[deprecated]
    pub fn net_map(&self) -> HashMap<u16, String> {
        let mut map = HashMap::default();
        for (k,v) in &self.net_map {
            map.insert(*k as u16, v.clone());
        }
        map
    }
}

