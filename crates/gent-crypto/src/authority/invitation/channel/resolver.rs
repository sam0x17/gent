//! Thin Snow adapters for the workspace's RNG and maintained X25519 primitive.
//! Snow supplies the Noise state machine, SHA-256, and ChaChaPoly implementation.
use snow::{
    Error,
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub(super) struct Resolver;
impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(SystemRandom))
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match choice {
            DHChoice::Curve25519 => Some(Box::new(Dh25519::new([0; 32]))),
            _ => None,
        }
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
}
struct SystemRandom;
impl Random for SystemRandom {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(dest).map_err(|_| Error::Rng)
    }
}
struct Dh25519 {
    secret: StaticSecret,
    public: PublicKey,
}
impl Dh25519 {
    fn new(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}
impl Dh for Dh25519 {
    fn name(&self) -> &'static str {
        "25519"
    }
    fn pub_len(&self) -> usize {
        32
    }
    fn priv_len(&self) -> usize {
        32
    }
    fn set(&mut self, private: &[u8]) {
        // Snow calls this only with the locally checked 32-byte static key.
        *self = Self::new(private.try_into().expect("X25519 private key length"));
    }
    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        rng.try_fill_bytes(bytes.as_mut())?;
        *self = Self::new(*bytes);
        Ok(())
    }
    fn pubkey(&self) -> &[u8] {
        self.public.as_bytes()
    }
    fn privkey(&self) -> &[u8] {
        self.secret.as_bytes()
    }
    fn dh(&self, public: &[u8], out: &mut [u8]) -> Result<(), Error> {
        // Snow keeps remote keys in a MAXDHLEN scratch array, even for X25519.
        let bytes: [u8; 32] = public
            .get(..32)
            .ok_or(Error::Dh)?
            .try_into()
            .expect("32-byte prefix");
        let shared = self.secret.diffie_hellman(&PublicKey::from(bytes));
        if !shared.was_contributory() || out.len() < 32 {
            return Err(Error::Dh);
        }
        out[..32].copy_from_slice(shared.as_bytes());
        Ok(())
    }
}
