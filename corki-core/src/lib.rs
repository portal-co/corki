#![no_std]

use either::Either;
use kem::{Decapsulate, Encapsulate};
use rand::{CryptoRng, Rng, RngCore};
use slh_dsa::signature::{Keypair, Signer, Verifier, rand_core::CryptoRngCore};
#[doc(hidden)]
pub mod __ {
    pub use core;
    // pub use paste;
}
const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}
const fn max_arr<const N: usize>(a: [usize; N]) -> usize {
    let mut m: usize = 0;
    let mut i: usize = 0;
    while i != N {
        m = max(m, a[i]);
        i += 1;
    }
    return m;
}
macro_rules! key_ty{
    (enum $name:ident ($kind:ident) {$($a:ident [$b:ident] => $v:ty | $k:expr),*}) => {
        // $crate::__::paste::paste!{
            #[derive(Clone)]
            #[non_exhaustive]
            pub enum $name{
                $($a{key: $v}),*
            }
            #[derive(Clone,Copy,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
            #[non_exhaustive]
            pub enum $kind{
                $($a),*
            }
            impl $crate::__::core::fmt::Display for $kind{
                fn fmt(&self, f: &mut $crate::__::core::fmt::Formatter<'_>) -> $crate::__::core::result::Result<(), $crate::__::core::fmt::Error>{
                    match self{
                        $(Self::$a => $crate::__::core::write!(f,$crate::__::core::stringify!($b))),*
                    }
                }
            }
            impl $kind{
                pub const LEN: usize = $name::LEN;
                pub fn len(&self) -> usize{
                    match self{
                        $(Self::$a => $k),*
                    }
                }
                pub fn from_str(a: &str) -> $crate::__::core::option::Option<Self>{
                    $crate::__::core::option::Option::Some(match a{
                        $(a if a == $crate::__::core::stringify!($b) => Self::$a),*,
                        _ => return $crate::__::core::option::Option::None
                    })
                }
            }
            impl $name{
                pub const LEN: usize = $crate::max_arr([$($k),*]);
                pub fn kind(&self) -> $kind{
                    match self{
                        $($name::$a{..} => $kind::$a),*,
                        _ => unsafe{$crate::__::core::hint::unreachable_unchecked()}
                    }
                }
                pub fn render_bytes(&self, target: &mut [u8]){
                    for (b,t) in self.bytes().zip(target.iter_mut()){
                        *t = b
                    }
                }
            }
        // }
    }
}
key_ty!(enum EncryptionKey (EncryptionKeyKind){
    Symmetric [S] => [u8;32] | (32),
    XWing [X] => x_wing::EncapsulationKey | x_wing::ENCAPSULATION_KEY_SIZE
});
key_ty!(enum DecryptionKey (DecryptionKeyKind){
    Symmetric [S] => [u8;32] | (32),
    XWing [X] => x_wing::DecapsulationKey | x_wing::DECAPSULATION_KEY_SIZE
});
key_ty!(enum SigningKey (SigningKeyKind){
    SLHDSA [s] => slh_dsa::SigningKey<slh_dsa::Shake256s> | (<<slh_dsa::Shake256s as slh_dsa::SigningKeyLen>::SkLen as typenum::Unsigned>::USIZE)
});
key_ty!(enum VerificationKey (VerificationKeyKind){
    SLHDSA [s] => slh_dsa::VerifyingKey<slh_dsa::Shake256s> | (<<slh_dsa::Shake256s as slh_dsa::VerifyingKeyLen>::VkLen as typenum::Unsigned>::USIZE)
});
impl Into<EncryptionKey> for &'_ DecryptionKey {
    fn into(self) -> EncryptionKey {
        match self {
            DecryptionKey::Symmetric { key } => EncryptionKey::Symmetric { key: *key },
            DecryptionKey::XWing { key } => EncryptionKey::XWing {
                key: key.encapsulation_key(),
            },
        }
    }
}
impl Into<VerificationKey> for &'_ SigningKey {
    fn into(self) -> VerificationKey {
        match self {
            SigningKey::SLHDSA { key } => VerificationKey::SLHDSA {
                key: key.verifying_key(),
            },
        }
    }
}
impl EncryptionKey {
    pub fn from_bytes(kind: EncryptionKeyKind, bytes: &[u8]) -> Option<Self> {
        match kind {
            EncryptionKeyKind::Symmetric => {
                bytes.try_into().ok().map(|a| Self::Symmetric { key: a })
            }
            EncryptionKeyKind::XWing => {
                bytes
                    .try_into()
                    .ok()
                    .and_then(|a: &[u8; x_wing::ENCAPSULATION_KEY_SIZE]| {
                        Some(Self::XWing {
                            key: a.try_into().ok()?,
                        })
                    })
            }
        }
    }
    pub fn bytes(&self) -> impl Iterator<Item = u8> {
        match self {
            Self::Symmetric { key } => either::Either::Left(key.iter().cloned()),
            Self::XWing { key } => either::Either::Right(key.as_bytes().into_iter()),
        }
    }
    pub fn encapsulate(
        &self,
        mut rng: &mut (dyn CryptoRngCore + '_),
    ) -> ([u8; 32], impl Iterator<Item = u8>) {
        match self {
            Self::XWing { key } => match key.encapsulate(&mut rng).ok().unwrap() {
                (a, b) => (b, Either::Left(a.as_bytes().into_iter())),
            },
            Self::Symmetric { key } => match rng.r#gen::<[u8; 32]>() {
                c => (
                    c,
                    Either::Right(key.iter().cloned().zip(c.into_iter()).map(|(a, b)| a ^ b)),
                ),
            },
        }
    }
}
impl DecryptionKey {
    pub fn decapsulate(&self, i: &mut (dyn Iterator<Item = u8> + '_)) -> Option<[u8; 32]> {
        match self {
            Self::XWing { key } => {
                let mut c = [0u8; x_wing::CIPHERTEXT_SIZE];
                for c in c.iter_mut() {
                    *c = i.next()?;
                }
                let c = x_wing::Ciphertext::from(&c);
                Some(key.decapsulate(&c).unwrap())
            }
            Self::Symmetric { key } => {
                let mut c = [0u8; 32];
                for c in c.iter_mut() {
                    *c = i.next()?;
                }
                for (c, k) in c.iter_mut().zip(key.iter()) {
                    *c ^= *k;
                }
                Some(c)
            }
        }
    }
    pub fn from_bytes(kind: DecryptionKeyKind, bytes: &[u8]) -> Option<Self> {
        match kind {
            DecryptionKeyKind::Symmetric => {
                bytes.try_into().ok().map(|a| Self::Symmetric { key: a })
            }
            DecryptionKeyKind::XWing => {
                bytes
                    .try_into()
                    .ok()
                    .and_then(|a: [u8; x_wing::DECAPSULATION_KEY_SIZE]| {
                        Some(Self::XWing {
                            key: a.try_into().ok()?,
                        })
                    })
            }
        }
    }
    pub fn rand(kind: DecryptionKeyKind, rng: &mut (dyn CryptoRngCore + '_)) -> Self {
        match kind {
            DecryptionKeyKind::Symmetric => Self::Symmetric { key: rng.r#gen() },
            DecryptionKeyKind::XWing => Self::XWing {
                key: x_wing::DecapsulationKey::from(
                    rng.r#gen::<[u8; x_wing::DECAPSULATION_KEY_SIZE]>(),
                ),
            },
        }
    }
    pub fn bytes(&self) -> impl Iterator<Item = u8> {
        match self {
            Self::Symmetric { key } => either::Either::Left(key.iter().cloned()),
            Self::XWing { key } => either::Either::Right(key.as_bytes().iter().cloned()),
        }
    }
}
impl SigningKey {
    pub fn from_bytes(kind: SigningKeyKind, bytes: &[u8]) -> Option<Self> {
        match kind {
            SigningKeyKind::SLHDSA => Some(SigningKey::SLHDSA {
                key: slh_dsa::SigningKey::try_from(bytes).ok()?,
            }),
        }
    }
    pub fn bytes(&self) -> impl Iterator<Item = u8> {
        match self {
            Self::SLHDSA { key } => key.to_bytes().into_iter(),
        }
    }
    pub fn rand(kind: SigningKeyKind, rng: &mut (dyn CryptoRngCore + '_)) -> Self {
        match kind {
            SigningKeyKind::SLHDSA => Self::SLHDSA {
                key: slh_dsa::SigningKey::new(rng),
            },
        }
    }
    pub fn sign(&self, msg: &[u8]) -> impl Iterator<Item = u8> {
        match self {
            Self::SLHDSA { key } => key.sign(msg).to_bytes().into_iter(),
        }
    }
}
impl VerificationKey {
    pub fn from_bytes(kind: VerificationKeyKind, bytes: &[u8]) -> Option<Self> {
        match kind {
            VerificationKeyKind::SLHDSA => Some(VerificationKey::SLHDSA {
                key: slh_dsa::VerifyingKey::try_from(bytes).ok()?,
            }),
        }
    }
    pub fn bytes(&self) -> impl Iterator<Item = u8> {
        match self {
            Self::SLHDSA { key } => key.to_bytes().into_iter(),
        }
    }
    pub fn verify(&self, msg: &[u8], sig: &mut (dyn Iterator<Item = u8> + '_)) -> Option<bool> {
        match self {
            Self::SLHDSA { key } => {
                const LEN: usize = <<slh_dsa::Shake256s as slh_dsa::SignatureLen>::SigLen as typenum::Unsigned>::USIZE;
                let mut c = [0u8; LEN];
                for c in c.iter_mut() {
                    *c = sig.next()?;
                }
                let c = hybrid_array::Array::try_from(c).ok()?;
                let c = slh_dsa::Signature::try_from(&c).ok()?;
                Some(key.verify(msg, &c).is_ok())
            }
        }
    }
}
