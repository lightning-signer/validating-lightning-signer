use bitcoin::secp256k1::ffi::CPtr;
use bitcoin::secp256k1::schnorrsig::KeyPair;
use bitcoin::secp256k1::{ffi, key, Error, Secp256k1, Verification};
use core::fmt;
use std::ops::BitXor;

pub const SCHNORR_PUBLIC_KEY_SIZE: usize = 32;

/// An x-only public key, used for verification of Schnorr signatures and serialized according to BIP-340.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
/// use secp256k1::{rand, Secp256k1, KeyPair, XOnlyPublicKey};
///
/// let secp = Secp256k1::new();
/// let key_pair = KeyPair::new(&secp, &mut rand::thread_rng());
/// let xonly = XOnlyPublicKey::from_keypair(&key_pair);
/// # }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct XOnlyPublicKey(ffi::XOnlyPublicKey);

impl fmt::LowerHex for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl XOnlyPublicKey {
    /// Obtains a raw const pointer suitable for use with FFI functions.
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::XOnlyPublicKey {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::XOnlyPublicKey {
        &mut self.0
    }

    /// Creates a new Schnorr public key from a Schnorr key pair.
    #[inline]
    pub fn from_keypair(keypair: &KeyPair) -> XOnlyPublicKey {
        let mut pk_parity = 0;
        unsafe {
            let mut xonly_pk = ffi::XOnlyPublicKey::new();
            let ret = ffi::secp256k1_keypair_xonly_pub(
                ffi::secp256k1_context_no_precomp,
                &mut xonly_pk,
                &mut pk_parity,
                keypair.as_ptr(),
            );
            debug_assert_eq!(ret, 1);
            XOnlyPublicKey(xonly_pk)
        }
    }

    /// Creates a Schnorr public key directly from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the length of the data slice is not 32 bytes or the
    /// slice does not represent a valid Secp256k1 point x coordinate.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<XOnlyPublicKey, Error> {
        if data.is_empty() || data.len() != SCHNORR_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidPublicKey);
        }

        unsafe {
            let mut pk = ffi::XOnlyPublicKey::new();
            if ffi::secp256k1_xonly_pubkey_parse(
                ffi::secp256k1_context_no_precomp,
                &mut pk,
                data.as_c_ptr(),
            ) == 1
            {
                Ok(XOnlyPublicKey(pk))
            } else {
                Err(Error::InvalidPublicKey)
            }
        }
    }

    #[inline]
    /// Serializes the key as a byte-encoded x coordinate value (32 bytes).
    pub fn serialize(&self) -> [u8; SCHNORR_PUBLIC_KEY_SIZE] {
        let mut ret = [0u8; SCHNORR_PUBLIC_KEY_SIZE];

        unsafe {
            let err = ffi::secp256k1_xonly_pubkey_serialize(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                self.as_c_ptr(),
            );
            debug_assert_eq!(err, 1);
        }
        ret
    }

    /// Tweaks an x-only PublicKey by adding the generator multiplied with the given tweak to it.
    ///
    /// # Returns
    ///
    /// An opaque type representing the parity of the tweaked key, this should be provided to
    /// `tweak_add_check` which can be used to verify a tweak more efficiently than regenerating
    /// it and checking equality.
    ///
    /// # Errors
    ///
    /// If the resulting key would be invalid or if the tweak was not a 32-byte length slice.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
    /// use secp256k1::{Secp256k1, KeyPair};
    /// use secp256k1::rand::{RngCore, thread_rng};
    ///
    /// let secp = Secp256k1::new();
    /// let mut tweak = [0u8; 32];
    /// thread_rng().fill_bytes(&mut tweak);
    ///
    /// let mut key_pair = KeyPair::new(&secp, &mut thread_rng());
    /// let mut public_key = key_pair.public_key();
    /// public_key.tweak_add_assign(&secp, &tweak).expect("Improbable to fail with a randomly generated tweak");
    /// # }
    /// ```
    pub fn tweak_add_assign<V: Verification>(
        &mut self,
        secp: &Secp256k1<V>,
        tweak: &[u8],
    ) -> Result<Parity, Error> {
        if tweak.len() != 32 {
            return Err(Error::InvalidTweak);
        }

        unsafe {
            let mut pubkey = ffi::PublicKey::new();
            let mut err = ffi::secp256k1_xonly_pubkey_tweak_add(
                *secp.ctx(),
                &mut pubkey,
                self.as_c_ptr(),
                tweak.as_c_ptr(),
            );
            if err != 1 {
                return Err(Error::InvalidTweak);
            }

            let mut parity: bitcoin::secp256k1::secp256k1_sys::types::c_int = 0;
            err = ffi::secp256k1_xonly_pubkey_from_pubkey(
                *secp.ctx(),
                &mut self.0,
                &mut parity,
                &pubkey,
            );
            if err == 0 {
                return Err(Error::InvalidPublicKey);
            }

            Parity::from_i32(parity).map_err(Into::into)
        }
    }

    /// Verifies that a tweak produced by [`XOnlyPublicKey::tweak_add_assign`] was computed correctly.
    ///
    /// Should be called on the original untweaked key. Takes the tweaked key and output parity from
    /// [`XOnlyPublicKey::tweak_add_assign`] as input.
    ///
    /// Currently this is not much more efficient than just recomputing the tweak and checking
    /// equality. However, in future this API will support batch verification, which is
    /// significantly faster, so it is wise to design protocols with this in mind.
    ///
    /// # Returns
    ///
    /// True if tweak and check is successful, false otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "std", feature =  "rand-std"))] {
    /// use secp256k1::{Secp256k1, KeyPair};
    /// use secp256k1::rand::{thread_rng, RngCore};
    ///
    /// let secp = Secp256k1::new();
    /// let mut tweak = [0u8; 32];
    /// thread_rng().fill_bytes(&mut tweak);
    ///
    /// let mut key_pair = KeyPair::new(&secp, &mut thread_rng());
    /// let mut public_key = key_pair.public_key();
    /// let original = public_key;
    /// let parity = public_key.tweak_add_assign(&secp, &tweak).expect("Improbable to fail with a randomly generated tweak");
    /// assert!(original.tweak_add_check(&secp, &public_key, parity, tweak));
    /// # }
    /// ```
    pub fn tweak_add_check<V: Verification>(
        &self,
        secp: &Secp256k1<V>,
        tweaked_key: &Self,
        tweaked_parity: Parity,
        tweak: [u8; 32],
    ) -> bool {
        let tweaked_ser = tweaked_key.serialize();
        unsafe {
            let err = ffi::secp256k1_xonly_pubkey_tweak_add_check(
                *secp.ctx(),
                tweaked_ser.as_c_ptr(),
                tweaked_parity.to_i32(),
                &self.0,
                tweak.as_c_ptr(),
            );

            err == 1
        }
    }
}

/// Represents the parity passed between FFI function calls.
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum Parity {
    /// Even parity.
    Even = 0,
    /// Odd parity.
    Odd = 1,
}

impl Parity {
    /// Converts parity into an integer (byte) value.
    ///
    /// This returns `0` for even parity and `1` for odd parity.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Converts parity into an integer value.
    ///
    /// This returns `0` for even parity and `1` for odd parity.
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    /// Constructs a [`Parity`] from a byte.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_u8(parity: u8) -> Result<Parity, InvalidParityValue> {
        Parity::from_i32(parity.into())
    }

    /// Constructs a [`Parity`] from a signed integer.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_i32(parity: i32) -> Result<Parity, InvalidParityValue> {
        match parity {
            0 => Ok(Parity::Even),
            1 => Ok(Parity::Odd),
            _ => Err(InvalidParityValue(parity)),
        }
    }
}

/// The conversion returns `0` for even parity and `1` for odd.
impl From<Parity> for i32 {
    fn from(parity: Parity) -> i32 {
        parity.to_i32()
    }
}

/// The conversion returns `0` for even parity and `1` for odd.
impl From<Parity> for u8 {
    fn from(parity: Parity) -> u8 {
        parity.to_u8()
    }
}

/// Returns even parity if the operands are equal, odd otherwise.
impl BitXor for Parity {
    type Output = Parity;

    fn bitxor(self, rhs: Parity) -> Self::Output {
        // This works because Parity has only two values (i.e. only 1 bit of information).
        if self == rhs {
            Parity::Even // 1^1==0 and 0^0==0
        } else {
            Parity::Odd // 1^0==1 and 0^1==1
        }
    }
}

/// Error returned when conversion from an integer to `Parity` fails.
//
// Note that we don't allow inspecting the value because we may change the type.
// Yes, this comment is intentionally NOT doc comment.
// Too many derives for compatibility with current Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct InvalidParityValue(i32);

impl fmt::Display for InvalidParityValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid value {} for Parity - must be 0 or 1", self.0)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl ::std::error::Error for InvalidParityValue {}

impl From<InvalidParityValue> for Error {
    fn from(_error: InvalidParityValue) -> Self {
        Error::InvalidPublicKey
    }
}

impl CPtr for XOnlyPublicKey {
    type Target = ffi::XOnlyPublicKey;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

/// Creates a new Schnorr public key from a FFI x-only public key.
impl From<ffi::XOnlyPublicKey> for XOnlyPublicKey {
    #[inline]
    fn from(pk: ffi::XOnlyPublicKey) -> XOnlyPublicKey {
        XOnlyPublicKey(pk)
    }
}

impl From<key::PublicKey> for XOnlyPublicKey {
    fn from(src: key::PublicKey) -> XOnlyPublicKey {
        unsafe {
            let mut pk = ffi::XOnlyPublicKey::new();
            assert_eq!(
                1,
                ffi::secp256k1_xonly_pubkey_from_pubkey(
                    ffi::secp256k1_context_no_precomp,
                    &mut pk,
                    core::ptr::null_mut(),
                    src.as_c_ptr(),
                )
            );
            XOnlyPublicKey(pk)
        }
    }
}
