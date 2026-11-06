use std::ops::{Add, Mul, Sub};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Constant-time multiplication in GF(2^8)
///
/// Implements the Russian Peasant Multiplication algorithm using branchless
/// bitmasking to resist timing side-channel attacks.
#[inline]
fn gf256_multiply_const_time(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        let bit_b = Choice::from(b & 1);
        p ^= u8::conditional_select(&0, &a, bit_b);
        let carry = Choice::from((a >> 7) & 1);
        a = (a << 1) ^ u8::conditional_select(&0, &0x1b, carry);
        b >>= 1;
    }
    p
}

/// Constant-time inverse calculation in GF(2^8)
///
/// Uses Fermat's Little Theorem: a^(p-2) = a^254 in GF(2^8).
/// Evaluated via a fixed-length straight-line addition chain with zero data-dependent branches.
#[inline]
fn gf256_inverse_const_time(a: u8) -> u8 {
    // Fixed addition chain for a^254 (11 multiplications, straight line)
    let a2 = gf256_multiply_const_time(a, a);
    let a3 = gf256_multiply_const_time(a2, a);
    let a6 = gf256_multiply_const_time(a3, a3);
    let a12 = gf256_multiply_const_time(a6, a6);
    let a14 = gf256_multiply_const_time(a12, a2);
    let a15 = gf256_multiply_const_time(a14, a);
    let a30 = gf256_multiply_const_time(a15, a15);
    let a60 = gf256_multiply_const_time(a30, a30);
    let a120 = gf256_multiply_const_time(a60, a60);
    let a240 = gf256_multiply_const_time(a120, a120);
    gf256_multiply_const_time(a240, a14)
}

/// Galois Field (GF(256)) arithmetic implementation
///
/// Represents elements in GF(2^8) using irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
///
/// # Example
/// ```
/// use shamir_share::FiniteField;
///
/// let a = FiniteField::new(0x53);
/// let b = FiniteField::new(0xCA);
/// let sum = a + b;  // XOR operation
/// let product = a * b;  // Carryless multiplication
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize))]
pub struct FiniteField(pub u8);

impl FiniteField {
    /// Creates a new finite field element
    ///
    /// # Example
    /// ```
    /// use shamir_share::FiniteField;
    ///
    /// let element = FiniteField::new(0xAB);
    /// assert_eq!(element.0, 0xAB);
    /// ```
    #[inline]
    pub fn new(value: u8) -> Self {
        Self(value)
    }

    /// Performs multiplication in GF(256) using a constant-time algorithm
    /// to prevent timing side-channel attacks.
    ///
    /// This implements the Russian Peasant Multiplication algorithm which is
    /// constant-time and resistant to side-channel attacks.
    ///
    /// # Example
    /// ```
    /// use shamir_share::FiniteField;
    ///
    /// let a = FiniteField::new(0x53);
    /// let b = FiniteField::new(0xCA);
    /// assert_eq!(a.multiply(b), FiniteField::new(0x01));
    /// ```
    #[inline]
    pub fn multiply(self, other: Self) -> Self {
        Self(gf256_multiply_const_time(self.0, other.0))
    }

    /// Computes exponentiation in GF(256) using a branchless square-and-multiply algorithm
    ///
    /// # Example
    /// ```
    /// use shamir_share::FiniteField;
    ///
    /// let base = FiniteField::new(0x03);
    /// assert_eq!(base.exp(3), base * base * base);
    /// ```
    #[inline]
    pub fn exp(self, mut exp: u32) -> Self {
        let mut result = FiniteField::new(1);
        let mut base = self;
        for _ in 0..32 {
            let bit = Choice::from((exp & 1) as u8);
            let mult = result.multiply(base);
            result = Self(u8::conditional_select(&result.0, &mult.0, bit));
            base = base.multiply(base);
            exp >>= 1;
        }
        result
    }

    /// Computes multiplicative inverse in constant time, returning a [`subtle::CtOption`].
    ///
    /// Uses Fermat's Little Theorem: a^(p-2) = a^254 in GF(2^8).
    /// The returned `CtOption` is `None` for zero (which has no inverse).
    #[inline]
    pub fn ct_inverse(self) -> subtle::CtOption<Self> {
        let inv = Self(gf256_inverse_const_time(self.0));
        let is_non_zero = !self.0.ct_eq(&0);
        subtle::CtOption::new(inv, is_non_zero)
    }

    /// Computes multiplicative inverse using a constant-time algorithm
    /// to prevent timing side-channel attacks.
    ///
    /// Uses Fermat's Little Theorem: a^(p-2) = a^254 in GF(2^8)
    /// Returns None for zero (which has no inverse)
    ///
    /// # Example
    /// ```
    /// use shamir_share::FiniteField;
    ///
    /// let a = FiniteField::new(0x53);
    /// let inv = a.inverse().unwrap();
    /// assert_eq!(a * inv, FiniteField::new(0x01));
    /// ```
    #[inline]
    pub fn inverse(self) -> Option<Self> {
        Option::from(self.ct_inverse())
    }
}

impl ConstantTimeEq for FiniteField {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for FiniteField {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u8::conditional_select(&a.0, &b.0, choice))
    }
}

/// Implements addition as XOR in GF(2^8)
impl Add for FiniteField {
    type Output = Self;
    #[inline]
    fn add(self, other: Self) -> Self {
        // In GF(2^8), addition is XOR
        #[allow(clippy::suspicious_arithmetic_impl)]
        let result = self.0 ^ other.0;
        Self(result)
    }
}

/// Implements subtraction as XOR in GF(2^8)
impl Sub for FiniteField {
    type Output = Self;
    #[inline]
    fn sub(self, other: Self) -> Self {
        // In GF(2^8), subtraction is the same as addition (XOR)
        self.add(other)
    }
}

/// Implements multiplication in GF(2^8)
impl Mul for FiniteField {
    type Output = Self;
    #[inline]
    fn mul(self, other: Self) -> Self {
        self.multiply(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addition() {
        let a = FiniteField::new(0x53);
        let b = FiniteField::new(0xCA);
        assert_eq!((a + b).0, 0x99);
    }

    #[test]
    fn test_subtraction() {
        let a = FiniteField::new(0x53);
        let b = FiniteField::new(0xCA);
        assert_eq!((a - b).0, (a + b).0);
    }

    #[test]
    fn test_multiplication() {
        let a = FiniteField::new(0x53);
        let b = FiniteField::new(0xCA);
        assert_eq!((a * b).0, 0x1);
    }

    #[test]
    fn test_inverse() {
        let a = FiniteField::new(0x53);
        let inv = a.inverse().unwrap();
        assert_eq!((a * inv).0, 0x01);
    }

    #[test]
    fn test_zero_inverse() {
        let zero = FiniteField::new(0);
        assert_eq!(zero.inverse(), None);
    }

    #[test]
    fn test_multiplication_associativity() {
        let a = FiniteField::new(0x53);
        let b = FiniteField::new(0xCA);
        let c = FiniteField::new(0x7B);
        assert_eq!((a * b) * c, a * (b * c));
    }

    #[test]
    fn test_all_inverses() {
        for i in 1..=255 {
            let a = FiniteField::new(i);
            let inv = a.inverse().unwrap();
            assert_eq!((a * inv).0, 0x01);
        }
    }

    #[test]
    fn test_specific_inverses() {
        let test_values = [(0x53, 0xCA), (0x7B, 0x06), (0xA4, 0x8F), (0xE1, 0x0D)];

        for &(a, expected_inv) in &test_values {
            let field_a = FiniteField::new(a);
            let inv = field_a.inverse().unwrap();
            assert_eq!(inv.0, expected_inv, "Inverse mismatch for 0x{:02X}", a);
            assert_eq!((field_a * inv).0, 0x01);
        }
    }

    #[test]
    fn test_commutativity() {
        let a = FiniteField::new(0x53);
        let b = FiniteField::new(0xCA);
        assert_eq!(a * b, b * a);
    }

    #[test]
    fn test_distributivity() {
        let a = FiniteField::new(0x53);
        let b = FiniteField::new(0xCA);
        let c = FiniteField::new(0x7B);
        assert_eq!(a * (b + c), (a * b) + (a * c));
    }

    #[test]
    fn test_exp() {
        let a = FiniteField::new(0x03);
        assert_eq!(a.exp(0), FiniteField::new(1));
        assert_eq!(a.exp(1), a);
        assert_eq!(a.exp(2), a * a);
        assert_eq!(a.exp(3), a * a * a);
    }
}
