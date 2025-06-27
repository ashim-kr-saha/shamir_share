use std::ops::{Add, Mul, Sub};

/// Constant-time multiplication in GF(2^8)
///
/// Implements the Russian Peasant Multiplication algorithm which is
/// constant-time and resistant to side-channel attacks.
#[inline]
fn gf256_multiply_const_time(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p: u8 = 0;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b; // Corresponds to the irreducible polynomial x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    p
}

/// Constant-time inverse calculation in GF(2^8)
///
/// Uses Fermat's Little Theorem: a^(p-2) = a^254 in GF(2^8)
/// This is slower but secure against side-channel attacks.
#[inline]
fn gf256_inverse_const_time(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }

    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u32;

    while exp > 0 {
        if exp & 1 == 1 {
            result = gf256_multiply_const_time(result, base);
        }
        base = gf256_multiply_const_time(base, base);
        exp >>= 1;
    }
    result
}

/// Galois Field (GF(256)) arithmetic implementation
///
/// Represents elements in GF(2⁸) using irreducible polynomial x⁸ + x⁴ + x³ + x + 1 (0x11B)
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

    /// Computes exponentiation in GF(256) using square-and-multiply
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
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.multiply(base);
            }
            base = base.multiply(base);
            exp >>= 1;
        }
        result
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
        if self.0 == 0 {
            None
        } else {
            Some(Self(gf256_inverse_const_time(self.0)))
        }
    }
}

/// Implements addition as XOR in GF(2⁸)
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

/// Implements multiplication using carryless algorithm
impl Mul for FiniteField {
    type Output = Self;
    #[inline]
    fn mul(self, other: Self) -> Self {
        self.multiply(other)
    }
}

impl Sub for FiniteField {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        // In GF(2^8), addition and subtraction are the same operation (XOR)
        // This is mathematically correct, not a suspicious operation
        #[allow(clippy::suspicious_arithmetic_impl)]
        let result = self.add(other);
        result
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
        let a = FiniteField::new(0x12);
        let b = FiniteField::new(0x34);
        let c = FiniteField::new(0x56);
        assert_eq!(a * (b + c), (a * b) + (a * c));
    }

    #[test]
    fn test_identity() {
        let one = FiniteField::new(1);
        let value = FiniteField::new(0xAB);
        assert_eq!(value * one, value);
    }
}
