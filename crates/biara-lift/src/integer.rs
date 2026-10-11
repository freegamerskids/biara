//! Scalar integer operations for [`crate::calls::Arg`] summaries.
//!
//! [`IntOp::apply`] evaluates one operation on concrete values with strict
//! bit-width semantics: every operand and result is masked to `bits` (valid
//! range `1..=64`). It performs no allocation and never panics on shift
//! amounts; out-of-range shifts that LLVM defines as poison return `None`.

/// Integer operation usable inside `Arg::Expr` summaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum IntOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    LShr,
    AShr,
    Trunc,
    ZExt { from: u32 },
    SExt { from: u32 },
    Fshl,
    Fshr,
}

impl IntOp {
    /// Number of operands this operation takes.
    pub fn arity(self) -> usize {
        match self {
            Self::Add
            | Self::Sub
            | Self::Mul
            | Self::And
            | Self::Or
            | Self::Xor
            | Self::Shl
            | Self::LShr
            | Self::AShr => 2,
            Self::Trunc | Self::ZExt { .. } | Self::SExt { .. } => 1,
            Self::Fshl | Self::Fshr => 3,
        }
    }

    /// Evaluate on concrete values masked to `bits` (`1..=64`).
    ///
    /// `bits` is the operand/result width. For [`IntOp::ZExt`]/[`IntOp::SExt`],
    /// `from` is the source width and must satisfy `1 <= from <= bits <= 64`.
    /// Returns `None` when widths are out of range, the operand count does
    /// not match [`IntOp::arity`], or the operation is poison under LLVM
    /// rules (shift amount `>= bits` for [`IntOp::Shl`], [`IntOp::LShr`] and
    /// [`IntOp::AShr`]).
    ///
    /// Funnel shifts ([`IntOp::Fshl`]/[`IntOp::Fshr`]) follow LLVM
    /// `llvm.fshl`/`llvm.fshr` semantics: the shift amount is taken modulo
    /// `bits`, so large amounts wrap rather than poison. With
    /// `s = c % bits`, `fshl(a, b, c)` is `a` when `s == 0` and
    /// `((a << s) | (b >> (bits - s)))` otherwise. `fshr` returns `b`
    /// when `s == 0`, or `((b >> s) | (a << (bits - s)))` otherwise.
    /// Equal halves give left and right rotations, respectively.
    pub fn apply(self, bits: u32, args: &[u64]) -> Option<u64> {
        if bits == 0 || bits > 64 {
            return None;
        }
        if args.len() != self.arity() {
            return None;
        }
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        match self {
            Self::Add => Some(((args[0] & mask).wrapping_add(args[1] & mask)) & mask),
            Self::Sub => Some(((args[0] & mask).wrapping_sub(args[1] & mask)) & mask),
            Self::Mul => Some(((args[0] & mask).wrapping_mul(args[1] & mask)) & mask),
            Self::And => Some((args[0] & mask) & (args[1] & mask)),
            Self::Or => Some((args[0] & mask) | (args[1] & mask)),
            Self::Xor => Some((args[0] & mask) ^ (args[1] & mask)),
            Self::Shl => {
                let shift = args[1] & mask;
                if shift >= u64::from(bits) {
                    return None;
                }
                Some(((args[0] & mask) << (shift as u32)) & mask)
            }
            Self::LShr => {
                let shift = args[1] & mask;
                if shift >= u64::from(bits) {
                    return None;
                }
                Some((args[0] & mask) >> (shift as u32))
            }
            Self::AShr => {
                let shift = args[1] & mask;
                if shift >= u64::from(bits) {
                    return None;
                }
                let shift = shift as u32;
                let value = args[0] & mask;
                if shift == 0 {
                    return Some(value);
                }
                if bits == 64 {
                    Some(((value as i64).wrapping_shr(shift)) as u64)
                } else {
                    let sign = 1u64 << (bits - 1);
                    let shifted = value >> shift;
                    if value & sign == 0 {
                        Some(shifted)
                    } else {
                        Some(shifted | ((u64::MAX << (bits - shift)) & mask))
                    }
                }
            }
            Self::Trunc => Some(args[0] & mask),
            Self::ZExt { from } => {
                if from == 0 || from > 64 || from > bits {
                    return None;
                }
                let source = if from == 64 {
                    u64::MAX
                } else {
                    (1u64 << from) - 1
                };
                Some(args[0] & source)
            }
            Self::SExt { from } => {
                if from == 0 || from > 64 || from > bits {
                    return None;
                }
                let source = if from == 64 {
                    u64::MAX
                } else {
                    (1u64 << from) - 1
                };
                let value = args[0] & source;
                let sign = 1u64 << (from - 1);
                if value & sign == 0 {
                    Some(value)
                } else {
                    Some(value | (mask & !source))
                }
            }
            Self::Fshl => {
                let shift = ((args[2] & mask) % u64::from(bits)) as u32;
                let a = args[0] & mask;
                let b = args[1] & mask;
                if shift == 0 {
                    Some(a)
                } else {
                    Some(((a << shift) | (b >> (bits - shift))) & mask)
                }
            }
            Self::Fshr => {
                let shift = ((args[2] & mask) % u64::from(bits)) as u32;
                let a = args[0] & mask;
                let b = args[1] & mask;
                if shift == 0 {
                    Some(b)
                } else {
                    Some(((b >> shift) | (a << (bits - shift))) & mask)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::IntOp;

    #[test]
    fn arity_matches_operands() {
        assert_eq!(IntOp::Add.arity(), 2);
        assert_eq!(IntOp::Sub.arity(), 2);
        assert_eq!(IntOp::Mul.arity(), 2);
        assert_eq!(IntOp::And.arity(), 2);
        assert_eq!(IntOp::Or.arity(), 2);
        assert_eq!(IntOp::Xor.arity(), 2);
        assert_eq!(IntOp::Shl.arity(), 2);
        assert_eq!(IntOp::LShr.arity(), 2);
        assert_eq!(IntOp::AShr.arity(), 2);
        assert_eq!(IntOp::Trunc.arity(), 1);
        assert_eq!(IntOp::ZExt { from: 8 }.arity(), 1);
        assert_eq!(IntOp::SExt { from: 8 }.arity(), 1);
        assert_eq!(IntOp::Fshl.arity(), 3);
        assert_eq!(IntOp::Fshr.arity(), 3);
    }

    #[test]
    fn wrapping_narrow_arithmetic() {
        assert_eq!(IntOp::Add.apply(8, &[200, 100]), Some(44));
        assert_eq!(IntOp::Add.apply(8, &[255, 1]), Some(0));
        assert_eq!(IntOp::Sub.apply(8, &[0, 1]), Some(255));
        assert_eq!(IntOp::Mul.apply(8, &[16, 16]), Some(0));
        assert_eq!(IntOp::Mul.apply(8, &[200, 2]), Some(144));
        // High garbage above the width must not leak into the result.
        assert_eq!(IntOp::Add.apply(8, &[0x1_00 | 200, 100]), Some(44));
        assert_eq!(IntOp::And.apply(8, &[0x1ff, 0xff]), Some(0xff));
    }

    #[test]
    fn wrapping_64bit_arithmetic() {
        assert_eq!(IntOp::Add.apply(64, &[u64::MAX, 1]), Some(0));
        assert_eq!(IntOp::Sub.apply(64, &[0, 1]), Some(u64::MAX));
        assert_eq!(
            IntOp::Mul.apply(64, &[u64::MAX, 2]),
            Some(0xffff_ffff_ffff_fffe)
        );
        assert_eq!(IntOp::Xor.apply(64, &[u64::MAX, 1]), Some(u64::MAX - 1));
    }

    #[test]
    fn narrow_logical_shifts() {
        assert_eq!(IntOp::Shl.apply(8, &[0xff, 1]), Some(0xfe));
        assert_eq!(IntOp::Shl.apply(8, &[0x01, 7]), Some(0x80));
        assert_eq!(IntOp::LShr.apply(8, &[0xff, 1]), Some(0x7f));
        assert_eq!(IntOp::LShr.apply(8, &[0x80, 7]), Some(0x01));
        // Shifting in high garbage still masks the value first.
        assert_eq!(IntOp::LShr.apply(8, &[0x1_ff, 7]), Some(0x01));
    }

    #[test]
    fn narrow_arithmetic_shift_sign_extends() {
        // 0xff is -1 as i8; arithmetic shifts keep all ones.
        assert_eq!(IntOp::AShr.apply(8, &[0xff, 1]), Some(0xff));
        assert_eq!(IntOp::AShr.apply(8, &[0xff, 7]), Some(0xff));
        // 0x80 is -128 as i8; >> 1 is -64 (0xc0).
        assert_eq!(IntOp::AShr.apply(8, &[0x80, 1]), Some(0xc0));
        assert_eq!(IntOp::AShr.apply(8, &[0x80, 7]), Some(0xff));
        // Positive values shift in zeros like a logical shift.
        assert_eq!(IntOp::AShr.apply(8, &[0x7f, 1]), Some(0x3f));
        // 32-bit -2^31 >> 31 is -1.
        assert_eq!(IntOp::AShr.apply(32, &[0x8000_0000, 31]), Some(0xffff_ffff));
        assert_eq!(IntOp::AShr.apply(32, &[0x8000_0000, 1]), Some(0xc000_0000));
    }

    #[test]
    fn casts_truncate_and_extend() {
        assert_eq!(IntOp::Trunc.apply(8, &[0x1234]), Some(0x34));
        assert_eq!(IntOp::Trunc.apply(64, &[0x1234]), Some(0x1234));
        assert_eq!(IntOp::Trunc.apply(1, &[0b101]), Some(0b1));
        assert_eq!(IntOp::ZExt { from: 8 }.apply(16, &[0xff]), Some(0xff));
        assert_eq!(IntOp::ZExt { from: 8 }.apply(16, &[0x1_ff]), Some(0xff));
        assert_eq!(IntOp::SExt { from: 8 }.apply(16, &[0xff]), Some(0xffff));
        assert_eq!(IntOp::SExt { from: 8 }.apply(16, &[0x7f]), Some(0x7f));
        assert_eq!(
            IntOp::SExt { from: 8 }.apply(64, &[0x80]),
            Some(0xffff_ffff_ffff_ff80)
        );
        // One-bit -1 sign-extends to all ones.
        assert_eq!(IntOp::SExt { from: 1 }.apply(8, &[1]), Some(0xff));
        assert_eq!(IntOp::SExt { from: 1 }.apply(8, &[0]), Some(0x00));
        // Equal widths are a masked identity.
        assert_eq!(IntOp::SExt { from: 16 }.apply(16, &[0xffff]), Some(0xffff));
        assert_eq!(
            IntOp::ZExt { from: 64 }.apply(64, &[u64::MAX]),
            Some(u64::MAX)
        );
    }

    #[test]
    fn funnel_shift_values_and_modulo() {
        // Zero shifts select the appropriate half of the concatenation.
        assert_eq!(IntOp::Fshl.apply(8, &[0xab, 0xcd, 0]), Some(0xab));
        assert_eq!(IntOp::Fshl.apply(8, &[0xab, 0xcd, 8]), Some(0xab));
        assert_eq!(IntOp::Fshl.apply(8, &[0xab, 0xcd, 16]), Some(0xab));
        assert_eq!(IntOp::Fshr.apply(8, &[0xab, 0xcd, 0]), Some(0xcd));
        assert_eq!(IntOp::Fshr.apply(8, &[0xab, 0xcd, 8]), Some(0xcd));
        // Mixed halves: both directions select 0x23 at a half-width shift.
        assert_eq!(IntOp::Fshl.apply(8, &[0x12, 0x34, 4]), Some(0x23));
        assert_eq!(IntOp::Fshr.apply(8, &[0x12, 0x34, 4]), Some(0x23));
        // Amounts wrap modulo the width: 12 % 8 == 4.
        assert_eq!(IntOp::Fshl.apply(8, &[0x12, 0x34, 12]), Some(0x23));
        assert_eq!(IntOp::Fshr.apply(8, &[0x12, 0x34, 12]), Some(0x23));
        // Equal halves rotate.
        assert_eq!(IntOp::Fshl.apply(8, &[0x81, 0x81, 1]), Some(0x03));
        assert_eq!(IntOp::Fshr.apply(8, &[0x81, 0x81, 1]), Some(0xc0));
        assert_eq!(IntOp::Fshl.apply(8, &[0x81, 0x81, 9]), Some(0x03));
        // Single-bit widths select the left or right half respectively.
        assert_eq!(IntOp::Fshl.apply(1, &[1, 0, 7]), Some(1));
        assert_eq!(IntOp::Fshr.apply(1, &[0, 1, 7]), Some(1));
    }

    #[test]
    fn poison_shifts_return_none() {
        assert_eq!(IntOp::Shl.apply(8, &[0xff, 8]), None);
        assert_eq!(IntOp::Shl.apply(8, &[0x01, 255]), None);
        assert_eq!(IntOp::LShr.apply(8, &[0xff, 8]), None);
        assert_eq!(IntOp::AShr.apply(8, &[0xff, 8]), None);
        // Width-64 shifts accept 63 but poison at 64 without panicking.
        assert_eq!(IntOp::Shl.apply(64, &[1, 63]), Some(0x8000_0000_0000_0000));
        assert_eq!(IntOp::Shl.apply(64, &[1, 64]), None);
        assert_eq!(IntOp::LShr.apply(64, &[u64::MAX, 64]), None);
        assert_eq!(IntOp::AShr.apply(64, &[u64::MAX, 64]), None);
        // Incoming register summaries may contain bits above the operand width.
        assert_eq!(IntOp::Shl.apply(8, &[1, 256]), Some(1));
        assert_eq!(IntOp::LShr.apply(8, &[0x80, 257]), Some(0x40));
        assert_eq!(IntOp::AShr.apply(8, &[0x80, 257]), Some(0xc0));
        assert_eq!(IntOp::Fshl.apply(3, &[5, 2, 8]), Some(5));
        assert_eq!(IntOp::Fshr.apply(3, &[5, 2, 8]), Some(2));
    }

    #[test]
    fn invalid_widths_and_arity_return_none() {
        assert_eq!(IntOp::Add.apply(0, &[1, 2]), None);
        assert_eq!(IntOp::Add.apply(65, &[1, 2]), None);
        assert_eq!(IntOp::Trunc.apply(0, &[1]), None);
        assert_eq!(IntOp::Fshl.apply(65, &[1, 2, 3]), None);
        assert_eq!(IntOp::Add.apply(32, &[1]), None);
        assert_eq!(IntOp::Add.apply(32, &[1, 2, 3]), None);
        assert_eq!(IntOp::Trunc.apply(8, &[]), None);
        assert_eq!(IntOp::Fshl.apply(8, &[1, 2]), None);
        assert_eq!(IntOp::ZExt { from: 0 }.apply(16, &[1]), None);
        assert_eq!(IntOp::ZExt { from: 65 }.apply(64, &[1]), None);
        assert_eq!(IntOp::ZExt { from: 16 }.apply(8, &[1]), None);
        assert_eq!(IntOp::ZExt { from: 8 }.apply(0, &[1]), None);
        assert_eq!(IntOp::SExt { from: 0 }.apply(16, &[1]), None);
        assert_eq!(IntOp::SExt { from: 17 }.apply(16, &[1]), None);
    }
}
