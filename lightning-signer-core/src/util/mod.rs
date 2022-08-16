/// Byte to integer conversion
pub mod byte_utils;
/// Clock provider
pub mod clock;
/// Cryptographic utilities
pub mod crypto_utils;
/// Logging macros
#[macro_use]
#[allow(unused_macros)]
pub mod macro_logger;
#[macro_use]
/// Debugging
pub mod debug_utils;
/// Logging
pub mod log_utils;
/// An implementation of the LDK Sign trait for integration with LDK based nodes
pub mod loopback;
#[allow(missing_docs)]
pub mod test_logger;
#[allow(missing_docs)]
#[cfg(feature = "test_utils")]
#[macro_use]
pub mod test_utils;
#[allow(missing_docs)]
#[cfg(feature = "test_utils")]
#[rustfmt::skip]
#[macro_use]
pub mod functional_test_utils;
/// Key utilities
pub mod key_utils;
/// Status error results
pub mod status;
/// Transaction utilities
pub mod transaction_utils;
/// Velocity control
pub mod velocity;

/// The initial commitment number when counting backwards
pub const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

use crate::prelude::*;
use core::slice::Iter;
use itertools::{put_back, PutBack};

/// Iterator over elements in `to` that are not in `from`
pub struct AddedItemsIter<'a, T: Ord + Eq> {
    from: PutBack<Iter<'a, T>>,
    to: PutBack<Iter<'a, T>>,
}

impl<'a, T: Ord + Eq> AddedItemsIter<'a, T> {
    /// Both vectors must be sorted
    pub fn new(from: &'a Vec<T>, to: &'a Vec<T>) -> Self {
        AddedItemsIter { from: put_back(from.iter()), to: put_back(to.iter()) }
    }
}

impl<'a, T: Ord + Eq> Iterator for AddedItemsIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.from.next() {
                // Nothing in `from` - yield remaining elements in `to`
                None => return self.to.next(),
                Some(next_from) => {
                    match self.to.next() {
                        // Nothing in `to` - done
                        None => return None,
                        Some(next_to) => {
                            if next_from < next_to {
                                // `from` is behind - consume `from` but not `to`
                                self.to.put_back(next_to);
                                continue;
                            } else if next_from == next_to {
                                // consume both
                                continue;
                            } else {
                                // `to` is behind - consume `to` but not `from`
                                self.from.put_back(next_from);
                                return Some(next_to);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::util::AddedItemsIter;

    #[test]
    fn delta_test() {
        fn check(from: Vec<u8>, to: Vec<u8>, expect: Vec<u8>) {
            assert_eq!(AddedItemsIter::new(&from, &to).cloned().collect::<Vec<u8>>(), expect);
        }

        check(vec![], vec![1, 2, 4], vec![1, 2, 4]);
        check(vec![3], vec![1, 2, 4], vec![1, 2, 4]);
        check(vec![2, 3], vec![1, 2, 4], vec![1, 4]);
        check(vec![1, 2, 3], vec![1, 2, 4], vec![4]);
        check(vec![0, 1, 2, 3], vec![1, 2, 4], vec![4]);
        check(vec![0, 1, 3], vec![1, 2, 4], vec![2, 4]);
        check(vec![0, 1, 3], vec![1, 2, 4, 5], vec![2, 4, 5]);
    }
}
