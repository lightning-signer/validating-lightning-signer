#![allow(missing_docs)]
use core::cell::{RefCell, RefMut};
use core::ops::{Deref, DerefMut};

/// Convenience trait for Send + Sync
pub trait SendSync {}

pub struct MutexGuard<'a, T>(RefMut<'a, T>);

pub struct Mutex<T> {
    inner: RefCell<T>,
}

impl<T> Mutex<T> {
    pub fn new(inner: T) -> Self {
        Self { inner: RefCell::new(inner) }
    }

    pub fn lock(&self) -> Result<MutexGuard<T>, ()> {
        Ok(MutexGuard(self.inner.borrow_mut()))
    }
}

impl<'a, T> Deref for MutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, T> DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.0.deref_mut()
    }
}
