use core::alloc::Layout;
use core::panic::PanicInfo;

use crate::tests::{test_bitcoin, test_lightning_signer};
use alloc_cortex_m::CortexMHeap;
use cortex_m::asm;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use lightning_signer::bitcoin::secp256k1::Secp256k1;

// this is the allocator the application will use
#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

const HEAP_SIZE: usize = 1024 * 448; // 448 KiB, leave some space for stack on a 512 KiB RAM system

#[entry]
fn main() -> ! {
    hprintln!("heap size {}", HEAP_SIZE).unwrap();

    unsafe { ALLOCATOR.init(cortex_m_rt::heap_start() as usize, HEAP_SIZE) }

    let size = Secp256k1::preallocate_size();
    hprintln!("secp buf size {}", size * 16).unwrap();

    test_bitcoin();
    test_lightning_signer(|| hprintln!("used memory {}", ALLOCATOR.used()).unwrap());

    // exit QEMU
    // NOTE do not run this on hardware; it can corrupt OpenOCD state
    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

// define what happens in an Out Of Memory (OOM) condition
#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    hprintln!("alloc error").unwrap();
    debug::exit(debug::EXIT_FAILURE);
    asm::bkpt();

    loop {}
}

#[inline(never)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    hprintln!("panic {:?}", info.message()).unwrap();
    debug::exit(debug::EXIT_FAILURE);
    loop {}
}
