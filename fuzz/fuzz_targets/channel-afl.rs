#[cfg(not(feature = "repro"))]
#[macro_use]
extern crate afl;

use arbitrary::Arbitrary;
use vls_fuzz::channel::ChannelFuzz;

fn main() {
    #[cfg(not(feature = "repro"))]
    fuzz!(|bytes| {
        let mut unstructured = arbitrary::Unstructured::new(&bytes);
        let data = Vec::arbitrary(&mut unstructured).unwrap();
        #[cfg(feature = "debug")]
        println!("{:?}", data);
        let mut fuzz = ChannelFuzz::new();
        fuzz.run(data).unwrap();
    });

    #[cfg(feature = "repro")]
    {
        use std::io::Read;
        // read bytes from stdin
        let bytes = std::io::stdin().lock().bytes().map(|b| b.unwrap()).collect::<Vec<u8>>();
        let mut unstructured = arbitrary::Unstructured::new(&bytes);
        let data = Vec::arbitrary(&mut unstructured).unwrap();
        println!("{:?}", data);
        let mut fuzz = ChannelFuzz::new();
        fuzz.run(data).unwrap();
        println!("done");
    }
}
