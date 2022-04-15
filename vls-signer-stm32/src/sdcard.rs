use alloc::string::String;
use core::cmp::min;
use stm32f4xx_hal::sdio::{Sdio, SdCard};
use fatfs::{FileSystem, FsOptions, Read, Write, Seek, SeekFrom, IoBase, DefaultTimeProvider, LossyOemCpConverter};
use rtt_target::rprintln;

pub struct Card {
    pos: u64,
    sdio: Sdio<SdCard>,
    blocks: u32,
}

impl IoBase for Card { type Error = (); }

impl Read for Card {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Self::Error> {
        // rprintln!("read {} @ {}", buf.len(), self.pos);
        let mut count = 0;
        let mut block = [0u8; 512];
        while !buf.is_empty() {
            let n = (self.pos / 512) as u32;
            // rprintln!("read block {}", n);
            self.sdio.read_block(n, &mut block)
                .map_err(|e| {
                    rprintln!("error {:?}", e);
                    ()
                })?;
            let offset = (self.pos % 512) as usize;
            let len = min(buf.len(), (512 - offset) as usize);
            // rprintln!("len {}", len);
            buf[0..len].copy_from_slice(&block[offset..offset + len]);
            buf = &mut buf[len..];
            self.pos += len as u64;
            count += len;
        }
        Ok(count)
    }
}

impl Write for Card {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        todo!()
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // TODO
        Ok(())
    }
}

impl Seek for Card {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        match pos {
            SeekFrom::Start(p) => {
                // rprintln!("seek start {}", p);
                self.pos = p;
            }
            SeekFrom::End(p) => {
                // rprintln!("seek end {}", p);
                self.pos = ((self.blocks as i64 * 512) + p) as u64;
            }
            SeekFrom::Current(p) => {
                // rprintln!("seek cur {}", p);
                self.pos = (self.pos as i64 + p) as u64;
            }
        }
        Ok(self.pos)
    }
}

pub fn open(sdio: Sdio<SdCard>) -> Result<FileSystem<Card, DefaultTimeProvider, LossyOemCpConverter>, fatfs::Error<()>> {
    let blocks = sdio.card().map(|c| c.block_count()).unwrap();
    let card = Card { sdio, pos: 0, blocks };
    rprintln!("before new");
    let fs = FileSystem::new(card, FsOptions::new())?;
    rprintln!("after new");
    Ok(fs)
}

pub fn test(sdio: Sdio<SdCard>) {
    let fs = open(sdio).unwrap();
    for f in fs.root_dir().iter() {
        let entry = f.unwrap();
        let filename = entry.file_name();
        rprintln!("file {:?}", filename);
        if filename.starts_with("README") {
            let mut buf = [0u8; 100];
            let mut file = entry.to_file();
            loop {
                let len = file.read(&mut buf).unwrap();
                if len == 0 {
                    break;
                }
                rprintln!("contents len {}", len);
                rprintln!("contents {}", String::from_utf8_lossy(&buf[0..len]));
            }
        }
    }
}
