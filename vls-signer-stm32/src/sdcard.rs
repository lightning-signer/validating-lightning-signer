use alloc::string::String;
use core::cmp::min;
use fatfs::{
    DefaultTimeProvider, Dir, File, FileSystem, FsOptions, IoBase, LossyOemCpConverter,
    OemCpConverter, Read, Seek, SeekFrom, TimeProvider, Write,
};
use log::{debug, error, info};
use stm32f4xx_hal::prelude::*;
use stm32f4xx_hal::sdio::{ClockFreq, SdCard, Sdio};
use stm32f4xx_hal::timer::SysDelay;

const BLOCK_SIZE: usize = 512;

pub struct Card {
    pos: u64,
    sdio: Sdio<SdCard>,
    num_blocks: u32,
    buf: [u8; BLOCK_SIZE],
    buf_block_index: u32,
    is_dirty: bool,
}

impl Card {
    fn read_block(&mut self, n: u32) -> Result<(), <Self as IoBase>::Error> {
        if n == self.buf_block_index {
            // already have it in cache
            return Ok(());
        }
        // write out the current block if dirty
        self.write_block()?;

        self.do_read_block(n)
    }

    fn do_read_block(&mut self, n: u32) -> Result<(), <Self as IoBase>::Error> {
        // rprintln!("read block {}", n);
        self.sdio.read_block(n, &mut self.buf).map_err(|e| {
            error!("error {:?}", e);
            ()
        })?;
        self.buf_block_index = n;
        Ok(())
    }

    fn write_block(&mut self) -> Result<(), <Self as IoBase>::Error> {
        if self.is_dirty {
            // rprintln!("write block {}", self.buf_block_index);
            // rprint!(".");
            self.sdio.write_block(self.buf_block_index, &self.buf).map_err(|e| {
                error!("error {:?}", e);
                ()
            })?;
            self.is_dirty = false;
        }
        Ok(())
    }
}

impl IoBase for Card {
    type Error = ();
}

impl Read for Card {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Self::Error> {
        // rprintln!("read {} @ {}", buf.len(), self.pos);
        let mut count = 0;
        while !buf.is_empty() {
            let n = (self.pos / BLOCK_SIZE as u64) as u32;
            if n >= self.num_blocks {
                // end of disk
                break;
            }
            // fill the buffer
            if let Err(e) = self.read_block(n) {
                error!("error {:?} count {}", e, count);
                // If we didn't manage to read anything, return the error,
                // otherwise return how many bytes we wrote
                if count == 0 {
                    return Err(e);
                } else {
                    return Ok(count);
                }
            }
            let offset = (self.pos % BLOCK_SIZE as u64) as usize;
            // read to the end of the buffer, or the sector, whichever is closer
            let len = min(buf.len(), (BLOCK_SIZE - offset) as usize);
            // rprintln!("offset {} len {} block {}", offset, len, self.buf_block);
            buf[0..len].copy_from_slice(&self.buf[offset..offset + len]);
            buf = &mut buf[len..];
            self.pos += len as u64;
            count += len;
        }
        Ok(count)
    }
}

impl Write for Card {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, <Self as IoBase>::Error> {
        let mut count = 0;
        while !buf.is_empty() {
            let n = (self.pos / BLOCK_SIZE as u64) as u32;
            if n >= self.num_blocks {
                // end of disk
                break;
            }

            // potentially write out a dirty buffer, then fill buffer
            if let Err(e) = self.read_block(n) {
                // If we didn't manage to write anything, return the error,
                // otherwise return how many bytes we wrote
                if count == 0 {
                    return Err(e);
                } else {
                    return Ok(count);
                }
            }
            let offset = self.pos as usize % BLOCK_SIZE;
            // write to the end of the buffer, or the sector, whichever is closer
            let len = min(buf.len(), BLOCK_SIZE - offset);
            // rprintln!("len {}", len);
            self.buf[offset..offset + len].copy_from_slice(&buf[0..len]);
            self.is_dirty = true;
            buf = &buf[len..];
            self.pos += len as u64;
            count += len;
        }
        Ok(count)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // rprintln!("flush");
        self.write_block()
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
                self.pos = ((self.num_blocks as usize * BLOCK_SIZE) as i64 + p) as u64;
            }
            SeekFrom::Current(p) => {
                // rprintln!("seek cur {}", p);
                self.pos = (self.pos as i64 + p) as u64;
            }
        }
        Ok(self.pos)
    }
}

type FS = FileSystem<Card, DefaultTimeProvider, LossyOemCpConverter>;

pub fn open(sdio: Sdio<SdCard>) -> Result<FS, fatfs::Error<()>> {
    let blocks = sdio.card().map(|c| c.block_count()).unwrap();
    let mut card = Card {
        sdio,
        pos: 0,
        num_blocks: blocks,
        buf: [0u8; BLOCK_SIZE],
        buf_block_index: 0,
        is_dirty: false,
    };

    // prefetch the first block, making the buffer a valid copy of what's on disk
    card.do_read_block(0)?;

    debug!("before new");
    let fs = FileSystem::new(card, FsOptions::new())?;

    debug!("after new");
    Ok(fs)
}

pub fn copy_dir<TP: TimeProvider, OCC: OemCpConverter>(
    from_dir: Dir<Card, TP, OCC>,
    to_dir: Dir<Card, TP, OCC>,
) -> Result<(), fatfs::Error<()>> {
    for entry_res in from_dir.iter() {
        let entry = entry_res?;
        let name = entry.file_name();
        if entry.is_file() {
            info!("cp {} ", name);
            let copy = to_dir.create_file(&name)?;
            let orig = entry.to_file();
            copy_file(orig, copy)?;
            info!("");
        } else if entry.is_dir() && entry.file_name() != "." && entry.file_name() != ".." {
            info!("cp -r {}", name);
            let copy = to_dir.create_dir(&name)?;
            copy_dir(entry.to_dir(), copy)?;
        }
    }
    Ok(())
}

fn rmdir<TP: TimeProvider, OCC: OemCpConverter>(
    dir: Dir<Card, TP, OCC>,
) -> Result<(), fatfs::Error<()>> {
    for f_res in dir.iter() {
        let f = f_res?;
        if f.is_file() {
            info!("rm {}", &f.file_name());
            dir.remove(&f.file_name())?;
        } else if f.is_dir() && f.file_name() != "." && f.file_name() != ".." {
            info!("rmdir {}", &f.file_name());
            rmdir(f.to_dir())?;
            dir.remove(&f.file_name())?;
        }
    }
    Ok(())
}

pub fn copy_file<TP: TimeProvider, OCC>(
    mut from: File<Card, TP, OCC>,
    mut to: File<Card, TP, OCC>,
) -> Result<(), fatfs::Error<()>> {
    let mut buf = [0u8; 1000];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            break;
        }
        to.write_all(&buf[0..n])?;
    }
    Ok(())
}

pub fn init_sdio(sdio: &mut Sdio<SdCard>, delay: &mut SysDelay) {
    info!("detecting sdcard");
    loop {
        match sdio.init(ClockFreq::F24Mhz) {
            Ok(_) => break,
            Err(e) => info!("waiting for sdio - {:?}", e),
        }

        delay.delay_ms(1000u32);
    }

    let nblocks = sdio.card().map(|c| c.block_count());
    info!("sdcard detected: nbr of blocks: {:?}", nblocks);
}

// Effectively does:
//
// rm -r /b
// cp -r /a /b
// ls /
// cat /readme*
pub fn test(sdio: Sdio<SdCard>) {
    let fs = open(sdio).unwrap();
    let root_dir = fs.root_dir();

    if let Ok(from_dir) = root_dir.open_dir("a") {
        if let Ok(to_dir) = root_dir.open_dir("b") {
            rmdir(to_dir).expect("rm b");
        }
        let to_dir = root_dir.create_dir("b").expect("create b");
        let copy_res = copy_dir(from_dir, to_dir);
        info!("copy result: {:?}", copy_res);
    }

    for f in fs.root_dir().iter() {
        let entry = f.unwrap();
        let filename = entry.file_name();
        info!("file {:?}", filename);
        if filename.starts_with("readme") {
            let mut buf = [0u8; 100];
            let mut file = entry.to_file();
            loop {
                let len = file.read(&mut buf).unwrap();
                if len == 0 {
                    break;
                }
                info!("contents {}", String::from_utf8_lossy(&buf[0..len]));
            }
        }
    }
}
