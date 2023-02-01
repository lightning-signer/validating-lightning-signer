use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt;
use core::fmt::Debug;
use core::str::FromStr;
use vls_protocol::model::Secret;

use rand_core::RngCore;

use log::*;

use fatfs::{self, Read, Write};

use cortex_m::prelude::_embedded_hal_blocking_delay_DelayMs;

use crate::sdcard;
use crate::DeviceContext;

use vls_protocol_signer::lightning_signer::{
    bitcoin::{
        hashes::hex::ToHex,
        secp256k1::{PublicKey, Secp256k1},
        Network,
    },
    signer::derive::{key_derive, KeyDerivationStyle},
};

pub struct CommonContext {
    pub devctx: Arc<RefCell<DeviceContext>>,
    pub kdstyle: KeyDerivationStyle,
    pub network: Network,
    pub permissive: bool,
    pub setupfs: Option<Arc<RefCell<SetupFS>>>,
}

impl fmt::Debug for CommonContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let runpath = self.setupfs.as_ref().map(|arcref| arcref.borrow().runpath());
        f.debug_struct("CommonContext")
            .field("kdstyle", &self.kdstyle)
            .field("network", &self.network)
            .field("permissive", &self.permissive)
            .field("runpath", &runpath)
            .finish()
    }
}

#[derive(Debug)]
pub struct TestingContext {
    pub cmn: CommonContext,
}

#[derive(Debug)]
pub struct NormalContext {
    pub cmn: CommonContext,
    pub seed: Secret,
}

#[derive(Debug)]
pub enum RunContext {
    Testing(TestingContext),
    Normal(NormalContext),
}

pub struct SetupFS {
    fs: sdcard::FS,
    runpath: Option<String>,
}

impl fmt::Debug for SetupFS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetupFS").field("runpath", &self.runpath).finish()
    }
}

const RUNPATH_PATH: &str = "RUNPATH";
const TESTDIR_PATH: &str = "test-mode";
const TESTING_FILE: &str = "TESTING";
const PERMISSIVE_FILE: &str = "PERMISSIVE";
const NETWORK_FILE: &str = "NETWORK";
const KDSTYLE_FILE: &str = "KDSTYLE";
const HSMSEED_FILE: &str = "hsm_secret";

// These should be managed instead of fixed
const TESTING_KDSTYLE: KeyDerivationStyle = KeyDerivationStyle::Native;
const TESTING_NETWORK: Network = Network::Regtest;

impl SetupFS {
    // Survey the sdcard, determine the runpath, setup if uninitialized
    pub fn initialize(&mut self) {
        let rootdir = self.fs.root_dir();
        let runpath = match self.read_file_string(&rootdir, RUNPATH_PATH) {
            Some(runpath) => runpath,
            None => {
                info!("{} doesn't exist, creating default with {}", RUNPATH_PATH, TESTDIR_PATH);
                let testdir_path = self.create_default_testdir(&rootdir);
                self.write_file_string(&rootdir, RUNPATH_PATH, &testdir_path);
                testdir_path
            }
        };
        self.runpath = Some(runpath);
    }

    // Read the kdstyle, network and optional seed from the FS
    pub fn context(&self) -> (KeyDerivationStyle, Network, Option<Secret>, bool) {
        let rootdir = self.fs.root_dir();
        let runpath = self.runpath.as_ref().expect("runpath");
        let rundir = rootdir
            .open_dir(&runpath)
            .unwrap_or_else(|err| panic!("open {} failed: {:#?}", runpath, err));

        let kdstyle = KeyDerivationStyle::from_str(
            &self.read_file_string(&rundir, KDSTYLE_FILE).expect("kdstyle file"),
        )
        .expect("invalid kdstyle");

        let network =
            Network::from_str(&self.read_file_string(&rundir, NETWORK_FILE).expect("network file"))
                .expect("invalid network");

        // If the rundir has a TESTING file we're in testing mode
        let is_testing = match rundir.open_file(TESTING_FILE) {
            Err(fatfs::Error::NotFound) => false, // Ok, maybe we're in normal mode ...
            Err(err) => panic!("open {} failed: {:#?}", TESTING_FILE, err),
            Ok(_) => true,
        };

        // If the rundir has a PERMISSIVE file we're in permissive mode
        let is_permissive = match rundir.open_file(PERMISSIVE_FILE) {
            Err(fatfs::Error::NotFound) => false, // Ok, maybe we're in normal mode ...
            Err(err) => panic!("open {} failed: {:#?}", PERMISSIVE_FILE, err),
            Ok(_) => true,
        };

        let opt_seed = if is_testing {
            None
        } else {
            // Otherwise we are in NORMAL mode and we need a HSMSEED_FILE
            Some(self.read_seed_file(&rundir, HSMSEED_FILE))
        };

        (kdstyle, network, opt_seed, is_permissive)
    }

    pub fn list_nodes(&self) -> Vec<(Network, String)> {
        let mut rv = vec![];
        let rootdir = self.fs.root_dir();
        for di in rootdir.iter() {
            let entry = di.unwrap();
            if entry.is_dir() {
                let rundir = entry.to_dir();
                if let Some(network_str) = &self.read_file_string(&rundir, NETWORK_FILE) {
                    rv.push((
                        Network::from_str(network_str).expect("valid network"),
                        entry.file_name(),
                    ));
                }
            }
        }
        rv
    }

    #[allow(unused)]
    pub fn runpath(&self) -> String {
        self.runpath.as_ref().unwrap().clone()
    }

    #[allow(unused)]
    pub fn abbrev_path(&self) -> String {
        let mut abbrev_path = self.runpath();
        abbrev_path.truncate(9); // for limited horizontal space
        abbrev_path
    }

    #[allow(unused)]
    pub fn rundir(&self) -> sdcard::DIR {
        let rootdir = self.fs.root_dir();
        let runpath = self.runpath();
        rootdir
            .open_dir(&runpath)
            .unwrap_or_else(|err| panic!("open {} failed: {:#?}", runpath, err))
    }

    fn select_runpath(&mut self, runpath: String) {
        let rootdir = self.fs.root_dir();
        self.write_file_string(&rootdir, RUNPATH_PATH, &runpath);
        self.runpath = Some(runpath);
    }

    fn create_default_testdir(&self, rootdir: &sdcard::DIR) -> String {
        self.create_rundir(
            rootdir,
            &TESTDIR_PATH.to_string(),
            TESTING_NETWORK,
            TESTING_KDSTYLE,
            None,
        )
    }

    fn create_rundir(
        &self,
        rootdir: &sdcard::DIR,
        dirpath: &String,
        network: Network,
        kdstyle: KeyDerivationStyle,
        opt_seed: Option<[u8; 32]>,
    ) -> String {
        match rootdir.create_dir(dirpath) {
            Ok(rundir) => {
                self.write_file_string(&rundir, NETWORK_FILE, &network.to_string());
                self.write_file_string(&rundir, KDSTYLE_FILE, &kdstyle.to_string());
                if opt_seed.is_some() {
                    self.write_seed_file(&rundir, HSMSEED_FILE, &opt_seed.unwrap());
                } else {
                    self.write_file_string(&rundir, TESTING_FILE, &"".to_string());
                }
            }
            Err(err) => panic!("create_dir {} failed: {:#?}", dirpath, err),
        };
        dirpath.clone()
    }

    #[allow(unused)]
    // Removes a file, ok if it doesn't exist
    pub fn remove_possible_file(&self, rundir: &sdcard::DIR, path: &str) {
        rundir.remove(path).ok(); // ignore errors
    }

    // Read a string value from a file, stripping an optional trailing newline
    fn read_file_string(&self, rundir: &sdcard::DIR, path: &str) -> Option<String> {
        match rundir.open_file(path) {
            Err(_) => None,
            Ok(mut file) => {
                let mut buffer = [0u8; 128];
                match file.read(&mut buffer) {
                    Err(err) => panic!("read {} failed: {:#?}", KDSTYLE_FILE, err),
                    Ok(mut len) => {
                        if buffer[len - 1] == '\n' as u8 {
                            len -= 1
                        }
                        Some(String::from_utf8(buffer[..len].to_vec()).expect("invaid string"))
                    }
                }
            }
        }
    }

    // Write a string value to a file with a trailing newline
    fn write_file_string(&self, rundir: &sdcard::DIR, path: &str, val: &String) {
        let mut file = rundir
            .create_file(path)
            .unwrap_or_else(|err| panic!("create {} failed: {:#?}", path, err));
        file.truncate().unwrap_or_else(|err| panic!("truncate {} failed: {:#?}", path, err));
        file.write(format!("{}\n", val).as_bytes())
            .unwrap_or_else(|err| panic!("write {} failed: {:#?}", path, err));
        file.flush().unwrap_or_else(|err| panic!("flush {} failed: {:#?}", path, err));
    }

    // Read a binary seed value from a file
    fn read_seed_file(&self, rundir: &sdcard::DIR, path: &str) -> Secret {
        match rundir.open_file(path) {
            Err(err) => panic!("open {} failed: {:#?}", path, err),
            Ok(mut file) => {
                let mut buffer = [0u8; 32];
                match file.read(&mut buffer) {
                    Err(err) => panic!("read {} failed: {:#?}", path, err),
                    Ok(len) => {
                        if len != 32 {
                            panic!("seed file too small")
                        }
                        let mut extra = [0u8; 1];
                        if file.read(&mut extra).expect("empty read") != 0 {
                            panic!("seed file too big")
                        }
                        Secret(buffer)
                    }
                }
            }
        }
    }

    // Write a binary seed to a file
    fn write_seed_file(&self, rundir: &sdcard::DIR, path: &str, seed: &[u8; 32]) {
        let mut file = rundir
            .create_file(path)
            .unwrap_or_else(|err| panic!("create {} failed: {:#?}", path, err));
        file.truncate().unwrap_or_else(|err| panic!("truncate {} failed: {:#?}", path, err));
        file.write(seed).unwrap_or_else(|err| panic!("write {} failed: {:#?}", path, err));
        file.flush().unwrap_or_else(|err| panic!("flush {} failed: {:#?}", path, err));
    }
}

pub fn setup_mode(mut devctx: DeviceContext) -> RunContext {
    info!("entering setup mode");
    let opt_setupfs = init_setupfs(&mut devctx);

    if !opt_setupfs.is_some() {
        info!("sdcard needed for setup mode");
        return run_context(devctx, opt_setupfs);
    } else {
        let mut setupfs = opt_setupfs.as_ref().unwrap().borrow_mut();

        loop {
            let mut nodes = setupfs.list_nodes();
            nodes.truncate(4); // limited display height

            // header
            let mut lines = vec![format!("{: ^19}", "Select Node"), format!("")];

            // a pair of lines for each node
            for (network, path) in nodes.iter() {
                let mut abbrev_path = path.clone();
                abbrev_path.truncate(9); // limited display width
                lines.push(format!(" {: >7}:{: <9}", network.to_string(), abbrev_path));
                lines.push(format!(""));
            }

            // pad
            lines.resize_with(9, || format!(""));

            if nodes.len() < 4 {
                lines.push(format!("{: ^19}", "New Node"));
            } else {
                lines.push(format!(""));
            }

            devctx.disp.clear_screen();
            devctx.disp.show_texts(&lines);

            loop {
                let (row, _col) =
                    devctx.disp.wait_for_touch(&mut devctx.touchscreen.inner, &mut devctx.i2c);
                info!("row {} touched", row);
                if row < 2 {
                    continue;
                };
                if (row - 2) % 2 == 0 {
                    let ndx = ((row - 2) / 2) as usize;
                    if ndx < nodes.len() {
                        let runpath = nodes[ndx].1.clone();
                        info!("{} selected", &runpath);
                        if manage_node(&mut devctx, &mut setupfs, nodes[ndx].0, &runpath) {
                            setupfs.select_runpath(runpath);
                            drop(setupfs);
                            return run_context(devctx, opt_setupfs);
                        } else {
                            break; // redisplay list w/ possible deletion
                        }
                    }
                }
                if row == 9 && nodes.len() < 4 {
                    info!("new node selected");
                    let dirpath = create_node(&mut devctx, &mut setupfs);
                    setupfs.select_runpath(dirpath);
                    drop(setupfs);
                    return run_context(devctx, opt_setupfs);
                }
                devctx.delay.delay_ms(100u16);
            }
        }
    }
}

pub fn create_node(devctx: &mut DeviceContext, setupfs: &mut SetupFS) -> String {
    info!("create_node entered");

    devctx.disp.clear_screen();
    devctx.disp.show_texts(&[
        format!("{: ^19}", "Choose Network"),
        format!(""),
        format!("{: ^19}", "testnet"),
        format!(""),
        format!("{: ^19}", "regtest"),
        format!(""),
        format!("{: ^19}", "signet"),
        format!(""),
        format!("{: ^19}", "bitcoin"),
        format!(""),
    ]);

    let network = loop {
        let (row, _col) =
            devctx.disp.wait_for_touch(&mut devctx.touchscreen.inner, &mut devctx.i2c);
        info!("row {} touched", row);
        if row == 2 {
            info!("testnet selected");
            break Network::Testnet;
        } else if row == 4 {
            info!("regtest selected");
            break Network::Regtest;
        } else if row == 6 {
            info!("signet selected");
            break Network::Signet;
        } else if row == 8 {
            info!("bitcoin selected");
            break Network::Bitcoin;
        }
        devctx.delay.delay_ms(100u16);
    };
    info!("network: {}", network.to_string());

    // TODO - could support other choices ...
    let kdstyle = KeyDerivationStyle::Native;
    info!("kdstyle: {}", kdstyle.to_string());

    let mut seed: [u8; 32] = [0u8; 32];
    let rng = devctx.rng.as_mut().unwrap();
    rng.fill_bytes(&mut seed);
    info!("seed: {}", seed.to_hex());

    let nodeid = node_id_from_seed(kdstyle, network, &seed);
    info!("nodeid: {}", nodeid);

    let rootdir = setupfs.fs.root_dir();
    let dirpath =
        setupfs.create_rundir(&rootdir, &nodeid.to_string(), network, kdstyle, Some(seed));
    dirpath
}

pub fn manage_node(
    devctx: &mut DeviceContext,
    setupfs: &mut SetupFS,
    network: Network,
    runpath: &String,
) -> bool {
    // Present the user with a choice to launch, delete, or back to setup.
    // Returns true if should launch, false otherwise ...
    let mut abbrev_path = runpath.clone();
    abbrev_path.truncate(9); // limited display width

    // If the rundir has a PERMISSIVE file we're in permissive mode
    let is_permissive = {
        let rootdir = setupfs.fs.root_dir();
        let rundir = rootdir
            .open_dir(&runpath)
            .unwrap_or_else(|err| panic!("open {} failed: {:#?}", runpath, err));
        match rundir.open_file(PERMISSIVE_FILE) {
            Err(fatfs::Error::NotFound) => false, // Ok, maybe we're in normal mode ...
            Err(err) => panic!("open {} failed: {:#?}", PERMISSIVE_FILE, err),
            Ok(_) => true,
        }
    };

    let mut lines = vec![];
    lines.push(format!("{: ^19}", "Manage Node"));
    lines.push(format!(" {: >7}:{: <9}", network.to_string(), abbrev_path));
    lines.push(format!("{: ^19}", if is_permissive { "PERMISSIVE" } else { "ENFORCING" }));
    lines.push(format!(""));
    lines
        .push(format!("{: ^19}", if is_permissive { "Make Enforcing" } else { "Make Permissive" }));
    lines.push(format!(""));
    if runpath != TESTDIR_PATH {
        lines.push(format!("{: ^19}", "Delete"));
    } else {
        lines.push(format!(""));
    }

    lines.resize_with(9, || format!(""));
    lines.push(format!("{:^9} {:^9}", "Back", "Launch"));

    devctx.disp.clear_screen();
    devctx.disp.show_texts(&lines);

    loop {
        let (row, col) = devctx.disp.wait_for_touch(&mut devctx.touchscreen.inner, &mut devctx.i2c);
        info!("row {} touched", row);
        if row == 4 {
            info!("toggle permissive");
            let rootdir = setupfs.fs.root_dir();
            let rundir = rootdir
                .open_dir(&runpath)
                .unwrap_or_else(|err| panic!("open {} failed: {:#?}", runpath, err));
            if is_permissive {
                rundir
                    .remove(PERMISSIVE_FILE)
                    .unwrap_or_else(|err| panic!("remove {} failed: {:#?}", PERMISSIVE_FILE, err));
            } else {
                setupfs.write_file_string(&rundir, PERMISSIVE_FILE, &"".to_string());
            }
            return false;
        } else if row == 6 && runpath != TESTDIR_PATH {
            info!("delete {} selected", runpath);
            {
                let rootdir = setupfs.fs.root_dir();
                let rundir = rootdir
                    .open_dir(&runpath)
                    .unwrap_or_else(|err| panic!("open {} failed: {:#?}", runpath, err));
                sdcard::rmdir(rundir)
                    .unwrap_or_else(|err| panic!("rmdir {} failed: {:#?}", runpath, err));
                rootdir
                    .remove(runpath)
                    .unwrap_or_else(|err| panic!("remove {} failed: {:#?}", runpath, err));
            }
            // IMPORTANT - if the user deleted the currently selected node and then
            // resets w/o selecting a new one we crash ... select test-mode in case
            setupfs.select_runpath(TESTDIR_PATH.to_string());
            return false;
        } else if row == 9 {
            if col < 8 {
                info!("back selected");
                return false;
            } else if col > 10 {
                info!("launch selected");
                return true;
            }
        }
        devctx.delay.delay_ms(100u16);
    }
}

pub fn get_run_context(mut devctx: DeviceContext) -> RunContext {
    info!("get_run_context");
    let setupfs = init_setupfs(&mut devctx);
    run_context(devctx, setupfs)
}

fn init_setupfs(devctx: &mut DeviceContext) -> Option<Arc<RefCell<SetupFS>>> {
    // Probe the sdcard
    devctx.disp.clear_screen();
    devctx.disp.show_texts(&[format!("probing sdcard ...")]);
    let mut sdio = devctx.sdio.take().unwrap();
    let setupfs = match sdcard::init_sdio(&mut sdio, &mut devctx.delay) {
        false => None,
        true => {
            let fs = sdcard::open(sdio).unwrap();
            Some(Arc::new(RefCell::new(SetupFS { fs, runpath: None })))
        }
    };

    if setupfs.is_some() {
        // Survey the sdcard, initialize if necessary
        setupfs.as_ref().unwrap().borrow_mut().initialize();
    }

    setupfs
}

fn run_context(bare_devctx: DeviceContext, setupfs: Option<Arc<RefCell<SetupFS>>>) -> RunContext {
    let devctx = Arc::new(RefCell::new(bare_devctx));

    // If there is no sdcard we're in testing mode
    if setupfs.is_none() {
        return RunContext::Testing(TestingContext {
            cmn: CommonContext {
                devctx,
                kdstyle: TESTING_KDSTYLE,
                network: TESTING_NETWORK,
                permissive: false,
                setupfs,
            },
        });
    }

    let (kdstyle, network, opt_seed, permissive) = setupfs.as_ref().unwrap().borrow().context();
    match opt_seed {
        None => RunContext::Testing(TestingContext {
            cmn: CommonContext { devctx, kdstyle, network, permissive, setupfs },
        }),
        Some(seed) => RunContext::Normal(NormalContext {
            cmn: CommonContext { devctx, kdstyle, network, permissive, setupfs },
            seed,
        }),
    }
}

fn node_id_from_seed(style: KeyDerivationStyle, network: Network, seed: &[u8]) -> PublicKey {
    let secp_ctx = Secp256k1::new();
    let deriver = key_derive(style, network);
    deriver.node_keys(seed, &secp_ctx).0
}
