//! Safe Rust bindings over the DisLMDB C ABI (`bindings/ABI.kdl`).
//!
//! Build `libdislmdb` first (`make lib`), then `cargo test -p dislmdb` from
//! this crate directory (links `../../build/lib`).

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::path::Path;
use std::ptr;

mod ffi {
    use super::*;

    pub type DislmdbEnv = c_void;
    pub type DislmdbTxn = c_void;

    #[repr(C)]
    pub struct MdbVal {
        pub mv_size: usize,
        pub mv_data: *mut c_void,
    }

    unsafe extern "C" {
        pub fn dislmdb_version(major: *mut c_int, minor: *mut c_int, patch: *mut c_int)
            -> *const c_char;
        pub fn dislmdb_strerror(err: c_int) -> *const c_char;
        pub fn dislmdb_env_config_init(config: *mut EnvConfig) -> c_int;
        pub fn dislmdb_env_create(env: *mut *mut DislmdbEnv) -> c_int;
        pub fn dislmdb_env_open(env: *mut DislmdbEnv, config: *const EnvConfig) -> c_int;
        pub fn dislmdb_env_close(env: *mut DislmdbEnv);
        pub fn dislmdb_txn_begin(
            env: *mut DislmdbEnv,
            parent: *mut DislmdbTxn,
            flags: c_uint,
            txn: *mut *mut DislmdbTxn,
        ) -> c_int;
        pub fn dislmdb_txn_commit(txn: *mut DislmdbTxn) -> c_int;
        pub fn dislmdb_txn_abort(txn: *mut DislmdbTxn);
        pub fn dislmdb_dbi_open(
            txn: *mut DislmdbTxn,
            name: *const c_char,
            flags: c_uint,
            dbi: *mut c_uint,
        ) -> c_int;
        pub fn dislmdb_put(
            txn: *mut DislmdbTxn,
            dbi: c_uint,
            key: *mut MdbVal,
            data: *mut MdbVal,
            flags: c_uint,
        ) -> c_int;
        pub fn dislmdb_get_lmdb_txn(txn: *mut DislmdbTxn) -> *mut c_void;
        pub fn mdb_get(
            txn: *mut c_void,
            dbi: c_uint,
            key: *mut MdbVal,
            data: *mut MdbVal,
        ) -> c_int;
        pub fn dislmdb_acl_set_principal(env: *mut DislmdbEnv, principal: *const c_char)
            -> c_int;
        pub fn dislmdb_acl_grant(
            env: *mut DislmdbEnv,
            principal: *const c_char,
            perms: c_uint,
        ) -> c_int;
    }

    pub const MDB_CREATE: c_uint = 0x4_0000;
    pub const DISLMDB_ACL_ALL: c_uint = 0x7;

    /// Layout must match `DISLMDB_env_config` / nested configs for the fields we set.
    /// We only touch the leading fields + consensus.mechanism via byte offsets
    /// after `dislmdb_env_config_init` fills defaults — safer than full mirror.
    #[repr(C)]
    pub struct EnvConfig {
        // Opaque blob sized large enough for current DISLMDB_env_config.
        // Init via C; we only patch path pointer and a few scalars through helpers.
        pub _bytes: [u8; 4096],
    }
}

/// Library error (DisLMDB or LMDB code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub i32);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = unsafe {
            let p = ffi::dislmdb_strerror(self.0);
            if p.is_null() {
                return write!(f, "dislmdb error {}", self.0);
            }
            CStr::from_ptr(p).to_string_lossy()
        };
        write!(f, "{s} ({})", self.0)
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

fn check(rc: c_int) -> Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(Error(rc))
    }
}

/// DisLMDB version string + components.
pub fn version() -> (String, i32, i32, i32) {
    let mut major = 0;
    let mut minor = 0;
    let mut patch = 0;
    let s = unsafe {
        let p = ffi::dislmdb_version(&mut major, &mut minor, &mut patch);
        if p.is_null() {
            String::new()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    };
    (s, major, minor, patch)
}

/// Open environment (solo consensus by default).
pub struct Env {
    raw: *mut ffi::DislmdbEnv,
    _path: CString,
}

// Safety: DisLMDB env is used from one thread in these bindings.
unsafe impl Send for Env {}

impl Env {
    pub fn open(path: &Path) -> Result<Self> {
        let path_c = CString::new(path.to_string_lossy().as_ref()).map_err(|_| Error(-1))?;
        let mut raw: *mut ffi::DislmdbEnv = ptr::null_mut();
        check(unsafe { ffi::dislmdb_env_create(&mut raw) })?;

        let mut cfg = ffi::EnvConfig { _bytes: [0; 4096] };
        check(unsafe { ffi::dislmdb_env_config_init(&mut cfg as *mut _ as *mut _) })?;

        // Patch path pointer at start of DISLMDB_env_config (const char *path).
        unsafe {
            let path_slot = cfg._bytes.as_mut_ptr() as *mut *const c_char;
            *path_slot = path_c.as_ptr();
        }

        let rc = unsafe { ffi::dislmdb_env_open(raw, &cfg as *const _ as *const _) };
        if rc != 0 {
            unsafe { ffi::dislmdb_env_close(raw) };
            return Err(Error(rc));
        }
        Ok(Self {
            raw,
            _path: path_c,
        })
    }

    pub fn set_principal(&self, name: &str) -> Result<()> {
        let c = CString::new(name).map_err(|_| Error(-1))?;
        check(unsafe { ffi::dislmdb_acl_set_principal(self.raw, c.as_ptr()) })
    }

    pub fn acl_grant_all(&self, principal: &str) -> Result<()> {
        let c = CString::new(principal).map_err(|_| Error(-1))?;
        check(unsafe { ffi::dislmdb_acl_grant(self.raw, c.as_ptr(), ffi::DISLMDB_ACL_ALL) })
    }

    pub fn put(&self, db: &str, key: &[u8], val: &[u8]) -> Result<()> {
        let mut txn: *mut ffi::DislmdbTxn = ptr::null_mut();
        check(unsafe { ffi::dislmdb_txn_begin(self.raw, ptr::null_mut(), 0, &mut txn) })?;
        let name = CString::new(db).map_err(|_| Error(-1))?;
        let mut dbi: c_uint = 0;
        let mut rc =
            unsafe { ffi::dislmdb_dbi_open(txn, name.as_ptr(), ffi::MDB_CREATE, &mut dbi) };
        if rc != 0 {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return Err(Error(rc));
        }
        let mut k = ffi::MdbVal {
            mv_size: key.len(),
            mv_data: key.as_ptr() as *mut c_void,
        };
        let mut v = ffi::MdbVal {
            mv_size: val.len(),
            mv_data: val.as_ptr() as *mut c_void,
        };
        rc = unsafe { ffi::dislmdb_put(txn, dbi, &mut k, &mut v, 0) };
        if rc != 0 {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return Err(Error(rc));
        }
        check(unsafe { ffi::dislmdb_txn_commit(txn) })
    }

    pub fn get(&self, db: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut txn: *mut ffi::DislmdbTxn = ptr::null_mut();
        check(unsafe { ffi::dislmdb_txn_begin(self.raw, ptr::null_mut(), 0x2_0000, &mut txn) })?;
        let name = CString::new(db).map_err(|_| Error(-1))?;
        let mut dbi: c_uint = 0;
        let mut rc = unsafe { ffi::dislmdb_dbi_open(txn, name.as_ptr(), 0, &mut dbi) };
        if rc != 0 {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return if rc == -30798 {
                // MDB_NOTFOUND for missing DBI
                Ok(None)
            } else {
                Err(Error(rc))
            };
        }
        let mut k = ffi::MdbVal {
            mv_size: key.len(),
            mv_data: key.as_ptr() as *mut c_void,
        };
        let mut v = ffi::MdbVal {
            mv_size: 0,
            mv_data: ptr::null_mut(),
        };
        let mtxn = unsafe { ffi::dislmdb_get_lmdb_txn(txn) };
        rc = unsafe { ffi::mdb_get(mtxn, dbi, &mut k, &mut v) };
        let out = if rc == 0 {
            let slice = unsafe { std::slice::from_raw_parts(v.mv_data as *const u8, v.mv_size) };
            Ok(Some(slice.to_vec()))
        } else if rc == -30798 {
            Ok(None)
        } else {
            Err(Error(rc))
        };
        unsafe { ffi::dislmdb_txn_abort(txn) };
        out
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ffi::dislmdb_env_close(self.raw) };
            self.raw = ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn version_nonempty() {
        let (s, maj, _, _) = version();
        assert!(!s.is_empty());
        assert!(maj >= 0);
    }

    #[test]
    fn solo_put_get() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dislmdb_rs_{stamp}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let env = Env::open(&dir).expect("open");
        env.put("kv", b"hello", b"world").expect("put");
        let got = env.get("kv", b"hello").expect("get");
        assert_eq!(got.as_deref(), Some(&b"world"[..]));
        drop(env);
        let _ = fs::remove_dir_all(&dir);
    }
}
