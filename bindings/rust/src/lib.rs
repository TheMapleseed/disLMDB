//! Safe Rust bindings over the DisLMDB C ABI (`bindings/ABI.kdl`).
//!
//! Build `libdislmdb` first (`make lib`), then `cargo test -p dislmdb` from
//! this crate directory (links `../../build/lib`).

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::path::Path;
use std::ptr;

mod offsets {
    include!(concat!(env!("OUT_DIR"), "/offsets.rs"));
}

mod ffi {
    use super::*;

    pub type DislmdbEnv = c_void;
    pub type DislmdbTxn = c_void;

    #[repr(C)]
    pub struct MdbVal {
        pub mv_size: usize,
        pub mv_data: *mut c_void,
    }

    pub type IndexScanCb = Option<
        unsafe extern "C" fn(
            secondary_key: *const MdbVal,
            primary_key: *const MdbVal,
            primary_val: *const MdbVal,
            user: *mut c_void,
        ) -> c_int,
    >;

    unsafe extern "C" {
        pub fn dislmdb_version(major: *mut c_int, minor: *mut c_int, patch: *mut c_int)
            -> *const c_char;
        pub fn dislmdb_strerror(err: c_int) -> *const c_char;
        pub fn dislmdb_env_config_init(config: *mut c_void) -> c_int;
        pub fn dislmdb_env_create(env: *mut *mut DislmdbEnv) -> c_int;
        pub fn dislmdb_env_open(env: *mut DislmdbEnv, config: *const c_void) -> c_int;
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
        pub fn dislmdb_del(
            txn: *mut DislmdbTxn,
            dbi: c_uint,
            key: *mut MdbVal,
            data: *mut MdbVal,
        ) -> c_int;
        pub fn dislmdb_index_put(
            txn: *mut DislmdbTxn,
            primary_dbi: c_uint,
            index_dbi: c_uint,
            primary_key: *mut MdbVal,
            primary_val: *mut MdbVal,
            secondary_key: *mut MdbVal,
            flags: c_uint,
        ) -> c_int;
        pub fn dislmdb_index_del(
            txn: *mut DislmdbTxn,
            primary_dbi: c_uint,
            index_dbi: c_uint,
            primary_key: *mut MdbVal,
            secondary_key: *mut MdbVal,
        ) -> c_int;
        pub fn dislmdb_index_get(
            txn: *mut DislmdbTxn,
            primary_dbi: c_uint,
            index_dbi: c_uint,
            secondary_key: *mut MdbVal,
            primary_key_out: *mut MdbVal,
            primary_val_out: *mut MdbVal,
        ) -> c_int;
        pub fn dislmdb_index_scan(
            txn: *mut DislmdbTxn,
            primary_dbi: c_uint,
            index_dbi: c_uint,
            start_key: *const MdbVal,
            prefix: *const MdbVal,
            limit: usize,
            cb: IndexScanCb,
            user: *mut c_void,
        ) -> c_int;
        pub fn dislmdb_put_versioned(
            txn: *mut DislmdbTxn,
            dbi: c_uint,
            key: *mut MdbVal,
            data: *mut MdbVal,
            flags: c_uint,
            version: u64,
        ) -> c_int;
        pub fn dislmdb_get_versioned(
            txn: *mut DislmdbTxn,
            dbi: c_uint,
            key: *mut MdbVal,
            version_out: *mut u64,
            data_out: *mut c_void,
            data_cap: *mut usize,
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
        pub fn dislmdb_acl_grant_prefix(
            env: *mut DislmdbEnv,
            principal: *const c_char,
            key_prefix: *const c_char,
            perms: c_uint,
        ) -> c_int;
        pub fn dislmdb_acl_role_define(
            env: *mut DislmdbEnv,
            role: *const c_char,
            key_prefix: *const c_char,
            perms: c_uint,
        ) -> c_int;
        pub fn dislmdb_acl_role_undefine(env: *mut DislmdbEnv, role: *const c_char) -> c_int;
        pub fn dislmdb_acl_role_get(
            env: *mut DislmdbEnv,
            role: *const c_char,
            perms_out: *mut c_uint,
            prefix_out: *mut c_char,
            prefix_cap: usize,
        ) -> c_int;
        pub fn dislmdb_acl_role_assign(
            env: *mut DislmdbEnv,
            principal: *const c_char,
            role: *const c_char,
        ) -> c_int;
        pub fn dislmdb_acl_role_unassign(
            env: *mut DislmdbEnv,
            principal: *const c_char,
            role: *const c_char,
        ) -> c_int;
        pub fn dislmdb_acl_effective(
            env: *mut DislmdbEnv,
            principal: *const c_char,
            perms_out: *mut c_uint,
        ) -> c_int;
    }

    pub const MDB_CREATE: c_uint = 0x4_0000;
    pub const MDB_RDONLY: c_uint = 0x2_0000;
    pub const MDB_NOTFOUND: c_int = -30798;
}

/// ACL capability bits (match `dislmdb_errors.h`).
pub const ACL_ALL: u32 = 0x7;
pub const ACL_READ: u32 = 0x1;
pub const ACL_WRITE: u32 = 0x2;
pub const ACL_ADMIN: u32 = 0x4;

/// One row from [`Env::index_scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub secondary_key: Vec<u8>,
    pub primary_key: Vec<u8>,
    pub primary_val: Vec<u8>,
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

fn mdb_val(bytes: &[u8]) -> ffi::MdbVal {
    ffi::MdbVal {
        mv_size: bytes.len(),
        mv_data: bytes.as_ptr() as *mut c_void,
    }
}

fn copy_mdb(v: &ffi::MdbVal) -> Vec<u8> {
    if v.mv_data.is_null() || v.mv_size == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(v.mv_data as *const u8, v.mv_size) }.to_vec()
}

unsafe extern "C" fn index_scan_trampoline(
    secondary_key: *const ffi::MdbVal,
    primary_key: *const ffi::MdbVal,
    primary_val: *const ffi::MdbVal,
    user: *mut c_void,
) -> c_int {
    // Safety: caller passes a live &mut Vec<IndexEntry> for the scan duration.
    let out = unsafe { &mut *(user as *mut Vec<IndexEntry>) };
    let sk = unsafe { &*secondary_key };
    let pk = unsafe { &*primary_key };
    let pv = unsafe { &*primary_val };
    out.push(IndexEntry {
        secondary_key: copy_mdb(sk),
        primary_key: copy_mdb(pk),
        primary_val: copy_mdb(pv),
    });
    0
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

/// Open options for [`Env::open_with`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenOptions {
    /// When true, enables ACL / RBAC enforcement (`DISLMDB_env_config.enable_acl`).
    pub enable_acl: bool,
    /// Named DBI budget (0 = leave C default after init).
    pub maxdbs: u32,
}

/// Open environment (**solo** consensus + ephemeral `local_port=0` by default).
pub struct Env {
    raw: *mut ffi::DislmdbEnv,
    _path: CString,
}

// Safety: DisLMDB env is used from one thread in these bindings.
unsafe impl Send for Env {}

impl Env {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with(path, OpenOptions::default())
    }

    pub fn open_with(path: &Path, opts: OpenOptions) -> Result<Self> {
        let path_c = CString::new(path.to_string_lossy().as_ref()).map_err(|_| Error(-1))?;
        let mut raw: *mut ffi::DislmdbEnv = ptr::null_mut();
        check(unsafe { ffi::dislmdb_env_create(&mut raw) })?;

        let mut cfg = vec![0u8; offsets::ENV_CONFIG_SIZE];
        check(unsafe { ffi::dislmdb_env_config_init(cfg.as_mut_ptr() as *mut c_void) })?;

        // Patch path (offset 0), force SOLO + port 0, optional maxdbs / enable_acl.
        // C config_init defaults to PBFT:9876; bindings open is single-process.
        unsafe {
            let base = cfg.as_mut_ptr();
            let path_slot = base as *mut *const c_char;
            *path_slot = path_c.as_ptr();
            let mech = base.add(offsets::OFFSETOF_CONSENSUS_MECH) as *mut u32;
            *mech = offsets::CONSENSUS_SOLO;
            let port = base.add(offsets::OFFSETOF_LOCAL_PORT) as *mut u16;
            *port = 0;
            if opts.maxdbs != 0 {
                let slot = base.add(offsets::OFFSETOF_MAXDBS) as *mut c_uint;
                *slot = opts.maxdbs;
            }
            if opts.enable_acl {
                let slot = base.add(offsets::OFFSETOF_ENABLE_ACL) as *mut u8;
                *slot = 1;
            }
        }

        let rc = unsafe { ffi::dislmdb_env_open(raw, cfg.as_ptr() as *const c_void) };
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
        check(unsafe { ffi::dislmdb_acl_grant(self.raw, c.as_ptr(), ACL_ALL) })
    }

    pub fn acl_grant_prefix(&self, principal: &str, prefix: &str, perms: u32) -> Result<()> {
        let p = CString::new(principal).map_err(|_| Error(-1))?;
        let pre = CString::new(prefix).map_err(|_| Error(-1))?;
        check(unsafe {
            ffi::dislmdb_acl_grant_prefix(self.raw, p.as_ptr(), pre.as_ptr(), perms)
        })
    }

    /// Define or update an RBAC role. `prefix = None` / empty ⇒ global role.
    pub fn acl_role_define(&self, role: &str, prefix: Option<&str>, perms: u32) -> Result<()> {
        let r = CString::new(role).map_err(|_| Error(-1))?;
        let pfx_owned = prefix
            .filter(|s| !s.is_empty())
            .map(CString::new)
            .transpose()
            .map_err(|_| Error(-1))?;
        let pfx_ptr = pfx_owned
            .as_ref()
            .map(|c| c.as_ptr())
            .unwrap_or(ptr::null());
        check(unsafe { ffi::dislmdb_acl_role_define(self.raw, r.as_ptr(), pfx_ptr, perms) })
    }

    pub fn acl_role_undefine(&self, role: &str) -> Result<()> {
        let r = CString::new(role).map_err(|_| Error(-1))?;
        check(unsafe { ffi::dislmdb_acl_role_undefine(self.raw, r.as_ptr()) })
    }

    pub fn acl_role_get(&self, role: &str) -> Result<(u32, String)> {
        let r = CString::new(role).map_err(|_| Error(-1))?;
        let mut perms: c_uint = 0;
        let mut buf = vec![0u8; 128];
        check(unsafe {
            ffi::dislmdb_acl_role_get(
                self.raw,
                r.as_ptr(),
                &mut perms,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
            )
        })?;
        let prefix = CStr::from_bytes_until_nul(&buf)
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok((perms, prefix))
    }

    pub fn acl_role_assign(&self, principal: &str, role: &str) -> Result<()> {
        let p = CString::new(principal).map_err(|_| Error(-1))?;
        let r = CString::new(role).map_err(|_| Error(-1))?;
        check(unsafe { ffi::dislmdb_acl_role_assign(self.raw, p.as_ptr(), r.as_ptr()) })
    }

    pub fn acl_role_unassign(&self, principal: &str, role: &str) -> Result<()> {
        let p = CString::new(principal).map_err(|_| Error(-1))?;
        let r = CString::new(role).map_err(|_| Error(-1))?;
        check(unsafe { ffi::dislmdb_acl_role_unassign(self.raw, p.as_ptr(), r.as_ptr()) })
    }

    pub fn acl_effective(&self, principal: &str) -> Result<u32> {
        let p = CString::new(principal).map_err(|_| Error(-1))?;
        let mut perms: c_uint = 0;
        check(unsafe { ffi::dislmdb_acl_effective(self.raw, p.as_ptr(), &mut perms) })?;
        Ok(perms)
    }

    pub fn put(&self, db: &str, key: &[u8], val: &[u8]) -> Result<()> {
        self.with_write_txn(db, |txn, dbi| {
            let mut k = mdb_val(key);
            let mut v = mdb_val(val);
            check(unsafe { ffi::dislmdb_put(txn, dbi, &mut k, &mut v, 0) })
        })
    }

    pub fn del(&self, db: &str, key: &[u8]) -> Result<()> {
        self.with_write_txn(db, |txn, dbi| {
            let mut k = mdb_val(key);
            check(unsafe { ffi::dislmdb_del(txn, dbi, &mut k, ptr::null_mut()) })
        })
    }

    pub fn index_put(
        &self,
        primary_db: &str,
        index_db: &str,
        primary_key: &[u8],
        primary_val: &[u8],
        secondary_key: &[u8],
    ) -> Result<()> {
        self.with_index_txn(primary_db, index_db, true, |txn, primary, index| {
            let mut pk = mdb_val(primary_key);
            let mut pv = mdb_val(primary_val);
            let mut sk = mdb_val(secondary_key);
            check(unsafe {
                ffi::dislmdb_index_put(txn, primary, index, &mut pk, &mut pv, &mut sk, 0)
            })
        })
    }

    pub fn index_del(
        &self,
        primary_db: &str,
        index_db: &str,
        primary_key: &[u8],
        secondary_key: &[u8],
    ) -> Result<()> {
        self.with_index_txn(primary_db, index_db, true, |txn, primary, index| {
            let mut pk = mdb_val(primary_key);
            let mut sk = mdb_val(secondary_key);
            check(unsafe { ffi::dislmdb_index_del(txn, primary, index, &mut pk, &mut sk) })
        })
    }

    /// Lookup via secondary index → `(primary_key, primary_val)`.
    pub fn index_get(
        &self,
        primary_db: &str,
        index_db: &str,
        secondary_key: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        self.with_index_read(primary_db, index_db, |txn, primary, index| {
            let mut sk = mdb_val(secondary_key);
            let mut pk = ffi::MdbVal {
                mv_size: 0,
                mv_data: ptr::null_mut(),
            };
            let mut pv = ffi::MdbVal {
                mv_size: 0,
                mv_data: ptr::null_mut(),
            };
            let rc = unsafe {
                ffi::dislmdb_index_get(txn, primary, index, &mut sk, &mut pk, &mut pv)
            };
            if rc == ffi::MDB_NOTFOUND {
                return Ok(None);
            }
            check(rc)?;
            Ok(Some((copy_mdb(&pk), copy_mdb(&pv))))
        })
    }

    /// Scan secondary index. `prefix = None` ⇒ no filter; `limit = 0` ⇒ unlimited.
    pub fn index_scan(
        &self,
        primary_db: &str,
        index_db: &str,
        prefix: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<IndexEntry>> {
        self.with_index_read(primary_db, index_db, |txn, primary, index| {
            let mut out: Vec<IndexEntry> = Vec::new();
            let pfx_owned = prefix.map(mdb_val);
            let pfx_ptr = pfx_owned
                .as_ref()
                .map(|v| v as *const ffi::MdbVal)
                .unwrap_or(ptr::null());
            let rc = unsafe {
                ffi::dislmdb_index_scan(
                    txn,
                    primary,
                    index,
                    ptr::null(),
                    pfx_ptr,
                    limit,
                    Some(index_scan_trampoline),
                    &mut out as *mut _ as *mut c_void,
                )
            };
            check(rc)?;
            Ok(out)
        })
    }

    pub fn put_versioned(&self, db: &str, key: &[u8], val: &[u8], version: u64) -> Result<()> {
        self.with_write_txn(db, |txn, dbi| {
            let mut k = mdb_val(key);
            let mut v = mdb_val(val);
            check(unsafe { ffi::dislmdb_put_versioned(txn, dbi, &mut k, &mut v, 0, version) })
        })
    }

    pub fn get_versioned(&self, db: &str, key: &[u8]) -> Result<Option<(u64, Vec<u8>)>> {
        let mut txn: *mut ffi::DislmdbTxn = ptr::null_mut();
        check(unsafe {
            ffi::dislmdb_txn_begin(self.raw, ptr::null_mut(), ffi::MDB_RDONLY, &mut txn)
        })?;
        let name = CString::new(db).map_err(|_| Error(-1))?;
        let mut dbi: c_uint = 0;
        let mut rc = unsafe { ffi::dislmdb_dbi_open(txn, name.as_ptr(), 0, &mut dbi) };
        if rc != 0 {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return if rc == ffi::MDB_NOTFOUND {
                Ok(None)
            } else {
                Err(Error(rc))
            };
        }
        let mut k = mdb_val(key);
        let mut ver: u64 = 0;
        let mut cap: usize = 0;
        rc = unsafe {
            ffi::dislmdb_get_versioned(txn, dbi, &mut k, &mut ver, ptr::null_mut(), &mut cap)
        };
        if rc == ffi::MDB_NOTFOUND {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return Ok(None);
        }
        if rc != 0 {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return Err(Error(rc));
        }
        let mut buf = vec![0u8; cap];
        let mut k2 = mdb_val(key);
        rc = unsafe {
            ffi::dislmdb_get_versioned(
                txn,
                dbi,
                &mut k2,
                &mut ver,
                buf.as_mut_ptr() as *mut c_void,
                &mut cap,
            )
        };
        unsafe { ffi::dislmdb_txn_abort(txn) };
        check(rc)?;
        buf.truncate(cap);
        Ok(Some((ver, buf)))
    }

    pub fn get(&self, db: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut txn: *mut ffi::DislmdbTxn = ptr::null_mut();
        check(unsafe {
            ffi::dislmdb_txn_begin(self.raw, ptr::null_mut(), ffi::MDB_RDONLY, &mut txn)
        })?;
        let name = CString::new(db).map_err(|_| Error(-1))?;
        let mut dbi: c_uint = 0;
        let mut rc = unsafe { ffi::dislmdb_dbi_open(txn, name.as_ptr(), 0, &mut dbi) };
        if rc != 0 {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return if rc == ffi::MDB_NOTFOUND {
                Ok(None)
            } else {
                Err(Error(rc))
            };
        }
        let mut k = mdb_val(key);
        let mut v = ffi::MdbVal {
            mv_size: 0,
            mv_data: ptr::null_mut(),
        };
        let mtxn = unsafe { ffi::dislmdb_get_lmdb_txn(txn) };
        rc = unsafe { ffi::mdb_get(mtxn, dbi, &mut k, &mut v) };
        let out = if rc == 0 {
            Ok(Some(copy_mdb(&v)))
        } else if rc == ffi::MDB_NOTFOUND {
            Ok(None)
        } else {
            Err(Error(rc))
        };
        unsafe { ffi::dislmdb_txn_abort(txn) };
        out
    }

    fn with_write_txn<F>(&self, db: &str, f: F) -> Result<()>
    where
        F: FnOnce(*mut ffi::DislmdbTxn, c_uint) -> Result<()>,
    {
        let mut txn: *mut ffi::DislmdbTxn = ptr::null_mut();
        check(unsafe { ffi::dislmdb_txn_begin(self.raw, ptr::null_mut(), 0, &mut txn) })?;
        let name = CString::new(db).map_err(|_| Error(-1))?;
        let mut dbi: c_uint = 0;
        let rc = unsafe { ffi::dislmdb_dbi_open(txn, name.as_ptr(), ffi::MDB_CREATE, &mut dbi) };
        if rc != 0 {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return Err(Error(rc));
        }
        match f(txn, dbi) {
            Ok(()) => {
                let rc = unsafe { ffi::dislmdb_txn_commit(txn) };
                // commit always consumes the handle; abort is a safe no-op after.
                if rc != 0 {
                    unsafe { ffi::dislmdb_txn_abort(txn) };
                }
                check(rc)
            }
            Err(e) => {
                unsafe { ffi::dislmdb_txn_abort(txn) };
                Err(e)
            }
        }
    }

    fn with_index_txn<F>(&self, primary_db: &str, index_db: &str, create: bool, f: F) -> Result<()>
    where
        F: FnOnce(*mut ffi::DislmdbTxn, c_uint, c_uint) -> Result<()>,
    {
        let mut txn: *mut ffi::DislmdbTxn = ptr::null_mut();
        check(unsafe { ffi::dislmdb_txn_begin(self.raw, ptr::null_mut(), 0, &mut txn) })?;
        let flags = if create { ffi::MDB_CREATE } else { 0 };
        let pname = CString::new(primary_db).map_err(|_| Error(-1))?;
        let iname = CString::new(index_db).map_err(|_| Error(-1))?;
        let mut primary: c_uint = 0;
        let mut index: c_uint = 0;
        let mut rc =
            unsafe { ffi::dislmdb_dbi_open(txn, pname.as_ptr(), flags, &mut primary) };
        if rc != 0 {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return Err(Error(rc));
        }
        rc = unsafe { ffi::dislmdb_dbi_open(txn, iname.as_ptr(), flags, &mut index) };
        if rc != 0 {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return Err(Error(rc));
        }
        match f(txn, primary, index) {
            Ok(()) => {
                let crc = unsafe { ffi::dislmdb_txn_commit(txn) };
                if crc != 0 {
                    unsafe { ffi::dislmdb_txn_abort(txn) };
                }
                check(crc)
            }
            Err(e) => {
                unsafe { ffi::dislmdb_txn_abort(txn) };
                Err(e)
            }
        }
    }

    fn with_index_read<T, F>(&self, primary_db: &str, index_db: &str, f: F) -> Result<T>
    where
        F: FnOnce(*mut ffi::DislmdbTxn, c_uint, c_uint) -> Result<T>,
    {
        let mut txn: *mut ffi::DislmdbTxn = ptr::null_mut();
        check(unsafe {
            ffi::dislmdb_txn_begin(self.raw, ptr::null_mut(), ffi::MDB_RDONLY, &mut txn)
        })?;
        let pname = CString::new(primary_db).map_err(|_| Error(-1))?;
        let iname = CString::new(index_db).map_err(|_| Error(-1))?;
        let mut primary: c_uint = 0;
        let mut index: c_uint = 0;
        let mut rc = unsafe { ffi::dislmdb_dbi_open(txn, pname.as_ptr(), 0, &mut primary) };
        if rc != 0 {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return Err(Error(rc));
        }
        rc = unsafe { ffi::dislmdb_dbi_open(txn, iname.as_ptr(), 0, &mut index) };
        if rc != 0 {
            unsafe { ffi::dislmdb_txn_abort(txn) };
            return Err(Error(rc));
        }
        let out = f(txn, primary, index);
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
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Env open binds a default UDP/TCP port; serialize opens across tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dislmdb_rs_{tag}_{stamp}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn version_nonempty() {
        let (s, maj, _, _) = version();
        assert!(!s.is_empty());
        assert!(maj >= 0);
    }

    #[test]
    fn solo_kv_index_versioned() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tmp_dir("kv");
        let env = Env::open(&dir).expect("open");
        // Stay within default maxdbs(=2): primary + index only.
        env.put("entities", b"hello", b"world").expect("put");
        let got = env.get("entities", b"hello").expect("get");
        assert_eq!(got.as_deref(), Some(&b"world"[..]));
        env.del("entities", b"hello").expect("del");
        assert!(env.get("entities", b"hello").unwrap().is_none());

        env.index_put("entities", "idx_name", b"\x01\x02", b"alice", b"alice")
            .expect("index_put");
        let pk = env.get("idx_name", b"alice").expect("idx get");
        assert_eq!(pk.as_deref(), Some(&[0x01u8, 0x02][..]));

        let (got_pk, got_pv) = env
            .index_get("entities", "idx_name", b"alice")
            .expect("index_get")
            .expect("found");
        assert_eq!(got_pk, b"\x01\x02");
        assert_eq!(got_pv, b"alice");

        env.index_put("entities", "idx_name", b"u2", b"amy", b"amy")
            .expect("index_put amy");
        env.index_put("entities", "idx_name", b"u3", b"bob", b"bob")
            .expect("index_put bob");
        let scan_a = env
            .index_scan("entities", "idx_name", Some(b"a"), 0)
            .expect("scan a");
        assert_eq!(scan_a.len(), 2);
        let scan_lim = env
            .index_scan("entities", "idx_name", None, 1)
            .expect("scan lim");
        assert_eq!(scan_lim.len(), 1);

        env.index_del("entities", "idx_name", b"\x01\x02", b"alice")
            .expect("index_del");

        env.put_versioned("entities", b"doc", b"v1", 10).expect("v10");
        assert!(env.put_versioned("entities", b"doc", b"old", 5).is_err());
        env.put_versioned("entities", b"doc", b"v2", 20).expect("v20");
        let (ver, payload) = env.get_versioned("entities", b"doc").unwrap().unwrap();
        assert_eq!(ver, 20);
        assert_eq!(payload, b"v2");
        drop(env);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rbac_roles() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tmp_dir("rbac");
        let env = Env::open_with(
            &dir,
            OpenOptions {
                enable_acl: true,
                maxdbs: 8,
            },
        )
        .expect("open acl");
        env.set_principal("alice").expect("principal");
        env.acl_grant_all("alice").expect("grant");
        env.acl_role_define("writer", None, ACL_READ | ACL_WRITE)
            .expect("define writer");
        env.acl_role_define("tenant_dave", Some("dave/"), ACL_READ | ACL_WRITE)
            .expect("define tenant");
        let (perms, pfx) = env.acl_role_get("tenant_dave").expect("role_get");
        assert_eq!(perms, ACL_READ | ACL_WRITE);
        assert_eq!(pfx, "dave/");
        env.acl_role_assign("eve", "writer").expect("assign eve");
        env.acl_role_assign("dave", "tenant_dave")
            .expect("assign dave");
        let eff = env.acl_effective("eve").expect("eff");
        assert_eq!(eff & (ACL_READ | ACL_WRITE), ACL_READ | ACL_WRITE);
        env.set_principal("eve").expect("as eve");
        env.put("kv", b"anywhere", b"1").expect("eve put");
        env.set_principal("dave").expect("as dave");
        assert!(env.put("kv", b"eve/x", b"n").is_err());
        env.put("kv", b"dave/inbox", b"y").expect("dave own");
        env.set_principal("alice").expect("as alice");
        env.acl_role_unassign("dave", "tenant_dave")
            .expect("unassign");
        env.set_principal("dave").expect("as dave gone");
        assert!(env.put("kv", b"dave/z", b"n").is_err());
        drop(env);
        let _ = fs::remove_dir_all(&dir);
    }
}
