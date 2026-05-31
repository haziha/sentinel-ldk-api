use std::ffi::{c_char, c_int, c_uint, c_ulonglong, c_void, CStr};
use std::sync::Arc;

#[derive(Debug, Eq, PartialEq, num_enum::IntoPrimitive, num_enum::FromPrimitive)]
#[repr(i32)]
pub enum HaspErrorCodes {
    /** Request successfully completed */
    StatusOk = 0,

    #[num_enum(catch_all)]
    UnknownError(i32),
}

impl HaspErrorCodes {
    fn ok(self) -> Result<(), Self> {
        if self == HaspErrorCodes::StatusOk {
            Ok(())
        } else {
            Err(self)
        }
    }
}

#[derive(Debug, Eq, PartialEq, num_enum::IntoPrimitive)]
#[repr(u32)]
pub enum HaspFileId {
    RW = 0xFFF4,
    RO = 0xFFFF5,
}

#[derive(Clone)]
pub struct HaspLibrary {
    inner: Arc<HaspLibraryInner>,
}

impl HaspLibrary {
    pub fn new(lib: libloading::Library) -> Result<Self, libloading::Error> {
        let login: libloading::Symbol<unsafe extern "C" fn(c_uint, *const c_char, *mut c_uint)> =
            unsafe { lib.get("hasp_login")? };
        let login = unsafe { std::mem::transmute(login) };

        let logout: libloading::Symbol<unsafe extern "C" fn(c_uint) -> c_int> =
            unsafe { lib.get("hasp_logout")? };
        let logout = unsafe { std::mem::transmute(logout) };

        let encrypt: libloading::Symbol<
            unsafe extern "C" fn(c_uint, *mut c_void, c_uint) -> c_int,
        > = unsafe { lib.get("hasp_encrypt")? };
        let encrypt = unsafe { std::mem::transmute(encrypt) };

        let decrypt: libloading::Symbol<
            unsafe extern "C" fn(c_uint, *mut c_void, c_uint) -> c_int,
        > = unsafe { lib.get("hasp_decrypt")? };
        let decrypt = unsafe { std::mem::transmute(decrypt) };

        let get_rtc: libloading::Symbol<unsafe extern "C" fn(c_uint, *mut c_ulonglong) -> c_int> =
            unsafe { lib.get("hasp_get_rtc")? };
        let get_rtc = unsafe { std::mem::transmute(get_rtc) };

        let get_size: libloading::Symbol<unsafe extern "C" fn(c_uint, c_uint, *mut c_uint)> =
            unsafe { lib.get("hasp_get_size")? };
        let get_size = unsafe { std::mem::transmute(get_size) };

        let read: libloading::Symbol<
            unsafe extern "C" fn(c_uint, c_uint, c_uint, c_uint, *mut c_void),
        > = unsafe { lib.get("hasp_read")? };
        let read = unsafe { std::mem::transmute(read) };

        let write: libloading::Symbol<
            unsafe extern "C" fn(c_uint, c_uint, c_uint, c_uint, *const c_void) -> c_int,
        > = unsafe { lib.get("hasp_write")? };
        let write = unsafe { std::mem::transmute(write) };

        Ok(Self {
            inner: Arc::new(HaspLibraryInner {
                _lib: lib,
                login,
                logout,
                encrypt,
                decrypt,
                get_rtc,
                get_size,
                read,
                write,
            }),
        })
    }

    pub fn login(
        &self,
        feature: u32,
        vendor_code: &CStr,
    ) -> Result<Result<HaspHandle, HaspErrorCodes>, libloading::Error> {
        let mut handle: c_uint = 0;
        let status = unsafe {
            (self.inner.login)(
                feature as c_uint,
                vendor_code.as_ptr(),
                &mut handle as *mut c_uint,
            )
        };
        let status = HaspErrorCodes::from(status);
        if status != HaspErrorCodes::StatusOk {
            return Ok(Err(status));
        }
        HaspHandle::new(self.inner.clone(), handle).map(|v| Ok(v))
    }
}

struct HaspLibraryInner {
    _lib: libloading::Library,

    login: libloading::Symbol<
        'static,
        unsafe extern "C" fn(c_uint, *const c_char, *mut c_uint) -> c_int,
    >,
    logout: libloading::Symbol<'static, unsafe extern "C" fn(c_uint) -> c_int>,

    encrypt:
        libloading::Symbol<'static, unsafe extern "C" fn(c_uint, *mut c_void, c_uint) -> c_int>,
    decrypt:
        libloading::Symbol<'static, unsafe extern "C" fn(c_uint, *mut c_void, c_uint) -> c_int>,

    get_rtc: libloading::Symbol<'static, unsafe extern "C" fn(c_uint, *mut c_ulonglong) -> c_int>,

    get_size:
        libloading::Symbol<'static, unsafe extern "C" fn(c_uint, c_uint, *mut c_uint) -> c_int>,

    read: libloading::Symbol<
        'static,
        unsafe extern "C" fn(c_uint, c_uint, c_uint, c_uint, *mut c_void) -> c_int,
    >,
    write: libloading::Symbol<
        'static,
        unsafe extern "C" fn(c_uint, c_uint, c_uint, c_uint, *const c_void) -> c_int,
    >,
}

impl HaspLibraryInner {
    fn logout(&self, handle: c_uint) -> Result<(), HaspErrorCodes> {
        let status = unsafe { (self.logout)(handle) };
        HaspErrorCodes::from(status).ok()
    }

    fn encrypt(&self, handle: c_uint, data: &mut [u8]) -> Result<(), HaspErrorCodes> {
        let status = unsafe {
            (self.encrypt)(
                handle,
                data.as_mut_ptr() as *mut c_void,
                data.len() as c_uint,
            )
        };
        HaspErrorCodes::from(status).ok()
    }

    fn decrypt(&self, handle: c_uint, data: &mut [u8]) -> Result<(), HaspErrorCodes> {
        let status = unsafe {
            (self.decrypt)(
                handle,
                data.as_mut_ptr() as *mut c_void,
                data.len() as c_uint,
            )
        };
        HaspErrorCodes::from(status).ok()
    }

    fn get_rtc(&self, handle: c_uint) -> Result<u64, HaspErrorCodes> {
        let mut time: u64 = 0;
        let status = unsafe { (self.get_rtc)(handle, &mut time as *mut c_ulonglong) };
        HaspErrorCodes::from(status).ok()?;
        Ok(time)
    }

    fn get_size(&self, handle: c_uint, file_id: HaspFileId) -> Result<u32, HaspErrorCodes> {
        let mut size: u32 = 0;
        let status = unsafe { (self.get_size)(handle, file_id.into(), &mut size as *mut u32) };
        HaspErrorCodes::from(status).ok()?;
        Ok(size)
    }

    fn read(
        &self,
        handle: c_uint,
        file_id: HaspFileId,
        offset: u32,
        data: &mut [u8],
    ) -> Result<(), HaspErrorCodes> {
        let status = unsafe {
            (self.read)(
                handle,
                file_id.into(),
                offset,
                data.len() as c_uint,
                data.as_mut_ptr() as *mut c_void,
            )
        };

        HaspErrorCodes::from(status).ok()
    }

    fn write(
        &self,
        handle: c_uint,
        file_id: HaspFileId,
        offset: u32,
        data: &[u8],
    ) -> Result<(), HaspErrorCodes> {
        let status = unsafe {
            (self.write)(
                handle,
                file_id.into(),
                offset,
                data.len() as c_uint,
                data.as_ptr() as *const c_void,
            )
        };
        HaspErrorCodes::from(status).ok()
    }
}

#[derive(Clone)]
pub struct HaspHandle {
    lib: Arc<HaspLibraryInner>,
    handle: c_uint,
}

impl HaspHandle {
    fn new(lib: Arc<HaspLibraryInner>, handle: c_uint) -> Result<Self, libloading::Error> {
        Ok(Self { lib, handle })
    }

    pub fn encrypt(&self, data: &mut [u8]) -> Result<(), HaspErrorCodes> {
        self.lib.encrypt(self.handle, data)
    }

    pub fn decrypt(&self, data: &mut [u8]) -> Result<(), HaspErrorCodes> {
        self.lib.decrypt(self.handle, data)
    }

    pub fn get_rtc(&self) -> Result<u64, HaspErrorCodes> {
        self.lib.get_rtc(self.handle)
    }

    pub fn get_size(&self, file_id: HaspFileId) -> Result<u32, HaspErrorCodes> {
        self.lib.get_size(self.handle, file_id)
    }

    pub fn read(
        &self,
        file_id: HaspFileId,
        offset: u32,
        data: &mut [u8],
    ) -> Result<(), HaspErrorCodes> {
        self.lib.read(self.handle, file_id, offset, data)
    }

    pub fn write(
        &self,
        file_id: HaspFileId,
        offset: u32,
        data: &[u8],
    ) -> Result<(), HaspErrorCodes> {
        self.lib.write(self.handle, file_id, offset, data)
    }
}

impl Drop for HaspHandle {
    fn drop(&mut self) {
        let status = self.lib.logout(self.handle);
        if let Err(status) = status {
            eprintln!("HASP Logout failed ({:?}).", status); // todo
        }
    }
}
