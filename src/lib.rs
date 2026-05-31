mod hasp;

pub use hasp::{HaspErrorCodes, HaspFileId, HaspHandle, HaspLibrary};

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn get_feature() -> u32 {
        std::env::var("ENV_FEATURE")
            .unwrap()
            .parse::<u32>()
            .unwrap()
    }

    fn get_vendor_code() -> CString {
        let vendor_code = std::env::var("ENV_VENDOR_CODE").unwrap();
        CString::new(vendor_code).unwrap()
    }

    fn create_hasp_library() -> HaspLibrary {
        let lib_name = libloading::library_filename("hasp_windows_x64_36366");
        let lib = unsafe { libloading::Library::new(lib_name).unwrap() };
        HaspLibrary::new(lib).unwrap()
    }

    fn login_hasp_library() -> HaspHandle {
        let lib = create_hasp_library();
        let vc = get_vendor_code();
        lib.login(get_feature(), &vc).unwrap().unwrap()
    }

    #[test]
    fn login() {
        login_hasp_library();
    }

    #[test]
    fn get_rtc() {
        let handle = login_hasp_library();
        handle.get_rtc().unwrap();
    }

    #[test]
    fn get_size() {
        let handle = login_hasp_library();
        handle.get_size(HaspFileId::RW).unwrap();
    }
}
