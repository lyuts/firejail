use std::ffi::{c_char, c_int, CStr};

// todo: duplicated from src/firejail/util.c - remove dplication
// return 1 if the file is a directory
#[unsafe(no_mangle)]
pub extern "C" fn is_dir(c_str: *const c_char) -> c_int {
    let fname = unsafe { CStr::from_ptr(c_str) };
    if let Ok(fname_str) = fname.to_str() {
        match is_directory(fname_str) {
            Ok(true) => 1,
            _ => 0,
        }
    } else {
        -1
    }
}

fn is_directory(fname: &str) -> std::io::Result<bool> {
    Ok(std::fs::metadata(fname)?.is_dir())
}

