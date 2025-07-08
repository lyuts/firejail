use std::{
    ffi::{CStr, CString, c_char, c_int},
    path::Path,
};
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

// return NULL if fname is already a directory, or if no directory found
#[unsafe(no_mangle)]
pub extern "C" fn extract_dir(c_str: *const c_char) -> *const c_char {
    let fname = unsafe { CStr::from_ptr(c_str) };
    if let Ok(fname_str) = fname.to_str() {
        match extract_directory(fname_str) {
            Ok(s) => CString::new(s).unwrap().into_raw(),
            _ => std::ptr::null(),
        }
    } else {
        std::ptr::null()
    }
}

fn extract_directory(fname: &str) -> std::io::Result<&str> {
    if is_directory(fname)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::IsADirectory,
            "Path is already a directory.",
        ));
    }
    let path = Path::new(fname);

    path.parent()
        .ok_or(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Unable to find parent directory.",
        ))
        .map(|p| p.to_str().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_dir_valid_dir() {
        let r = is_directory("./target");
        assert!(r.is_ok());
        assert!(r.unwrap());
    }

    #[test]
    fn test_is_dir_invalid_dir() {
        assert!(is_directory("./no_such_directory").is_err());
    }

    #[test]
    fn test_is_dir_valid_file() {
        let r = is_directory("./Cargo.lock");
        assert!(r.is_ok());
        assert!(!r.unwrap());
    }

    #[test]
    fn test_is_dir_invalid_file() {
        assert!(is_directory("./no_such_file.txt").is_err());
    }

    #[test]
    fn test_extract_directory() {
        assert!(extract_directory("./target").is_err());
        assert!(extract_directory("./target/CACHEDIR.TAG").is_ok());
    }
}
