use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{BufRead, BufReader},
};

// todo: figure out how to get this from a configure-like step at build time.
const SYSCONFDIR: &str = "/etc/firejail";

pub struct FileDB {
    next: *const FileDB,
    fname: *const libc::c_char, // file name
    len: usize,                 // length of file name
}

#[unsafe(no_mangle)]
pub extern "C" fn filedb_load_whitelist(
    head: *const FileDB,
    fname: *const libc::c_char,
    prefix: *const libc::c_char,
) -> *const FileDB {
    assert!(fname != std::ptr::null());
    assert!(prefix != std::ptr::null());

    let mut curr: *const FileDB = head;
    unsafe {
        let whitelist_file = File::open(format!(
            "{}/{}",
            SYSCONFDIR,
            CStr::from_ptr(fname).to_str().unwrap()
        ))
        .expect("Whitelist file must exist.");
        let reader = BufReader::new(whitelist_file);

        let prefix_str = CStr::from_ptr(prefix).to_str().unwrap();
        for line in reader.lines() {
            let line = line.expect("Must be valid line.");

            if line.starts_with(prefix_str) {
                curr = filedb_add(curr, CString::new(line).unwrap().into_raw());
            }
        }

        return head;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn filedb_add(head: *const FileDB, fname: *const libc::c_char) -> *const FileDB {
    assert!(fname != std::ptr::null());

    // don't add it if it is already there or if the parent directory is already in the list
    if filedb_find(head, fname) != std::ptr::null() {
        return head;
    }

    unsafe {
        // add a new entry
        let entry: *mut FileDB = libc::malloc(size_of::<FileDB>()) as *mut FileDB;
        if entry == std::ptr::null_mut() {
            panic!("malloc");
        }
        libc::memset(entry as *mut libc::c_void, 0, std::mem::size_of::<FileDB>());
        (*entry).fname = libc::strdup(fname);
        if (*entry).fname == std::ptr::null() {
            panic!("strdup");
        }
        (*entry).len = libc::strlen((*entry).fname);
        (*entry).next = head;
        return entry;
    }
}

// find exact name or an exact name in a parent directory
#[unsafe(no_mangle)]
pub extern "C" fn filedb_find(head: *const FileDB, fname: *const libc::c_char) -> *const FileDB {
    assert!(fname != std::ptr::null());

    let mut ptr: *const FileDB = head;
    let mut found = false;

    while ptr != std::ptr::null() {
        unsafe {
            let ptr_fname_str = CStr::from_ptr((*ptr).fname).to_str().unwrap();
            let fname_str = CStr::from_ptr(fname).to_str().unwrap();
            // ptr->fname can be a pattern, like .mutter-Xwaylandauth.*
            // check if fname is a match
            let re_name =
                fnmatch_regex::glob_to_regex(ptr_fname_str).expect("Must be valid regex.");
            found = re_name.is_match(fname_str);
            if found {
                break;
            }

            // if libc::fnmatch((*ptr).fname, fname, libc::FNM_PATHNAME) == 0 {
            //     found = 1;
            //     break;
            // }

            // parent directory in the list
            if fname_str.len() > (*ptr).len
            // if libc::strlen(fname) > (*ptr).len
                && fname_str.ends_with('/')
                // && (*fname.wrapping_add((*ptr).len) as u8) == b'/'
                && ptr_fname_str == fname_str
            // && libc::strncmp((*ptr).fname, fname, (*ptr).len) == 0
            {
                found = true;
                break;
            }

            ptr = (*ptr).next;
        }
    }

    if found {
        return ptr;
    }

    return std::ptr::null();
}

#[unsafe(no_mangle)]
pub extern "C" fn filedb_print(
    head: *const FileDB,
    prefix: *const libc::c_char,
    fp: *mut libc::FILE,
) {
    assert!(head != std::ptr::null());
    assert!(prefix != std::ptr::null());

    let mut ptr: *const FileDB = head;

    while ptr != std::ptr::null() {
        if fp != std::ptr::null_mut() {
            unsafe {
                libc::fprintf(
                    fp,
                    CString::new("%s%s\n").unwrap().as_ptr(),
                    prefix,
                    (*ptr).fname,
                );
            }
        } else {
            unsafe {
                println!(
                    "{}{}\n",
                    CStr::from_ptr(prefix).to_str().unwrap(),
                    CStr::from_ptr((*ptr).fname).to_str().unwrap()
                );
            }
        }
        unsafe {
            ptr = (*ptr).next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // can't have should_panic tests, because of inability to unwind
    // #[test]
    // #[should_panic]
    // fn test_filedb_print_invalid_input_1() {
    //     filedb_print(std::ptr::null(), std::ptr::null(), std::ptr::null_mut());
    // }

    // #[test]
    // #[should_panic]
    // fn test_filedb_print_invalid_input_2() {
    //     let fdb = FileDB {
    //         next: std::ptr::null(),
    //         fname: CString::new("somestring").unwrap().into_raw(),
    //         _len: 0,
    //     };
    //     filedb_print(
    //         &fdb,
    //         CString::new("somestring").unwrap().into_raw(),
    //         std::ptr::null_mut(),
    //     );
    // }

    // #[test]
    // #[should_panic]
    // fn test_filedb_print_invalid_input_3() {
    //     let fdb = FileDB {
    //         next: std::ptr::null(),
    //         fname: CString::new("somestring").unwrap().into_raw(),
    //         _len: 0,
    //     };
    //     let file_name = CString::new("Cargo.lock").expect("CString::new failed");
    //     unsafe {
    //         let fp: *mut libc::FILE =
    //             libc::fopen(file_name.as_ptr(), CString::new("r").unwrap().as_ptr());
    //         filedb_print(
    //             &fdb,
    //             CString::new("someotherstring").unwrap().into_raw(),
    //             fp,
    //         );
    //     }
    // }
}
