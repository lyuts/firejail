use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    fs::File,
    io::{BufRead, BufReader},
    sync::Mutex,
};

// todo: figure out how to get this from a configure-like step at build time.
const SYSCONFDIR: &str = "/etc/firejail";

lazy_static! {
    static ref FILEDBS: Mutex<HashMap<libc::uintptr_t, Vec<String>>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
}

#[repr(C)]
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
                // we don't do into_raw because filedb_add is already in rust
                filedb_add(head, CString::new(line).unwrap().as_ptr());
            }
        }

        return head;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn filedb_add(head: *const FileDB, fname: *const libc::c_char) -> *const FileDB {
    assert!(fname != std::ptr::null());

    let mut dbs = FILEDBS.lock().unwrap();
    if !dbs.contains_key(&(head as libc::uintptr_t)) {
        dbs.insert(head as libc::uintptr_t, vec![]);
    }

    unsafe {
        let rust_fname = CString::new(CStr::from_ptr(fname).to_bytes())
            .unwrap()
            .into_string()
            .unwrap();

        if dbs
            .get(&(head as libc::uintptr_t))
            .unwrap()
            .contains(&rust_fname)
        {
            return head;
        }

        // why not push? to preserve the behavior of the original file db implementation.
        dbs.get_mut(&(head as libc::uintptr_t))
            .unwrap()
            .insert(0, rust_fname);

        // println!("DBG DB[{:x?}].vec = {:?}", head, dbs.get(&(head as libc::uintptr_t)).unwrap());
    }

    return head;
}

// find exact name or an exact name in a parent directory
#[unsafe(no_mangle)]
pub extern "C" fn filedb_find_old(
    head: *const FileDB,
    fname: *const libc::c_char,
) -> *const FileDB {
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
            //     found = true;
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
pub extern "C" fn filedb_find(head: *const FileDB, fname: *const libc::c_char) -> *const FileDB {
    assert!(fname != std::ptr::null());

    let mut dbs = FILEDBS.lock().unwrap();
    if !dbs.contains_key(&(head as libc::uintptr_t)) {
        return std::ptr::null();
    }
    let mut found = false;

    let mut found_str = &String::new();

    for ptr_fname_str in dbs.get(&(head as libc::uintptr_t)).unwrap().iter() {
        unsafe {
            let fname_str = CStr::from_ptr(fname).to_str().unwrap();
            // ptr->fname can be a pattern, like .mutter-Xwaylandauth.*
            // check if fname is a match
            let re_name =
                fnmatch_regex::glob_to_regex(&ptr_fname_str).expect("Must be valid regex.");
            found = re_name.is_match(fname_str);
            if found {
                found_str = ptr_fname_str;
                println!("filedb_find> fnmatched {} by {}", fname_str, ptr_fname_str);
                break;
            }

            // parent directory in the list
            if fname_str.len() > ptr_fname_str.len()
            // if libc::strlen(fname) > (*ptr).len
                && fname_str.ends_with('/')
                // && (*fname.wrapping_add((*ptr).len) as u8) == b'/'
                && ptr_fname_str == fname_str
            // && libc::strncmp((*ptr).fname, fname, (*ptr).len) == 0
            {
                found = true;
                found_str = ptr_fname_str;
                break;
            }
        }
    }

    if found {
        // it doesn't matter what pointer we return. C code doesn't use it except for binary
        // found/didn't find checks.
        return 0xabcdef as *const FileDB;
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
                println!(
                    "{}{}\n",
                    CStr::from_ptr(prefix).to_str().unwrap(),
                    CStr::from_ptr((*ptr).fname).to_str().unwrap()
                );
                libc::fprintf(fp, c"%s%s\n".as_ptr(), prefix, (*ptr).fname);
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

#[unsafe(no_mangle)]
pub extern "C" fn write_filedb_to_file_as_line(
    head: *const FileDB,
    sep: *const char,
    fp: *mut libc::FILE,
) {
    let dbs = FILEDBS.lock().unwrap();
    if !dbs.contains_key(&(head as libc::uintptr_t)) {
        unsafe {
            libc::fprintf(fp, c"\n".as_ptr());
        }
        return;
    }

    for ptr_fname_str in dbs.get(&(head as libc::uintptr_t)).unwrap().iter() {
        unsafe {
            println!("WRITING {}", ptr_fname_str);
            libc::fprintf(
                fp,
                c"%s%s".as_ptr(),
                CString::new(ptr_fname_str.as_bytes()).unwrap().into_raw(),
                sep,
            );
        }
    }
    unsafe {
        libc::fprintf(fp, c"\n".as_ptr());
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn write_filedb_to_file_lines(
    head: *const FileDB,
    prefix: *const char,
    fp: *mut libc::FILE,
) {
    let mut dbs = FILEDBS.lock().unwrap();
    if !dbs.contains_key(&(head as libc::uintptr_t)) {
        return;
    }

    for ptr_fname_str in dbs.get(&(head as libc::uintptr_t)).unwrap().iter() {
        unsafe {
            println!("WRITING {}", ptr_fname_str);
            libc::fprintf(
                fp,
                c"%s%s\n".as_ptr(),
                prefix,
                CString::new(ptr_fname_str.as_bytes()).unwrap().into_raw(),
            );
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn filedb_is_empty(head: *const FileDB) -> libc::c_int {
    let dbs = FILEDBS.lock().unwrap();

    if dbs.contains_key(&(head as libc::uintptr_t))
        && !dbs.get(&(head as libc::uintptr_t)).unwrap().is_empty()
    {
        return 0;
    } else {
        return 1;
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
