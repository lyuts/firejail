use std::ffi::{CStr, CString};

pub struct FileDB {
    next: *const FileDB,
    fname: *const libc::c_char, // file name
    len: usize,                // length of file name
}

// find exact name or an exact name in a parent directory
#[unsafe(no_mangle)]
pub extern "C" fn filedb_find(head: *const FileDB, fname: *const libc::c_char) -> *const FileDB {
	assert!(fname != std::ptr::null());

    let mut ptr: *const FileDB = head;
	let mut found: i32 = 0;

	while ptr != std::ptr::null() {
        unsafe {
            // ptr->fname can be a pattern, like .mutter-Xwaylandauth.*
            // check if fname is a match
            if libc::fnmatch((*ptr).fname, fname, libc::FNM_PATHNAME) == 0 {
                found = 1;
                break;
            }

            // parent directory in the list
            if libc::strlen(fname) > (*ptr).len &&
                (*fname.wrapping_add((*ptr).len) as u8) == b'/' &&
                    libc::strncmp((*ptr).fname, fname, (*ptr).len) == 0 {
                        found = 1;
                        break;
                    }

            ptr = (*ptr).next;
        }
	}

	if found != 0 {
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
