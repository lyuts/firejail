use std::{
    ffi::{CStr, CString, OsStr},
    path::Path,
};

use crate::{
    FileDB, filedb_add, filedb_is_empty,
    trace::{Action, process_syscalls_from_trace_file},
    write_filedb_to_file_as_line,
};

/// Process trace file pointed to by fname, fname.1, fname.2, fname.3, fname.4, fname.5
#[unsafe(no_mangle)]
pub extern "C" fn build_bin(fname: *const libc::c_char, fp: *mut libc::FILE) {
    assert!(fname != std::ptr::null());
    let fname_r: String = unsafe { CStr::from_ptr(fname).to_str().unwrap().to_string() };
    println!("[DBG] build_bin: fname = {}", fname_r);

    let bin_out: *const FileDB = 0x0201 as *const FileDB;
    // run fname
    process_bin(fname_r.clone(), bin_out);

    // run all the rest
    for i in 1..=5 {
        let new_name_r: String = format!("{}.{}", fname_r, i);

        if let Ok(mdata) = std::fs::metadata(&new_name_r) {
            if mdata.is_file() {
                process_bin(new_name_r, bin_out);
            }
        }
    }

    if filedb_is_empty(bin_out) == 0 {
        unsafe {
            libc::fprintf(fp, c"private-bin ".as_ptr());
            write_filedb_to_file_as_line(bin_out, c",".as_ptr(), fp);
            libc::fprintf(fp, c"\n".as_ptr());
        }
    }
}

fn process_bin(fname: String, bin_out: *const FileDB) {
    assert!(!fname.is_empty());

    let v = process_syscalls_from_trace_file(&fname, bin_trace_match);
    for a in v {
        // a-la basename
        let file_name = Path::new(&a.file_path)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap()
            .to_string();
        filedb_add(
            bin_out,
            CString::new(file_name.as_bytes()).unwrap().as_ptr(),
        );
    }
}

fn bin_trace_match(action: &Action) -> bool {
    action.syscall == "exec"
        && (action.file_path.starts_with("/bin/")
            || action.file_path.starts_with("/sbin/")
            || action.file_path.starts_with("/usr/bin/")
            || action.file_path.starts_with("/usr/sbin/")
            || action.file_path.starts_with("/usr/local/bin/")
            || action.file_path.starts_with("/usr/local/sbin/")
            || action.file_path.starts_with("/usr/games/")
            || action.file_path.starts_with("/usr/local/games/"))
        && !action.file_path.ends_with("/strace")
        && !action.file_path.ends_with("/firejail")
}

#[cfg(test)]
mod tests {
    use crate::filedb_find;

    use super::*;

    #[test]
    fn test_process_bin() {
        let v = process_syscalls_from_trace_file("testdata/firejail-trace.ZUVfMS", bin_trace_match);
        assert_eq!(
            vec!["/usr/bin/top"],
            v.iter()
                .cloned()
                .map(|a| a.file_path)
                .collect::<Vec<String>>()
        );

        // for f in v {
        //     assert!(
        //         filedb_find(file_db, CString::new(f.file_path.as_bytes()).unwrap().as_ptr())
        //             != std::ptr::null(),
        //         "{} was not found in the result of reference implementation.",
        //         f.file_path
        //     );
        // }
    }
}
