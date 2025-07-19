use std::ffi::{CStr, CString};

use crate::{
    FileDB, filedb_add, filedb_find, filedb_is_empty, filedb_load_whitelist,
    trace::{Action, process_syscalls_from_trace_file},
    write_filedb_to_file_lines,
};

fn home_trace_match(action: &Action) -> bool {
    vec!["access", "fopen", "fopen64", "open64", "open", "opendir"]
        .contains(&action.syscall.as_str())
        && action.file_path.starts_with("/home")
        && (!action.file_path.ends_with(".Xauthority")
            && !action.file_path.ends_with(".Xdefaults-debian")
            && !action.file_path.ends_with(".bash_hist")
            && !action.file_path.ends_with(".bashrc"))
        && !action.file_path.contains(".config/pulse/")
        && !action.file_path.contains(".pulse/")
        && !action.file_path.contains(".local/share/flatpak")
        && !action.file_path.starts_with("/home/.config")
        && !action.file_path.starts_with("/home/.local")
        && !action.file_path.starts_with("/home/.local/share")
        && (!action.file_path.starts_with("/home/.cache") || action.file_path.contains(".cache/"))
}

fn process_home(
    fname: String,
    home_dir_path: String,
    db_out: *const FileDB,
    db_skip: *const FileDB,
) {
    assert!(!fname.is_empty());

    let v = process_syscalls_from_trace_file(&fname, home_trace_match);
    for a in v {
        let path_relative_to_home = &a.file_path[home_dir_path.len() + 1..];
        if filedb_find(
            db_skip,
            CString::new(path_relative_to_home).unwrap().as_ptr(),
        ) == std::ptr::null()
            && a.file_path.starts_with(&home_dir_path)
        {
            println!("process_home> adding {}", a.file_path);
            filedb_add(
                db_out,
                CString::new(path_relative_to_home).unwrap().as_ptr(),
            );
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn build_home(fname: *const libc::c_char, fp: *mut libc::FILE) {
    assert!(fname != std::ptr::null());

    let mut db_skip: *const FileDB = 0x0301 as *const FileDB;
    let db_out: *const FileDB = 0x0302 as *const FileDB;
    let fname_r: String = unsafe { CStr::from_ptr(fname).to_str().unwrap().to_string() };

    // load whitelist common
    db_skip = filedb_load_whitelist(
        db_skip,
        c"whitelist-common.inc".as_ptr(),
        c"whitelist ${HOME}/".as_ptr(),
    );

    let binding = std::env::home_dir().unwrap();
    let home_dir: &str = binding.to_str().unwrap();

    // run fname
    process_home(fname_r.clone(), home_dir.to_string(), db_out, db_skip);

    // run all the rest
    for i in 1..=5 {
        let new_name_r: String = format!("{}.{}", fname_r, i);

        if let Ok(mdata) = std::fs::metadata(&new_name_r) {
            if mdata.is_file() {
                process_home(new_name_r, home_dir.to_string(), db_out, db_skip);
            }
        }
    }

    // print the out list if any
    if filedb_is_empty(db_out) == 0 {
        write_filedb_to_file_lines(db_out, c"whitelist ${HOME}/".as_ptr(), fp);
        unsafe {
            libc::fprintf(fp, c"include whitelist-common.inc\n".as_ptr());
        }
    } else {
        unsafe {
            libc::fprintf(fp, c"private\n".as_ptr());
        }
    }
}
