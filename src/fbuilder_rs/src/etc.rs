use std::{
    ffi::CStr,
    path::Path,
};

use crate::{
    trace::{Action, process_syscalls_from_trace_file},
    write_vec_to_file_as_line,
};

#[unsafe(no_mangle)]
pub extern "C" fn build_etc(fname: *const libc::c_char, fp: *mut libc::FILE) {
    assert!(fname != std::ptr::null());

    let fname_r: String = unsafe { CStr::from_ptr(fname).to_str().unwrap().to_string() };

    let v = process_files_r(fname_r, "/etc".to_string());

    unsafe {
        libc::fprintf(fp, c"private-etc ".as_ptr());
    }
    if v.is_empty() {
        unsafe {
            libc::fprintf(fp, c"none\n".as_ptr());
        }
    } else {
        let x: Vec<String> = v
            .iter()
            .map(|a| {
                Path::new(&a.file_path)
                    .components()
                    .nth(2)
                    .map(|component| component.as_os_str().to_string_lossy().into_owned())
                    .unwrap()
            })
            .collect();
        write_vec_to_file_as_line(x, c",".as_ptr(), fp);
    }
}

// process fname, fname.1, fname.2, fname.3, fname.4, fname.5
fn process_files_r(fname: String, dir: String) -> Vec<Action> {
    // run fname
    let mut v = process_syscalls_from_trace_file(&fname, etc_trace_match);

    // run all the rest
    for i in 1..=5 {
        let new_name_r: String = format!("{}.{}", fname, i);
        if let Ok(mdata) = std::fs::metadata(&new_name_r) {
            if mdata.is_file() {
                v.extend(process_syscalls_from_trace_file(&new_name_r, etc_trace_match));
            }
        }
    }
    v
}

fn etc_trace_match(action: &Action) -> bool {
    vec![
        "access", "fopen", "fopen64", "open64", "open", "opendir", "connect",
    ]
    .contains(&action.syscall.as_str())
        && (action.file_path.starts_with("/etc") && !action.file_path.starts_with("/etc/firejail"))
}

#[cfg(test)]
mod tests {
    use super::*;
}
