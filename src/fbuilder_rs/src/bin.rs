use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use crate::{FileDB, filedb_add, filedb_is_empty, write_filedb_to_file_as_line};

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

    unsafe {
        if filedb_is_empty(bin_out) == 0 {
            libc::fprintf(fp, c"private-bin ".as_ptr());
            write_filedb_to_file_as_line(bin_out, c",".as_ptr(), fp);
            libc::fprintf(fp, c"\n".as_ptr());
        }
    }
}

fn process_bin(fname: String, bin_out: *const FileDB) {
    assert!(!fname.is_empty());

    let v = process_bin_from_trace_file(&fname, bin_trace_match);
    for f in v {
        filedb_add(bin_out, CString::new(f.as_bytes()).unwrap().as_ptr());
    }
}

///
/// 4:top:fopen /proc/sys/kernel/osrelease:0x57b4d4d33540
/// id_x : bin_name : syscall file_path : val
#[derive(Debug, PartialEq)]
struct Action {
    id_x: u32,
    bin_name: String,
    syscall: String,
    file_path: String,
    val: Option<i64>,
}

fn parse_action(line: String) -> Result<Action, ()> {
    let binding = line.split(':').collect::<Vec<_>>();
    let [id_x, bin_name, syscall_and_file_path, val_str] = binding.as_slice() else {
        panic!("Invalid contents of the trace file.");
    };

    let binding = syscall_and_file_path.split(' ').collect::<Vec<_>>();
    let [syscall, file_path] = binding.as_slice() else {
        panic!("Invalid contents of the trace file.");
    };

    let val = i64::from_str_radix(val_str, 10)
        .or_else(|_s| i64::from_str_radix(&val_str[2..], 16))
        .ok();

    Ok(Action {
        id_x: id_x.parse().unwrap(),
        bin_name: bin_name.to_string(),
        syscall: syscall.to_string(),
        file_path: file_path.to_string(),
        val,
    })
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

/// Find access to binaries from firejail's trace file.
fn process_bin_from_trace_file(
    trace_file_path: &str,
    trace_match: fn(&Action) -> bool,
) -> Vec<String> {
    let trace_file = File::open(trace_file_path).expect("Whitelist file must exist.");
    let reader = BufReader::new(trace_file);
    let mut actions = vec![];
    for line in reader.lines() {
        let line = line.expect("Must be valid line.");
        let action = parse_action(line).unwrap();
        if trace_match(&action) {
            // a-la basename
            let file_name = Path::new(&action.file_path)
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap()
                .to_string();
            actions.push(file_name);
        }
    }
    actions
}

#[cfg(test)]
mod tests {
    use crate::filedb_find;

    use super::*;

    #[test]
    fn parse_trace_string_to_action() {
        let parse_result =
            parse_action("4:top:fopen /proc/sys/kernel/osrelease:0x57b4d4d33540".to_string());
        assert!(parse_result.is_ok());
        assert_eq!(
            Action {
                id_x: 4,
                bin_name: "top".to_owned(),
                syscall: "fopen".to_owned(),
                file_path: "/proc/sys/kernel/osrelease".to_owned(),
                val: Some(0x57b4d4d33540),
            },
            parse_result.unwrap()
        );
    }

    #[test]
    fn parse_trace_file() {
        let v = process_bin_from_trace_file("testdata/firejail-trace.ZUVfMS", bin_trace_match);
        assert_eq!(vec!["top"], v);
    }

    #[test]
    fn test_process_bin() {
        let file_db: *const FileDB = 0x1234 as *const FileDB;
        process_bin("testdata/firejail-trace.ZUVfMS".to_owned(), file_db);

        let v = process_bin_from_trace_file("testdata/firejail-trace.ZUVfMS", bin_trace_match);
        assert_eq!(vec!["top"], v);

        for f in v {
            assert!(
                filedb_find(file_db, CString::new(f.as_bytes()).unwrap().as_ptr())
                    != std::ptr::null(),
                "{} was not found in the result of reference implementation.",
                f
            );
        }
    }
}
