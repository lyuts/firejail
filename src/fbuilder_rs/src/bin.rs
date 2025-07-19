use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use crate::{FileDB, filedb_add};

const MAX_BUF: i32 = 4096;

#[unsafe(no_mangle)]
pub extern "C" fn process_bin(fname: *const libc::c_char, bin_out: *const FileDB) {
    assert!(fname != std::ptr::null());

    unsafe {
        println!(
            "process_bin> fname = {:?}",
            CStr::from_ptr(fname).to_str().unwrap()
        );

        // process trace file
        let fp: *mut libc::FILE = libc::fopen(fname, c"r".as_ptr());
        if fp == std::ptr::null_mut() {
            eprintln!(
                "Error fbuilder: cannot open {}",
                CStr::from_ptr(fname).to_str().unwrap()
            );
            libc::exit(1);
        }

        let mut buf: [libc::c_char; MAX_BUF as usize] = [0; MAX_BUF as usize];
        while libc::fgets(buf.as_mut_ptr(), MAX_BUF, fp) != std::ptr::null_mut() {
            // remove \n
            let mut ptr: *mut libc::c_char = libc::strchr(buf.as_mut_ptr(), '\n' as i32);
            if ptr != std::ptr::null_mut() {
                *ptr = 0;
            }

            // parse line: 4:galculator:access /etc/fonts/conf.d:0
            // number followed by :
            ptr = buf.as_mut_ptr();
            if libc::isdigit((*ptr) as i32) == 0 {
                *ptr = 0;
                continue;
            }
            while libc::isdigit((*ptr) as i32) != 0 {
                ptr = ptr.wrapping_add(1);
            }
            if (*ptr) != ':' as i8 {
                continue;
            }
            ptr = ptr.wrapping_add(1);

            // next :
            ptr = libc::strchr(ptr, ':' as i32);
            if ptr == std::ptr::null_mut() {
                continue;
            }
            ptr = ptr.wrapping_add(1);
            if libc::strncmp(ptr, c"exec ".as_ptr(), 5) == 0 {
                ptr = ptr.wrapping_add(5);
            } else {
                continue;
            }

            if libc::strncmp(ptr, c"/bin/".as_ptr(), 5) == 0 {
                ptr = ptr.wrapping_add(5);
            } else if libc::strncmp(ptr, c"/sbin/".as_ptr(), 6) == 0 {
                ptr = ptr.wrapping_add(6);
            } else if libc::strncmp(ptr, c"/usr/bin/".as_ptr(), 9) == 0 {
                ptr = ptr.wrapping_add(9);
            } else if libc::strncmp(ptr, c"/usr/sbin/".as_ptr(), 10) == 0 {
                ptr = ptr.wrapping_add(10);
            } else if libc::strncmp(ptr, c"/usr/local/bin/".as_ptr(), 15) == 0 {
                ptr = ptr.wrapping_add(15);
            } else if libc::strncmp(ptr, c"/usr/local/sbin/".as_ptr(), 16) == 0 {
                ptr = ptr.wrapping_add(16);
            } else if libc::strncmp(ptr, c"/usr/games/".as_ptr(), 11) == 0 {
                ptr = ptr.wrapping_add(11);
            } else if libc::strncmp(ptr, c"/usr/local/games/".as_ptr(), 17) == 0 {
                ptr = ptr.wrapping_add(17);
            } else {
                continue;
            }

            // end of filename
            let ptr2: *mut libc::c_char = libc::strchr(ptr, ':' as i32);
            if ptr2 == std::ptr::null_mut() {
                continue;
            }
            *ptr2 = '\0' as i8;

            // skip strace and firejail (in case we hit a symlink in /usr/local/bin)
            if libc::strcmp(ptr, c"strace".as_ptr()) != 0
                && libc::strcmp(ptr, c"firejail".as_ptr()) != 0
            {
                print!("[DBG] bin_out was {:x?} ", bin_out);
                filedb_add(bin_out, ptr);
                println!(
                    " now {:x?} after adding {}\n",
                    bin_out,
                    CStr::from_ptr(ptr).to_str().unwrap()
                );
            }
        }

        libc::fclose(fp);
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
        .or_else(|s| i64::from_str_radix(&val_str[2..], 16))
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
        process_bin(c"testdata/firejail-trace.ZUVfMS".as_ptr(), file_db);

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
