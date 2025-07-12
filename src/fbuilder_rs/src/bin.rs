use std::ffi::CStr;

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
            }
            filedb_add(bin_out, ptr);
            println!(
                " now {:x?} after adding {}\n",
                bin_out,
                CStr::from_ptr(ptr).to_str().unwrap()
            );
        }

        libc::fclose(fp);
    }
}

fn process_bin_from_trace_file(fname: *const libc::c_char) -> Vec<String> {
    vec![]
}

#[cfg(test)]
mod tests {}
