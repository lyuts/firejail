use std::{
    fs::File,
    io::{BufRead, BufReader},
};

///
/// 4:top:fopen /proc/sys/kernel/osrelease:0x57b4d4d33540
/// id_x : bin_name : syscall file_path : val
#[derive(Clone, Debug, PartialEq)]
pub struct Action {
    pub id_x: u32,
    pub bin_name: String,
    pub syscall: String,
    pub file_path: String,
    pub val: Option<i64>,
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

/// Find access to files from firejail's trace file.
pub fn process_syscalls_from_trace_file(
    trace_file_path: &str,
    trace_match: fn(&Action) -> bool,
) -> Vec<Action> {
    let trace_file = File::open(trace_file_path).expect("Whitelist file must exist.");
    let reader = BufReader::new(trace_file);
    let mut actions = vec![];
    for line in reader.lines() {
        let line = line.expect("Must be valid line.");
        let action = parse_action(line).unwrap();
        if trace_match(&action) {
            actions.push(action);
        }
    }
    actions
}

#[cfg(test)]
mod tests {
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
        let v = process_syscalls_from_trace_file("testdata/firejail-trace.ZUVfMS", |a| a.syscall == "exec");
        assert_eq!(vec!["/usr/bin/top"], v.iter().cloned().map(|a| a.file_path).collect::<Vec<String>>());
    }

}
