use std::{fs::File, io::Read};

pub fn read_file_to_string(path: &str) -> String {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return String::new(),
    };
    let mut contents = String::new();
    if let Err(_) = file.read_to_string(&mut contents) {
        return String::new();
    }
    contents
}
