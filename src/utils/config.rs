use serde_yaml;
use std::{
    fs::File,
    io::{BufReader, Read},
};

#[allow(dead_code)]
pub fn yaml_config_to_json(file_path: &str) -> serde_yaml::Value {
    let file = File::open(file_path).expect("Failed to open file");
    let mut reader = BufReader::new(file);

    // 读取 YAML 文件内容
    let mut yaml_content = String::new();
    reader
        .read_to_string(&mut yaml_content)
        .expect("Failed to read YAML");

    // 将 YAML 转换为 JSON 格式
    let json_data =
        serde_yaml::from_str::<serde_yaml::Value>(&yaml_content).expect("Failed to parse YAML");
    json_data
}
