use serde_yaml::{self, Value};
use std::{
    fs::File,
    io::{BufReader, Read},
};

#[allow(dead_code)]
pub fn yaml_config_to_json(file_path: &str) -> serde_yaml::Value {
    let file = File::open(file_path).expect("Failed to open file");
    let mut reader = BufReader::new(file);

    let mut yaml_content = String::new();
    reader
        .read_to_string(&mut yaml_content)
        .expect("Failed to read YAML");

    let json_data =
        serde_yaml::from_str::<serde_yaml::Value>(&yaml_content).expect("Failed to parse YAML");
    json_data
}

pub fn get_path_and_host_value(yaml_value: &mut Value) -> (String, String) {
    let mut path = "".to_string();
    let mut host = "".to_string();
    if let Some(opts_mapping) = yaml_value.get("ws-opts").and_then(Value::as_mapping) {
        path = opts_mapping
            .get("path")
            .and_then(Value::as_str)
            .map_or("".to_string(), |value| value.to_string());
        let host_value =
            if let Some(header_mapping) = opts_mapping.get("headers").and_then(Value::as_mapping) {
                match header_mapping.get("Host").and_then(Value::as_str) {
                    Some(value) => value.to_string(),
                    None => match header_mapping.get("host").and_then(Value::as_str) {
                        Some(value) => value.to_string(),
                        None => "".to_string(), // 默认值，如果没有找到任何字段
                    },
                }
            } else {
                "".to_string()
            };
        host = host_value.to_string();
    }
    (path, host)
}

pub fn get_vless_tls_value(yaml_value: &mut Value) -> String {
    let security = yaml_value
        .get("tls")
        .and_then(Value::as_bool)
        .map(|v| match v {
            true => "tls".to_string(),
            false => "none".to_string(),
        })
        .unwrap_or("none".to_string());

    security
}

pub fn get_password_value(yaml_value: &mut Value) -> String {
    let password = yaml_value
        .get("password")
        .and_then(Value::as_str)
        .map_or("".to_string(), |password| password.to_string());

    password
}

pub fn get_uuid_value(yaml_value: &mut Value) -> String {
    let uuid = yaml_value
        .get(&Value::String("uuid".to_string()))
        .and_then(Value::as_str)
        .map_or("".to_string(), |uuid: &str| uuid.to_string());
    uuid
}

pub fn get_network_value(yaml_value: &mut Value) -> String {
    let network = yaml_value
        .get(&Value::String("network".to_string()))
        .and_then(Value::as_str)
        .map_or("".to_string(), |network| network.to_string());
    network
}

// sni字段或servername字段都视为同一个字段
pub fn get_sni_or_servename_value(yaml_value: &mut Value) -> String {
    let sni = match yaml_value.get("sni").and_then(Value::as_str) {
        Some(value) => value.to_string(),
        None => {
            match yaml_value.get("servername").and_then(Value::as_str) {
                Some(value) => value.to_string(),
                None => "".to_string(), // 默认值，如果没有找到任何字段
            }
        }
    };
    sni
}

pub fn get_client_fingerprint_value(yaml_value: &mut Value) -> String {
    let client_fingerprint = yaml_value
        .get("client-fingerprint")
        .and_then(Value::as_str)
        .filter(|fingerprint| !fingerprint.is_empty())
        .map_or_else(|| "".to_string(), |fingerprint| fingerprint.to_string());

    client_fingerprint
}

pub fn get_alpn_value(yaml_value: &mut Value) -> String {
    let alpn =
        yaml_value
            .get("alpn")
            .and_then(Value::as_sequence)
            .map_or("".to_string(), |alpn_value| {
                alpn_value
                    .iter()
                    .map(|v| v.as_str().unwrap_or("").to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            });
    alpn
}
