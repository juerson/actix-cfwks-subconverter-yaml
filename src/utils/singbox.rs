use serde_json::json;
use serde_yaml::Value;
use std::collections::HashMap;

pub fn build_vless_singbox_config(
    yaml_value: &mut Value,
    remarks: String,
    address: &String,
    port: u16,
) -> (String, String) {
    let uuid = crate::utils::config::get_uuid_value(yaml_value);
    let servername = crate::utils::config::get_sni_or_servename_value(yaml_value);
    let (path, host) = crate::utils::config::get_path_and_host_value(yaml_value);
    let client_fingerprint = crate::utils::config::get_client_fingerprint_value(yaml_value);
    let vless_singbox_config = r#"{
        "type": "vless",
        "tag": "vless_tag",
        "server": "",
        "server_port": 443,
        "uuid": "",
        "network": "tcp",
        "tls": {
            "enabled": true,
            "server_name": "",
            "insecure": true,
            "utls": {
                "enabled": true,
                "fingerprint": "chrome"
            }
        },
        "transport": {
            "type": "ws",
            "path": "/",
            "headers": {"Host": ""},
            "early_data_header_name": "Sec-WebSocket-Protocol"
        }
    }"#;

    let mut jsonvalue =
        serde_json::from_str(vless_singbox_config).unwrap_or(serde_json::Value::Null);

    let outer_updates = HashMap::from([
        ("tag", json!(remarks)),
        ("server", json!(address)),
        ("server_port", json!(port)),
        ("uuid", json!(uuid)),
    ]);

    let result: serde_json::Value = update_singbox_json_value(
        &mut jsonvalue,
        outer_updates,
        servername,
        client_fingerprint,
        path,
        host,
    );

    let formatted_json_str = serde_json::to_string_pretty(&result).unwrap();

    return (remarks, formatted_json_str);
}

pub fn build_trojan_singbox_config(
    yaml_value: &mut Value,
    remarks: String,
    address: &String,
    port: u16,
) -> (String, String) {
    let password = crate::utils::config::get_password_value(yaml_value);
    let servername = crate::utils::config::get_sni_or_servename_value(yaml_value);
    let (path, host) = crate::utils::config::get_path_and_host_value(yaml_value);
    let client_fingerprint = crate::utils::config::get_client_fingerprint_value(yaml_value);
    let singbox_trojan_config = r#"{
        "type": "trojan",
        "tag": "tag_name",
        "server": "",
        "server_port": 443,
        "password": "",
        "network": "tcp",
        "tls": {
            "enabled": true,
            "server_name": "",
            "insecure": true,
            "utls": {
                "enabled": true,
                "fingerprint": "chrome"
            }
        },
        "transport": {
            "type": "ws",
            "path": "/",
            "headers": {"Host": ""},
            "early_data_header_name": "Sec-WebSocket-Protocol"
        }
    }"#;

    let mut jsonvalue =
        serde_json::from_str(singbox_trojan_config).unwrap_or(serde_json::Value::Null);

    let outer_updates = HashMap::from([
        ("tag", json!(remarks)),
        ("server", json!(address)),
        ("server_port", json!(port)),
        ("password", json!(password)),
    ]);

    let result: serde_json::Value = update_singbox_json_value(
        &mut jsonvalue,
        outer_updates,
        servername,
        client_fingerprint,
        path,
        host,
    );

    let formatted_json_str = serde_json::to_string_pretty(&result).unwrap();

    return (remarks, formatted_json_str);
}

fn update_singbox_json_value(
    jsonvalue: &mut serde_json::Value,
    outer_updates: HashMap<&str, serde_json::Value>,
    servername: String,
    client_fingerprint: String,
    path: String,
    host: String,
) -> serde_json::Value {
    // 修改jsonvalue的外层字段（多个字段）
    for (key, new_value) in outer_updates {
        if let Some(outer_value) = jsonvalue.get_mut(key) {
            *outer_value = new_value;
        }
    }
    // 修改jsonvalue的tls字段
    if let Some(tls) = jsonvalue.get_mut("tls") {
        if let Some(server_name) = tls.get_mut("server_name") {
            *server_name = json!(servername);
        }
        // 手动关闭tls
        if host.ends_with("workers.dev") {
            if let Some(tls_enabled) = tls.get_mut("enabled") {
                *tls_enabled = json!(false);
            }
        }
        if let Some(utls) = tls.get_mut("utls") {
            if let Some(fingerprint) = utls.get_mut("fingerprint") {
                *fingerprint = json!(client_fingerprint);
            }
        }
    }
    // 修改jsonvalue的transport字段
    if let Some(transport) = jsonvalue.get_mut("transport") {
        if let Some(path_value) = transport.get_mut("path") {
            *path_value = json!(path);
        }
        if let Some(headers) = transport.get_mut("headers") {
            if let Some(host_value) = headers.get_mut("Host") {
                *host_value = json!(host);
            }
        }
    }
    jsonvalue.clone()
}
