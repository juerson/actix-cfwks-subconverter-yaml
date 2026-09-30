use super::config::{get_yaml_value, get_yaml_value_with_fallback};
use serde_json::json;
use serde_yaml::Value as YamlValue;

pub fn build_singbox_config_json(
    proxy_type: &str,
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> (String, String) {
    match proxy_type {
        "vless" => {
            let (remarks_name, vless_singbox) =
                build_vless_singbox_config(yaml_value, remarks, server_address, server_port);
            return (remarks_name, vless_singbox);
        }
        "vmess" => {
            let (remarks_name, vmess_singbox) =
                build_vmess_singbox_config(yaml_value, remarks, server_address, server_port);
            return (remarks_name, vmess_singbox);
        }
        "trojan" => {
            let (remarks_name, trojan_singbox) =
                build_trojan_singbox_config(yaml_value, remarks, server_address, server_port);
            return (remarks_name, trojan_singbox);
        }
        "ss" => {
            let (remarks_name, ss_singbox) =
                build_ss_singbox_config(yaml_value, remarks, server_address, server_port);
            return (remarks_name, ss_singbox);
        }
        _ => {}
    }

    return (String::new(), String::new());
}

fn build_vless_singbox_config(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> (String, String) {
    let uuid = get_yaml_value(&yaml_value, &"uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("00000000-0000-0000-0000-000000000000");

    let tls = get_yaml_value(&yaml_value, &"tls")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let servername =
        get_yaml_value_with_fallback(&yaml_value, &["servername", "sni"]).unwrap_or_default();
    let host =
        get_yaml_value_with_fallback(&yaml_value, &["ws-opts.headers.Host", "xhttp-opts.host"])
            .unwrap_or("");

    let path = get_yaml_value_with_fallback(&yaml_value, &["ws-opts.path", "xhttp-opts.path"])
        .unwrap_or("/");
    let client_fingerprint = get_yaml_value(&yaml_value, &"client-fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("chrome");
    let skip_cert_verify = get_yaml_value(&yaml_value, &"skip-cert-verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let network = get_yaml_value(&yaml_value, &"network")
        .and_then(|v| v.as_str())
        .unwrap_or("ws");

    let xhttp_mode = get_yaml_value(&yaml_value, &"xhttp-opts.mode")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let transport = match network {
        // https://github.com/Leadaxe/sing-box-lx/blob/lx/docs-lx/lx-protocols-transports.md
        // https://github.com/Leadaxe/sing-box-lx/blob/lx/docs-lx/lx-protocols-transports.md#110-examples
        "xhttp" => json!({
            "type": network,
            "path": path,
            "mode": xhttp_mode,
            "host": host,
            "x_padding_bytes": "100-1000"
        }),
        _ => json!({
            "type": network,
            "path": path,
            "headers": {"Host": host},
            "early_data_header_name": "Sec-WebSocket-Protocol"
        }),
    };

    let vless_jsonvalue = json!({
        "type": "vless",
        "tag": remarks,
        "server": server_address,
        "server_port": server_port,
        "uuid": uuid,
        "network": "tcp", // 不要填错到这里
        "tls": {
            "enabled": tls,
            "server_name": servername,
            "insecure": skip_cert_verify,
            "utls": {
                "enabled": true,
                "fingerprint": client_fingerprint
            }
        },
        "transport": transport
    });

    let json_string = serde_json::to_string_pretty(&vless_jsonvalue).unwrap_or_default();

    return (remarks, json_string);
}

fn build_vmess_singbox_config(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> (String, String) {
    let uuid = get_yaml_value(&yaml_value, &"uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("00000000-0000-0000-0000-000000000000");

    let alter_id = get_yaml_value(&yaml_value, &"alterId")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let cipher = get_yaml_value(&yaml_value, &"cipher")
        .and_then(|v| v.as_str())
        .unwrap_or("zero");

    let tls = get_yaml_value(&yaml_value, &"tls")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let servername = get_yaml_value_with_fallback(&yaml_value, &["servername"]).unwrap_or_default(); // priority over wss host
    let host =
        get_yaml_value_with_fallback(&yaml_value, &["ws-opts.headers.Host", "xhttp-opts.host"])
            .unwrap_or("");

    let path = get_yaml_value_with_fallback(&yaml_value, &["ws-opts.path", "xhttp-opts.path"])
        .unwrap_or("/");
    let client_fingerprint = get_yaml_value(&yaml_value, &"client-fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("chrome");
    let skip_cert_verify = get_yaml_value(&yaml_value, &"skip-cert-verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let network = get_yaml_value(&yaml_value, &"network")
        .and_then(|v| v.as_str())
        .unwrap_or("ws");

    let xhttp_mode = get_yaml_value(&yaml_value, &"xhttp-opts.mode")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let transport = match network {
        "xhttp" => json!({
            "type": network,
            "path": path,
            "mode": xhttp_mode,
            "host": host,
            "x_padding_bytes": "100-1000"
        }),
        _ => json!({
            "type": network,
            "path": path,
            "headers": {"Host": host},
            "early_data_header_name": "Sec-WebSocket-Protocol"
        }),
    };

    let vmess_jsonvalue = json!({
        "type": "vmess",
        "tag": remarks,
        "server": server_address,
        "server_port": server_port,
        "uuid": uuid,
        "security": cipher,
        "alter_id": alter_id,
        "tls": {
            "enabled": tls,
            "server_name": servername,
            "insecure": skip_cert_verify,
            "utls": {
                "enabled": true,
                "fingerprint": client_fingerprint
            }
        },
        "transport": transport
    });

    let json_string = serde_json::to_string_pretty(&vmess_jsonvalue).unwrap_or_default();

    return (remarks, json_string);
}

fn build_trojan_singbox_config(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> (String, String) {
    let password = get_yaml_value(&yaml_value, &"password")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let servername =
        get_yaml_value_with_fallback(&yaml_value, &["sni", "servername"]).unwrap_or_default();
    let host =
        get_yaml_value_with_fallback(&yaml_value, &["ws-opts.headers.Host", "xhttp-opts.host"])
            .unwrap_or("");

    let path = get_yaml_value_with_fallback(&yaml_value, &["ws-opts.path", "xhttp-opts.path"])
        .unwrap_or("/");
    let client_fingerprint = get_yaml_value(&yaml_value, &"client-fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("chrome");
    let skip_cert_verify = get_yaml_value(&yaml_value, &"skip-cert-verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let network = get_yaml_value(&yaml_value, &"network")
        .and_then(|v| v.as_str())
        .unwrap_or("ws");

    let xhttp_mode = get_yaml_value(&yaml_value, &"xhttp-opts.mode")
        .and_then(|v| v.as_str())
        .unwrap_or("stream-one");
    let transport = match network {
        "xhttp" => json!({
            "type": network,
            "path": path,
            "mode": xhttp_mode,
            "host": host,
            "x_padding_bytes": "100-1000"
        }),
        _ => json!({
            "type": network,
            "path": path,
            "headers": {"Host": host},
            "early_data_header_name": "Sec-WebSocket-Protocol"
        }),
    };

    let trojan_jsonvalue = json!({
        "type": "trojan",
        "tag": remarks,
        "server": server_address,
        "server_port": server_port,
        "password": password,
        "network": "tcp", // 不要填错到这里
        "tls": {
            "enabled": !servername.ends_with("workers.dev"),
            "server_name": servername,
            "insecure": skip_cert_verify,
            "utls": {
                "enabled": true,
                "fingerprint": client_fingerprint
            }
        },
        "transport": transport
    });

    let json_string = serde_json::to_string_pretty(&trojan_jsonvalue).unwrap_or_default();

    return (remarks, json_string);
}

fn build_ss_singbox_config(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> (String, String) {
    let cipher = get_yaml_value(&yaml_value, &"cipher")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    let password = get_yaml_value(&yaml_value, &"password")
        .and_then(|v| v.as_str())
        .unwrap_or("none");

    let plugin = get_yaml_value(&yaml_value, &"plugin")
        .and_then(|v| v.as_str())
        .unwrap_or("v2ray-plugin");

    let mode = get_yaml_value(&yaml_value, &"plugin-opts.mode")
        .and_then(|v| v.as_str())
        .unwrap_or("websocket");
    let host = get_yaml_value(&yaml_value, &"plugin-opts.host")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let path = get_yaml_value(&yaml_value, &"plugin-opts.path")
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    let tls_boolean = get_yaml_value(&yaml_value, &"plugin-opts.tls")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mux_boolean = get_yaml_value(&yaml_value, &"plugin-opts.mux")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let tls = match tls_boolean {
        true => "tls;",
        false => "",
    };
    let mux = match mux_boolean {
        true => "1",
        false => "0",
    };

    let ss_jsonvalue = json!({
        "type": "shadowsocks",
        "tag": remarks,
        "server": server_address,
        "server_port": server_port,
        "method": cipher,
        "password": password,
        "plugin": plugin,
        "plugin_opts": format!("{tls}mux={mux};mode={mode};path={path};host={host}")
    });

    let json_string = serde_json::to_string_pretty(&ss_jsonvalue).unwrap_or_default();

    return (remarks, json_string);
}
