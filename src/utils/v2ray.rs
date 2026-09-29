use super::config::{get_yaml_value, get_yaml_value_with_fallback};
use super::format_ip;
use base64::{engine::general_purpose::URL_SAFE, Engine};
use serde_json::json;
use serde_qs as qs;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

pub fn build_v2ray_links(
    proxy_type: &str,
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> (String, String) {
    match proxy_type {
        "vless" => {
            let vless_link =
                build_vless_link(yaml_value, remarks.clone(), server_address, server_port);
            return (remarks, vless_link);
        }
        "vmess" => {
            let vmess_link =
                build_vmess_link(yaml_value, remarks.clone(), server_address, server_port);
            return (remarks, vmess_link);
        }
        "trojan" => {
            let trojan_link =
                build_trojan_linnk(yaml_value, remarks.clone(), server_address, server_port);
            return (remarks, trojan_link);
        }
        "ss" => {
            let ss_link = build_ss_link(yaml_value, remarks.clone(), server_address, server_port);
            return (remarks, ss_link);
        }
        _ => {}
    }
    return ("".to_string(), "".to_string());
}

fn build_vless_link(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> String {
    let uuid = get_yaml_value(&yaml_value, &"uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("00000000-0000-0000-0000-000000000000");

    let network = get_yaml_value(&yaml_value, &"network")
        .and_then(|v| v.as_str())
        .unwrap_or("ws");

    let sni = get_yaml_value_with_fallback(&yaml_value, &["sni", "servername"]).unwrap_or_default();
    let host = get_yaml_value(&yaml_value, &"ws-opts.headers.Host")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let path = get_yaml_value(&yaml_value, &"ws-opts.path")
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    let client_fingerprint = get_yaml_value(&yaml_value, &"client-fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("chrome");
    // let skip_cert_verify_bool = get_yaml_value(&yaml_value, &"skip-cert-verify")
    //     .and_then(|v| v.as_bool())
    //     .unwrap_or(true);

    let tls_boolean = get_yaml_value(&yaml_value, &"tls")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let security = match tls_boolean {
        true => "tls",
        false => "none",
    };
    // let skip_cert_verify = match skip_cert_verify_bool {
    //     true => "1",
    //     false => "",
    // };

    let mut params = BTreeMap::new();
    params.insert("encryption", "none");
    params.insert("security", &security);
    params.insert("type", &network);
    params.insert("host", &host);
    params.insert("sni", &sni);
    params.insert("fp", &client_fingerprint);
    // params.insert("allowInsecure", skip_cert_verify);
    params.insert("path", &path);

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str = serialize_to_query_string(params);
    let encoding_remarks = urlencoding::encode(remarks.as_str());

    format!(
        "vless://{uuid}@{}:{server_port}/?{all_params_str}#{encoding_remarks}",
        format_ip(&server_address)
    )
}

fn build_vmess_link(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> String {
    let uuid = get_yaml_value(&yaml_value, &"uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("00000000-0000-0000-0000-000000000000");

    let cipher = get_yaml_value(&yaml_value, &"cipher")
        .and_then(|v| v.as_str())
        .unwrap_or("zero");
    let alter_id = get_yaml_value(&yaml_value, &"alterId")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let tls_boolean = get_yaml_value(&yaml_value, &"tls")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let servername = get_yaml_value_with_fallback(&yaml_value, &["servername"]).unwrap_or_default(); // priority over wss host
    let host = get_yaml_value(&yaml_value, &"ws-opts.headers.Host")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let network = get_yaml_value(&yaml_value, &"network")
        .and_then(|v| v.as_str())
        .unwrap_or("ws");

    let path = get_yaml_value(&yaml_value, &"ws-opts.path")
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    let client_fingerprint = get_yaml_value(&yaml_value, &"client-fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("chrome");

    let tls = match tls_boolean {
        true => "tls",
        false => "",
    };

    let vmess = json!({
        "ps": remarks,
        "v": "2",
        "add": server_address,
        "port": server_port,
        "id": uuid,
        "aid": alter_id,
        "scy": cipher,
        "net": network,
        "type": "none",
        "host": servername,
        "path": path,
        "tls": tls,
        "sni": host,
        "alpn": client_fingerprint});

    format!("vmess://{}", URL_SAFE.encode(vmess.to_string()))
}

fn build_trojan_linnk(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> String {
    let password = get_yaml_value(&yaml_value, &"password")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let network = get_yaml_value(&yaml_value, &"network")
        .and_then(|v| v.as_str())
        .unwrap_or("ws");

    let sni = get_yaml_value_with_fallback(&yaml_value, &["sni", "servername"]).unwrap_or_default();
    let host = get_yaml_value(&yaml_value, &"ws-opts.headers.Host")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let path = get_yaml_value(&yaml_value, &"ws-opts.path")
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    let client_fingerprint = get_yaml_value(&yaml_value, &"client-fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("chrome");

    let security = match host.ends_with("workers.dev") {
        true => "none",
        false => "tls",
    };

    // 构建节点链接后面的参数
    let mut params = BTreeMap::new();
    params.insert("security", security);
    params.insert("sni", &sni);
    params.insert("fp", &client_fingerprint);
    params.insert("type", &network);
    params.insert("host", &host);
    // params.insert("allowInsecure", skip_cert_verify);
    params.insert("path", &path);

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str = serialize_to_query_string(params);
    let encoding_remarks = urlencoding::encode(&remarks);

    format!(
        "trojan://{password}@{}:{server_port}/?{all_params_str}#{encoding_remarks}",
        format_ip(&server_address)
    )
}

fn build_ss_link(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> String {
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

    let plugin_value =
        format!("{plugin};{tls}mux={mux};mode={mode};path={path};host={host}").replace("=", "%3D");
    let base64_encoded = URL_SAFE.encode(format!("{}:{}", cipher, password));
    let encoding_remarks = urlencoding::encode(&remarks);

    format!(
        "ss://{base64_encoded}@{}:{server_port}?plugin={plugin_value}#{encoding_remarks}",
        format_ip(&server_address)
    )
}

fn serialize_to_query_string(params: BTreeMap<&str, &str>) -> String {
    let filtered_params: BTreeMap<_, _> =
        params.into_iter().filter(|(_, v)| !v.is_empty()).collect();
    let all_params_str = qs::to_string(&filtered_params).unwrap_or_default();
    all_params_str
}
