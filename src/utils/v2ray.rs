use serde_qs as qs;
use serde_yaml::Value;
use std::collections::BTreeMap;

pub fn build_vless_link(
    yaml_value: &mut Value,
    set_remarks: String,
    set_server: String,
    set_port: u16,
) -> String {
    let uuid = crate::utils::config::get_uuid_value(yaml_value);
    let network = crate::utils::config::get_network_value(yaml_value);
    let sni = crate::utils::config::get_sni_or_servename_value(yaml_value);
    let security = crate::utils::config::get_vless_tls_value(yaml_value);
    let (path, host) = crate::utils::config::get_path_and_host_value(yaml_value);
    let client_fingerprint = crate::utils::config::get_client_fingerprint_value(yaml_value);
    let alpn = crate::utils::config::get_alpn_value(yaml_value);

    let encoding_alpn = urlencoding::encode(&alpn);
    let encoding_path = urlencoding::encode(&path);
    let encoding_remarks = urlencoding::encode(set_remarks.as_str());

    let mut params = BTreeMap::new();
    params.insert("encryption", "none");
    params.insert("security", &security);
    params.insert("type", &network);
    params.insert("host", &host);
    params.insert("path", &encoding_path);
    params.insert("sni", &sni);
    params.insert("alpn", &encoding_alpn);
    params.insert("fp", &client_fingerprint);

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str = serialize_to_query_string(params);

    let vless_link =
        format!("vless://{uuid}@{set_server}:{set_port}/?{all_params_str}#{encoding_remarks}");
    vless_link
}

pub fn build_trojan_linnk(
    yaml_value: &mut Value,
    set_remarks: String,
    set_server: String,
    set_port: u16,
) -> String {
    let password = crate::utils::config::get_password_value(yaml_value);
    let network = crate::utils::config::get_network_value(yaml_value);
    let sni = crate::utils::config::get_sni_or_servename_value(yaml_value);
    let (path, host) = crate::utils::config::get_path_and_host_value(yaml_value);
    let client_fingerprint = crate::utils::config::get_client_fingerprint_value(yaml_value);
    let alpn = crate::utils::config::get_alpn_value(yaml_value);

    // url编码
    let encoding_alpn = urlencoding::encode(&alpn);
    let encoding_path = urlencoding::encode(&path);
    let encoding_remarks = urlencoding::encode(&set_remarks);

    let security = match host.ends_with("workers.dev") {
        true => "none",
        false => "tls",
    };

    // 构建节点链接后面的参数
    let mut params = BTreeMap::new();
    params.insert("security", security);
    params.insert("sni", &sni);
    params.insert("alpn", &encoding_alpn);
    params.insert("fp", &client_fingerprint);
    params.insert("type", &network);
    params.insert("host", &host);
    params.insert("path", &encoding_path);

    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
    let all_params_str = serialize_to_query_string(params);

    let trojan_link =
        format!("trojan://{password}@{set_server}:{set_port}/?{all_params_str}#{encoding_remarks}");
    trojan_link
}

#[allow(dead_code)]
fn serialize_to_query_string(params: BTreeMap<&str, &str>) -> String {
    let filtered_params: BTreeMap<_, _> =
        params.into_iter().filter(|(_, v)| !v.is_empty()).collect();
    let all_params_str = qs::to_string(&filtered_params).unwrap();
    all_params_str
}
