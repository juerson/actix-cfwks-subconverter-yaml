use rand::Rng;
use serde_qs as qs;
use serde_yaml::Value;
use std::collections::BTreeMap;
use urlencoding::encode;

pub fn subconvert(
    mut json_data: Value,
    target: String,
    address: String,
    mut port: u16,
    select_proxy_type: String,
    account_number: u8,
    tls_mode: String,
) -> (String, String) {
    if let Some(sequence) = json_data.as_sequence_mut() {
        let length = sequence.len();
        // 循环10次随机选择一个节点，当找到对应的代理类型/没有选择代理类型，就跳出循环，否则等执行完10次（后面还添加符合端口的才跳出循环）
        let mut index;
        let tls_porst: Vec<u16> = vec![443, 2053, 2083, 2087, 2096, 8443];
        let not_tls_ports: Vec<u16> = vec![80, 8080, 8880, 2052, 2082, 2086, 2095];
        for _ in 0..10 {
            if account_number > 0 && account_number <= length as u8 {
                index = account_number as usize - 1; // 选择指定的账号（数组的下标）
            } else {
                let mut rng = rand::thread_rng();
                index = rng.gen_range(0..length.clone()); // 随机选择账号（数组的下标）
            }
            // 获取选择的节点信息（配置文件数组的下标）
            if let Some(yaml_value) = sequence.get_mut(index) {
                let proxy_type = yaml_value
                    .get("type")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();

                // 选择的节点，代理类型要与用户选择的代理类型匹配
                if proxy_type.to_lowercase() == select_proxy_type.to_lowercase()
                    || select_proxy_type.to_lowercase() == "all"
                {
                    if port == 0 {
                        let mut config_port = yaml_value
                            .get("port")
                            .and_then(Value::as_u64)
                            .unwrap_or(443) as u16;
                        if proxy_type == "trojan" {
                            let (_path, host) = get_ws_path_and_host(yaml_value);
                            if host.ends_with("workers.dev") && tls_porst.contains(&config_port) {
                                config_port = 8080;
                            }
                            if !host.ends_with("workers.dev")
                                && not_tls_ports.contains(&config_port)
                            {
                                config_port = 443
                            }
                        } else if proxy_type == "vless" {
                            let tls = yaml_value
                                .get("tls")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            if tls && not_tls_ports.clone().contains(&config_port) {
                                config_port = 443
                            }
                            if !tls && tls_porst.contains(&config_port) {
                                config_port = 8080;
                            }
                        }
                        port = config_port;
                    }
                    // 端口跟url传入的tlsmode=true/false比较
                    // ————————————————————————————————————————————————————————————————————————————————————————————————————————
                    // 这里的端口放反，用于判断端口不在向量中就执行后面的代码（一些不在这两个向量的端口保留下来，无视这里的代码，执行后面的代码）
                    let ports = if tls_mode.to_lowercase() == "false" || tls_mode == "0" {
                        tls_porst.clone()
                    } else {
                        not_tls_ports.clone()
                    };
                    if ports.contains(&port) && tls_mode != "" {
                        continue; // 端口不匹配，跳过执行后面的代码，继续循环，期待随机从配置文件中选择的节点的端口符合要求
                    }
                    // ————————————————————————————————————————————————————————————————————————————————————————————————————————
                    // 端口跟配置文件中的tls匹配，vless就比较tls=true/false对应的端口是否符合要求，trojan的就判断sni的后缀是否workers.dev来判断是否支持tls，执行下面的代码
                    if proxy_type == "trojan" {
                        let (_path, host) = get_ws_path_and_host(yaml_value);
                        if (host.ends_with("workers.dev") && tls_porst.contains(&port))
                            || (!host.ends_with("workers.dev") && not_tls_ports.contains(&port))
                        {
                            continue;
                        }
                    } else if proxy_type == "vless" {
                        let security = get_vless_tls_value(yaml_value);
                        if (tls_porst.contains(&port) && security == "")
                            || (not_tls_ports.contains(&port) && security == "tls")
                        {
                            continue;
                        }
                    }
                    let padded_index =
                        format!("{:0width$}", index + 1, width = length.to_string().len());
                    // 节点名称
                    let remarks: String = format!("cfwks[{}]-{}:{}", padded_index, address, port);
                    // 根据target的值构建节点信息
                    if target.to_lowercase() == "clash" {
                        let mut yaml_value_clone = yaml_value.clone();
                        let clash_node =
                            build_clash_json(&mut yaml_value_clone, remarks.clone(), address, port);
                        let json_str = serde_json::to_string(&clash_node).unwrap();
                        let clash_with_prefix = format!("  - {json_str}");
                        return (remarks, clash_with_prefix); // 返回的前面是节点名称，后面是节点配置
                    } else if target.to_lowercase() == "v2ray"
                        && proxy_type.to_lowercase() == "vless"
                    {
                        let vless_link =
                            build_vless_link(yaml_value, remarks.clone(), address, port);
                        return ("".to_string(), vless_link); // 返回的前面是节点名称（v2ray链接的，后面不用remarks节点名称），后面是节点信息
                    } else if target.to_lowercase() == "v2ray"
                        && proxy_type.to_lowercase() == "trojan"
                    {
                        let trojan_link =
                            build_trojan_linnk(yaml_value, remarks.clone(), address, port);
                        return ("".to_string(), trojan_link); // 返回的前面是节点名称（v2ray链接的，后面不用remarks节点名称），后面是节点信息
                    }
                    break;
                }
            }
        }
    } else {
        println!("不是序列");
    }
    // 返回的前面是节点名称，后面是节点配置
    return ("".to_string(), "".to_string());
}

fn build_vless_link(
    yaml_value: &mut Value,
    set_remarks: String,
    set_server: String,
    set_port: u16,
) -> String {
    let uuid = yaml_value
        .get(&Value::String("uuid".to_string()))
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    let network = yaml_value
        .get(&Value::String("network".to_string()))
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    // sni字段或servername字段都视为同一个字段
    let sni = match yaml_value.get("sni").and_then(Value::as_str) {
        Some(value) => value.to_string(),
        None => {
            match yaml_value.get("servername").and_then(Value::as_str) {
                Some(value) => value.to_string(),
                None => "".to_string(), // 默认值，如果没有找到任何字段
            }
        }
    };

    let security = get_vless_tls_value(yaml_value);

    let client_fingerprint = get_client_fingerprint(yaml_value);

    let (path, host) = get_ws_path_and_host(yaml_value);

    let alpn = get_alpn(yaml_value);

    let encoding_alpn = encode(&alpn);
    let encoding_path = encode(&path);
    let encoding_remarks = encode(set_remarks.as_str());

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

fn build_trojan_linnk(
    yaml_value: &mut Value,
    set_remarks: String,
    set_server: String,
    set_port: u16,
) -> String {
    let password = yaml_value
        .get(&Value::String("password".to_string()))
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let network = yaml_value
        .get(&Value::String("network".to_string()))
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    let sni = yaml_value
        .get("sni")
        .and_then(Value::as_str)
        .map_or("".to_string(), |value| value.to_string());

    let client_fingerprint = get_client_fingerprint(yaml_value);

    let (path, host) = get_ws_path_and_host(yaml_value);

    let alpn = get_alpn(yaml_value);

    // url编码
    let encoding_alpn = encode(&alpn);
    let encoding_path = encode(&path);
    let encoding_remarks = encode(&set_remarks);

    let security = if host.ends_with("workers.dev") {
        "none"
    } else {
        "tls"
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

// 原来就是clash配置的，直接修改对应的值即可
fn build_clash_json(
    yaml_value: &mut Value,
    set_remarks: String,
    set_server: String,
    set_port: u16,
) -> &mut Value {
    if let Some(name) = yaml_value.get_mut(&Value::String("name".to_string())) {
        match name {
            Value::String(ref mut name_str) => {
                *name_str = set_remarks.into();
            }
            _ => {
                println!("name字段不是字符串类型");
            }
        }
    } else {
        println!("name字段不存在");
    }
    if let Some(server) = yaml_value.get_mut(&Value::String("server".to_string())) {
        match server {
            Value::String(ref mut server_str) => {
                *server_str = set_server.into();
            }
            _ => {
                println!("server该字段不是字符串类型");
            }
        }
    } else {
        println!("server字段不存在");
    }
    if let Some(port) = yaml_value.get_mut(&Value::String("port".to_string())) {
        match port {
            Value::Number(ref mut port_num) => {
                *port_num = set_port.into();
            }
            _ => {
                println!("port字段不是数字类型");
            }
        }
    } else {
        println!("port字段不存在");
    }
    yaml_value
}

fn get_vless_tls_value(yaml_value: &mut Value) -> String {
    let security = yaml_value
        .get("tls")
        .and_then(Value::as_bool)
        .map(|v| {
            if v {
                "tls".to_string()
            } else {
                "none".to_string()
            }
        })
        .unwrap_or("none".to_string());

    security
}

fn get_alpn(yaml_value: &mut Value) -> String {
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

fn serialize_to_query_string(params: BTreeMap<&str, &str>) -> String {
    let filtered_params: BTreeMap<_, _> =
        params.into_iter().filter(|(_, v)| !v.is_empty()).collect();
    let all_params_str = qs::to_string(&filtered_params).unwrap();
    all_params_str
}

fn get_ws_path_and_host(yaml_value: &mut Value) -> (String, String) {
    let mut path = "".to_string();
    let mut host = "".to_string();
    if let Some(opts_mapping) = yaml_value.get("ws-opts").and_then(Value::as_mapping) {
        path = opts_mapping
            .get("path")
            .and_then(Value::as_str)
            .map_or("".to_string(), |value| value.to_string());
        let host_value =
            if let Some(header_mapping) = opts_mapping.get("headers").and_then(Value::as_mapping) {
                match header_mapping.get("host").and_then(Value::as_str) {
                    Some(value) => value.to_string(),
                    None => match header_mapping.get("Host").and_then(Value::as_str) {
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

fn get_client_fingerprint(yaml_value: &mut Value) -> String {
    let client_fingerprint = yaml_value
        .get("client-fingerprint")
        .and_then(Value::as_str)
        .filter(|fingerprint| !fingerprint.is_empty())
        .map_or_else(|| "".to_string(), |fingerprint| fingerprint.to_string());
    client_fingerprint
}
