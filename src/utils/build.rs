use super::{
    convert,
    file_data::{self, MyData},
    net_data,
};
use crate::Params;

use lazy_static::lazy_static;
use regex::Regex;
use serde_json::{json, Value as JsonValue};
use serde_yaml::Value as YamlValue;

lazy_static! {
    // 匹配包含 "name:" 的 "- {}" 字符串，应用到clash相关代码中
    static ref PROXYIES_NAME_REGEX: Regex = Regex::new(
        r"  - \{([^}]*(name:[^}]*)[^}]*)\}"
    ).unwrap();
    static ref HTTP_PORTS: [u16; 7] = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    static ref HTTPS_PORTS: [u16; 6] = [443, 2053, 2083, 2087, 2096, 8443];
}

pub fn get_vec_data(uri_params: Params) -> Vec<Vec<MyData>> {
    // 针对win11中"复制文件地址"出现双引号的情况
    let trimmed_quotes_path = uri_params.data_source.trim_matches('"');

    // 从文件中读取数据，最大读取数，数据没有过滤
    let max_line: usize = 10000;

    // 获取数据(网络数据/本地数据)
    let my_datas: Vec<MyData> = if trimmed_quotes_path.to_lowercase().starts_with("https://") {
        // 传入的一个https://链接，就从网络获取数据
        net_data::process_network_data(
            &uri_params.column_name,
            uri_params.default_port,
            max_line,
            trimmed_quotes_path,
        )
    } else {
        // 传入的是本地文件路径，就从本地获取数据
        file_data::process_files_data(
            &uri_params.column_name, // 获取指定字段的数据作为节点别名的前缀
            uri_params.default_port, // 没有找到端口的情况，就使用它
            max_line,                // 获取指定数量的数据就返回
            trimmed_quotes_path,     // 指定数据源所在文件夹路径或文件路径
        )
    };

    if !my_datas.is_empty() {
        // ———————————————————————————————— 过滤不要的数据 ——————————————————————————————

        // 根据TLS模式是否开启，反向剔除不要端口的数据
        let filter_ports = match uri_params.tls_mode.as_str() {
            "true" | "1" | "all" => HTTP_PORTS.to_vec(), // 过滤掉非TLS模式的端口
            "false" | "0" => HTTPS_PORTS.to_vec(),       // 过滤掉TLS模式的端口
            _ => HTTP_PORTS.to_vec(),
        };
        let filtered_data: Vec<MyData> = my_datas
            .iter()
            .filter(|item| {
                // 端口不在filter_ports中，则保留
                if let Some(port) = item.port {
                    !filter_ports.contains(&port)
                } else {
                    true // 如果port为None，保留该元素
                }
            })
            .cloned()
            .collect();

        // —————————————————————————————————— 数据分页 ——————————————————————————————————

        // 定义每页的最大长度（元素个数），主要限制singbox、clash配置文件最多节点数
        let page_size = match uri_params.target.as_str() {
            "singbox" | "clash" => match (1..151).contains(&uri_params.node_count) {
                true => uri_params.node_count,
                false => 50,
            },
            _ => uri_params.node_count,
        };

        // 将 Vec<MyData> 转换为 Vec<Vec<MyData>>
        let paginated_data: Vec<Vec<MyData>> = filtered_data
            .chunks(page_size)
            .map(|chunk| chunk.to_vec())
            .collect();
        return paginated_data;
    }

    return Vec::new();
}

/// 分拣数据以及创建订阅内容
pub fn sorting_data_and_build_subscribe(
    all_proxies_yaml: YamlValue,
    uri_params: Params,
    clash_template: &str,
    singbox_template: &str,
) -> String {
    let paginated_data = get_vec_data(uri_params.clone());

    match paginated_data.get(uri_params.page - 1) {
        Some(page_data) => {
            // 没有数据，就返回空字符串
            if page_data.is_empty() {
                return String::new();
            }

            // 下面的代码块，通过不同的转换，获取节点名称和节点配置或v2ray链接
            let mut proxy_name_vec = Vec::new();
            let mut nodes_vec = Vec::new();
            for item in page_data {
                let csv_alias = item.alias.clone().unwrap_or("".to_string());
                let csv_addr = item.addr.clone();
                let csv_port = item.port.unwrap_or(uri_params.default_port);
                let (proxy_name, node) = convert::subconvert(
                    csv_alias,
                    csv_addr,
                    csv_port,
                    all_proxies_yaml.clone(),
                    uri_params.target.clone(),
                    uri_params.proxy_type.clone(),
                    uri_params.tls_mode.clone(),
                    uri_params.userid.clone(),
                    uri_params.skip_transport.clone(),
                    &HTTP_PORTS,
                    &HTTPS_PORTS,
                );
                if !node.is_empty() && !nodes_vec.contains(&node) {
                    nodes_vec.push(node);
                }
                if !proxy_name.is_empty()
                    && vec!["clash", "singbox"].contains(&uri_params.target.as_str())
                    && !proxy_name_vec.contains(&proxy_name)
                {
                    proxy_name_vec.push(proxy_name);
                }
            }

            // 防止没有nodes_vec数据
            if nodes_vec.is_empty() {
                return String::new();
            }

            // 前面获取到数据后，开始构建完整的配置文件订阅（或分享链接订阅）
            let full_subscribe = build_full_subscribe(
                uri_params.target,
                uri_params.template,
                proxy_name_vec,
                nodes_vec,
                clash_template,
                singbox_template,
            );

            full_subscribe
        }
        None => {
            // 如果没有数据，就返回空字符串
            return String::new();
        }
    }
}

/// 将生成的nodes_vec节点信息，构建完整的订阅（或分享链接订阅）
fn build_full_subscribe(
    target: String,
    enable_template: bool,
    proxy_name_vec: Vec<String>,
    nodes_vec: Vec<String>,
    clash_template: &str,
    singbox_template: &str,
) -> String {
    let mut html_body = String::new();
    match target.as_str() {
        "clash" => {
            match enable_template {
                true => {
                    // 读取模板文件
                    let content: String = std::fs::read_to_string(clash_template).unwrap();
                    // 替换模板文件中的内容
                    if !proxy_name_vec.is_empty() && !content.is_empty() {
                        html_body = PROXYIES_NAME_REGEX
                            .replace_all(&content, &nodes_vec.join("\n"))
                            .replace(
                                "      - 127.0.0.1:1080",
                                &proxy_name_vec
                                    .clone()
                                    .iter_mut()
                                    .map(|name| format!("      - {}", name))
                                    .collect::<Vec<String>>()
                                    .join("\n"),
                            );
                    }
                }
                false => {
                    html_body = format!("proxies:\n{}", nodes_vec.join("\n"));
                }
            }
        }
        "singbox" => {
            match enable_template {
                true => {
                    let content = std::fs::read_to_string(singbox_template).unwrap();
                    let singbox_json: JsonValue =
                        serde_json::from_str(&content).unwrap_or_default();
                    // 运用插入/retain()等操作修改模板文件的内容
                    if !proxy_name_vec.is_empty() && singbox_json.is_object() {
                        let mut singbox_config = singbox_json.clone();
                        if let Some(outbounds) = singbox_config["outbounds"].as_array_mut() {
                            // 将节点插入到outbounds中
                            for json_str in &nodes_vec {
                                let parsed_json =
                                    serde_json::from_str(json_str).expect("Failed to parse JSON");
                                outbounds.insert(2, parsed_json); // 插入到第3个位置
                            }
                            outbounds.iter_mut().for_each(|item| {
                                if let Some(obj) = item.as_object_mut() {
                                    obj.get_mut("outbounds")
                                        .and_then(JsonValue::as_array_mut)
                                        .map(|inside_outbounds| {
                                            // 使用 retain 方法来过滤掉 "{all}"
                                            inside_outbounds
                                                .retain(|x| x.as_str() != Some("{all}"));
                                            // 添加 proxy_name 到内层的 outbounds 中
                                            inside_outbounds.extend(
                                                proxy_name_vec
                                                    .iter()
                                                    .map(|s| JsonValue::String(s.clone())),
                                            );
                                        });
                                }
                            });
                        }
                        html_body = serde_json::to_string_pretty(&singbox_config).unwrap();
                    }
                }
                false => {
                    let mut outbounds = json!({"outbounds": []});
                    if let Some(array) = outbounds["outbounds"].as_array_mut() {
                        nodes_vec.iter().for_each(|name| {
                            array.push(serde_json::from_str(name).unwrap());
                        });
                    }
                    html_body = serde_json::to_string_pretty(&outbounds).unwrap();
                }
            }
        }
        _ => {
            html_body = nodes_vec.join("\n"); // 视为v2ray订阅的分享链接
        }
    }

    html_body
}
