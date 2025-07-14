use super::config::{get_yaml_value, get_yaml_value_with_fallback};
use super::{clash, singbox, v2ray};
use rand::prelude::IndexedRandom;
use serde_yaml::Value as YamlValue;

pub fn subconvert(
    csv_alias: String,
    csv_addr: String,
    mut port: u16,
    yamlvalue: YamlValue,
    uri_target: String,
    uri_proxy_type: String,
    uri_tls_mode: String,
    uri_userid: u8,
    skip_transport: bool,
    http_ports: &[u16; 7],
    https_ports: &[u16; 6],
) -> (String, String) {
    // 判断端口类型的闭包
    let is_https_ports = move |port: u16| -> bool { https_ports.contains(&port) };
    let is_http_ports = move |port: u16| -> bool { http_ports.contains(&port) };

    let csv_remarks = match csv_alias.is_empty() {
        true => String::new(),
        false => format!("{} | ", csv_alias),
    };
    if let Some(sequence) = yamlvalue.clone().as_sequence_mut() {
        // 循环200次，直到选中合适的节点配置为止，或循环200次才跳出循环
        for _ in 0..200 {
            let choose_item = sequence.choose(&mut rand::rng()).unwrap();
            let mut choose_item_clone = choose_item.clone();

            // ************** 1、初步排除不要的配置（对比配置的id和type） **************

            let id = get_yaml_value(&choose_item_clone, &"id")
                .and_then(|v| v.as_str().and_then(|s| s.parse::<usize>().ok()))
                .unwrap_or(0);

            let node_type = choose_item
                .get("type")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or("all".to_string());
            let userid = uri_userid as usize;
            if (uri_proxy_type != "all" && uri_proxy_type != node_type)
                || (userid != 0 && userid != id)
            {
                continue;
            }

            // ******************** 2、再次排除tls模式不符合的配置 ********************

            // 只有trojan根据sni或servername字段的值来判断tls，其它按照tls值判断
            let node_tls: String = match node_type.as_str() {
                "vless" | "vmess" | "ss" => {
                    get_yaml_value_with_fallback(choose_item, &["tls", "plugin-opts.tls"])
                        .map(|s| s.to_string())
                        .or_else(|| {
                            ["tls", "plugin-opts.tls"]
                                .iter()
                                .filter_map(|&path| get_yaml_value(choose_item, path))
                                .find_map(|v| v.as_bool().map(|b| b.to_string()))
                        })
                        .unwrap_or("false".to_string())
                }
                "trojan" => {
                    let servername =
                        get_yaml_value_with_fallback(choose_item, &["sni", "servername"])
                            .unwrap_or_default();
                    (!servername.ends_with("workers.dev")).to_string()
                }
                _ => "true".to_string(), // 不支持的协议，默认是true，可以使用clash
            };
            if (uri_tls_mode != "all" && uri_tls_mode != node_tls)
                || (node_tls == "true" && is_http_ports(port))
                || (node_tls == "false" && is_https_ports(port))
            {
                continue;
            }

            // ************************ 端口不存在的，随机端口 ************************

            let random_https_port = https_ports.choose(&mut rand::rng()).unwrap_or(&443);
            let random_http_port = http_ports.choose(&mut rand::rng()).unwrap_or(&8080);
            if node_tls == "true" && port == 0 {
                port = *random_https_port;
            } else if node_tls == "false" && port == 0 {
                port = *random_http_port;
            }

            let mut remarks = format!("【{}】{}{}:{}", id, csv_remarks, csv_addr.clone(), port);
            match uri_target.as_str() {
                "v2ray" => {
                    // 是否将ss节点添加到v2rayN中使用，需要就只写别名、地址、端口、密码和加密方式，其它需要自己手动补充
                    let mut skip_ss_transport = false;
                    if uri_proxy_type == "ss"
                        && node_type == "ss"
                        && node_tls == "true"
                        && skip_transport
                    {
                        let host = get_yaml_value(&choose_item, &"plugin-opts.host")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        remarks = format!("❓{}", host);
                        skip_ss_transport = true;
                    }
                    let (remarks_name, link) = v2ray::build_v2ray_links(
                        &node_type,
                        &mut choose_item_clone,
                        remarks,
                        csv_addr,
                        port,
                        skip_ss_transport,
                    );
                    if !remarks_name.is_empty() {
                        return (remarks_name, link);
                    }
                }
                "singbox" => {
                    let (remarks_name, json_string) = singbox::build_singbox_config_json(
                        &node_type,
                        &mut choose_item_clone,
                        remarks,
                        csv_addr,
                        port,
                    );
                    if !remarks_name.is_empty() {
                        return (remarks_name, json_string);
                    }
                }
                "clash" => {
                    let clash_node = clash::build_clash_yaml(
                        &mut choose_item_clone,
                        remarks.clone(),
                        csv_addr,
                        port,
                    );
                    let json_node: String = serde_json::to_string(&clash_node).unwrap();
                    let json_string = format!("  - {json_node}");
                    return (remarks, json_string);
                }

                _ => {}
            }

            break;
        }
    }

    // 返回的前面是节点名称，后面是节点配置
    return (String::new(), String::new());
}
