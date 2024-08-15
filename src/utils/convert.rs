use rand::seq::SliceRandom;
use rand::Rng;
use serde_yaml::Value;

pub fn subconvert(
    mut json_data: Value,
    target: String,
    address: String,
    mut port: u16,
    select_proxy_type: String,
    userid: u8,
    tls_mode: String,
) -> (String, String) {
    if let Some(sequence) = json_data.as_sequence_mut() {
        let length = sequence.len();
        let mut index;

        let not_tls_ports: Vec<u16> = vec![80, 8080, 8880, 2052, 2082, 2086, 2095];
        let tls_ports: Vec<u16> = vec![443, 2053, 2083, 2087, 2096, 8443];

        // 循环200次，随机选择一个节点配置信息，符合要求或满足最大循环次数，就跳出循环
        for _ in 0..200 {
            let random_https_port = tls_ports.choose(&mut rand::thread_rng()).unwrap_or(&443);
            let random_http_port: &u16 =
                not_tls_ports.choose(&mut rand::thread_rng()).unwrap_or(&80);

            index = match (1..=(length + 1) as u8).contains(&userid) {
                true => userid as usize - 1, // 选择指定的账号（数组的下标）
                false => rand::thread_rng().gen_range(0..length), // 随机选择账号（数组的下标）
            };

            // 获取选择的节点信息（配置文件数组的下标）
            if let Some(yaml_value) = sequence.get_mut(index) {
                let proxy_type = yaml_value
                    .get("type")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();

                let (_, host) = crate::utils::config::get_path_and_host_value(yaml_value);

                let is_workers_dev = host.ends_with("workers.dev");
                let is_tls_port = tls_ports.contains(&port);
                let is_not_tls_port = not_tls_ports.contains(&port);

                // 让 workers.dev 对标非tls的端口(http的端口)，其他的host对标tls的端口(https的端口)
                if (!is_workers_dev && port == 0) || (is_not_tls_port && !is_workers_dev) {
                    port = *random_https_port;
                } else if (is_workers_dev && port == 0) || (is_tls_port && is_workers_dev) {
                    port = *random_http_port;
                }
                if (tls_mode.to_lowercase() == "true" && not_tls_ports.contains(&port))
                    || (tls_mode.to_lowercase() == "false" && tls_ports.contains(&port))
                {
                    continue;
                }

                if select_proxy_type.to_lowercase() == proxy_type.to_lowercase()
                    || select_proxy_type.to_lowercase() == "all"
                {
                    let padded_index =
                        format!("{:0width$}", index + 1, width = length.to_string().len());
                    // 节点名称
                    let remarks: String = format!("cfwks[{}]-{}:{}", padded_index, address, port);

                    if target.to_lowercase() == "clash" {
                        let mut yaml_value_clone = yaml_value.clone();
                        let clash_node = crate::utils::clash::build_clash_json(
                            &mut yaml_value_clone,
                            remarks.clone(),
                            address,
                            port,
                        );
                        let json_str = serde_json::to_string(&clash_node).unwrap();
                        let clash_with_prefix = format!("  - {json_str}");
                        return (remarks, clash_with_prefix); // 返回的前面是节点名称，后面是节点配置
                    } else if target.to_lowercase() == "v2ray" {
                        match proxy_type.to_lowercase().as_str() {
                            "vless" => {
                                let vless_link = crate::utils::v2ray::build_vless_link(
                                    yaml_value,
                                    remarks.clone(),
                                    address,
                                    port,
                                );
                                return (remarks, vless_link); // 返回的前面是节点名称，后面是节点配置
                            }
                            "trojan" => {
                                let trojan_link = crate::utils::v2ray::build_trojan_linnk(
                                    yaml_value,
                                    remarks.clone(),
                                    address,
                                    port,
                                );
                                return (remarks, trojan_link); // 返回的前面是节点名称，后面是节点配置
                            }
                            _ => {}
                        }
                    } else if target.to_lowercase() == "singbox" {
                        match proxy_type.to_lowercase().as_str() {
                            "vless" => {
                                let (remarks_name, vless_singbox) =
                                    crate::utils::singbox::build_vless_singbox_config(
                                        yaml_value, remarks, &address, port,
                                    );
                                return (remarks_name, vless_singbox);
                            }
                            "trojan" => {
                                //
                                let (remarks_name, trojan_singbox) =
                                    crate::utils::singbox::build_trojan_singbox_config(
                                        yaml_value, remarks, &address, port,
                                    );
                                return (remarks_name, trojan_singbox);
                            }
                            _ => {}
                        }
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
