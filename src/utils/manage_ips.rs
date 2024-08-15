use lazy_static::lazy_static;
use regex::Regex;
use serde_yaml::Value as YamlValue;

lazy_static! {
    static ref IP_WITH_PORT_REGEX: Regex = Regex::new(r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3}),(\d{2,5})\b|(([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}),(\d{2,5})\b").unwrap();
}

pub fn batch_ips(
    ip_with_port_vec: Vec<String>,
    ip_with_none_port_vec: Vec<String>,
    nodes_vec: &mut Vec<String>,
    proxy_name_vec: &mut Vec<String>,
    config_data: YamlValue,
    target: String,
    port: u16,
    userid: u8,
    proxy_type: String,
    filter_tls_port: String,
    node_count: usize,
) {
    if !ip_with_port_vec.is_empty() && ip_with_none_port_vec.is_empty() {
        // 下面代码，用于处理有端口的
        let ip_with_port_take_vec: Vec<String> =
            ip_with_port_vec.iter().take(node_count).cloned().collect(); // 获取前node_count个
        processing_ips_with_ports(
            ip_with_port_take_vec,
            nodes_vec,
            proxy_name_vec,
            config_data,
            target.clone(),
            proxy_type,
            userid,
            filter_tls_port,
        );
    } else if ip_with_port_vec.is_empty() && !ip_with_none_port_vec.is_empty() {
        // 下面代码，用于处理没有端口的
        let ips: Vec<String> = ip_with_none_port_vec
            .iter()
            .take(node_count)
            .cloned()
            .collect(); // 获取前node_count个

        processing_ips(
            ips,
            nodes_vec,
            proxy_name_vec,
            config_data.clone(),
            target.clone(),
            port,
            proxy_type,
            userid,
            filter_tls_port,
        );
    } else if !ip_with_port_vec.is_empty() && !ip_with_none_port_vec.is_empty() {
        // 下面的代码，用于处理既有端口的和没有端口的
        let ip_with_port_take_vec: Vec<String> =
            ip_with_port_vec.iter().take(node_count).cloned().collect();

        processing_ips_with_ports(
            ip_with_port_take_vec.clone(),
            nodes_vec,
            proxy_name_vec,
            config_data.clone(),
            target.clone(),
            proxy_type.clone(),
            userid,
            filter_tls_port.clone(),
        );

        if ip_with_port_take_vec.len() < node_count {
            // ips_with_ports向量中的数量不满node_count数量时，就从ip_with_none_port_vec中获取
            let ips: Vec<String> = ip_with_none_port_vec
                .iter()
                .take(node_count - ip_with_port_take_vec.len())
                .cloned()
                .collect();
            if !ips.is_empty() {
                processing_ips(
                    ips,
                    nodes_vec,
                    proxy_name_vec,
                    config_data.clone(),
                    target.clone(),
                    port,
                    proxy_type,
                    userid,
                    filter_tls_port,
                );
            }
        }
    }
}

fn processing_ips(
    ips: Vec<String>,
    nodes: &mut Vec<String>,
    proxy_name_vec: &mut Vec<String>,
    config_data: YamlValue,
    target: String,
    port: u16,
    proxy_type: String,
    userid: u8,
    tls_mode: String,
) {
    ips.iter().for_each(|ip| {
        let (proxy_name, node) = crate::utils::convert::subconvert(
            config_data.clone(),
            target.clone(),
            ip.clone(),
            port,
            proxy_type.clone(),
            userid.clone(),
            tls_mode.clone(),
        );
        if !node.is_empty() && !nodes.contains(&node) {
            nodes.push(node);
        }
        if (target == "clash" || target == "singbox")
            && !proxy_name.is_empty()
            && !proxy_name_vec.contains(&proxy_name)
        {
            proxy_name_vec.push(proxy_name);
        }
    });
}
fn processing_ips_with_ports(
    ips_with_ports: Vec<String>,
    nodes: &mut Vec<String>,
    proxy_name_vec: &mut Vec<String>,
    config_data: YamlValue,
    target: String,
    proxy_type: String,
    userid: u8,
    tls_mode: String,
) {
    ips_with_ports.iter().for_each(|ip_with_port| {
        IP_WITH_PORT_REGEX
            .captures_iter(ip_with_port)
            .for_each(|cap| {
                let cap_ip = cap
                    .get(1)
                    .map_or("".to_string(), |m| m.as_str().to_string());
                let cap_port = cap.get(2).map_or(0, |m| m.as_str().parse::<u16>().unwrap());
                let (proxy_name, node) = crate::utils::convert::subconvert(
                    config_data.clone(),
                    target.clone(),
                    cap_ip,
                    cap_port,
                    proxy_type.clone(),
                    userid.clone(),
                    tls_mode.clone(),
                );
                if !node.is_empty() && !nodes.contains(&node) {
                    nodes.push(node);
                }
                if (target == "clash" || target == "singbox")
                    && !proxy_name.is_empty()
                    && !proxy_name_vec.contains(&proxy_name)
                {
                    proxy_name_vec.push(proxy_name);
                }
            })
    });
}
