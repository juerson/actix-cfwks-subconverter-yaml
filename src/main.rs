mod utils;

use actix_web::{get, App, HttpRequest, HttpResponse, HttpServer, Responder};
use lazy_static::lazy_static;
use local_ip_address::local_ip;
use regex::Regex;
use serde_json::json;
use serde_urlencoded::from_str;
use serde_yaml::Value as YamlValue;
use std::fs;

const SPECIFICATION: &str = include_str!("../使用说明.txt");

lazy_static! {
    static ref PROXYIES_NODE_INFO_REGEX: Regex = Regex::new(r"  - \{([^}]*(name:[^}]*)[^}]*)\}").unwrap(); // 匹配包含 "name:" 的 "- {}" 字符串
}

async fn default_route() -> impl Responder {
    HttpResponse::NotFound().body("Not found.")
}

#[get("/")]
async fn index(req: HttpRequest) -> impl Responder {
    let host_address = req.connection_info().host().to_owned();

    let html_body = SPECIFICATION.replace("127.0.0.1:10111", &host_address);

    // 获取当前局域网IP地址
    let ip_address = local_ip().unwrap().to_string();

    // 获取当前URL
    let url = format!(
        "{}://{}{}",
        req.connection_info().scheme(),
        req.connection_info()
            .host()
            .replace("127.0.0.1", &ip_address),
        req.uri()
    );

    // 生成二维码并将html_body嵌入网页中
    let html_content = utils::qrcode::generate_html_with_qrcode(&html_body, &url);

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html_content)
}

#[get("/sub")]
async fn subconverter(req: HttpRequest) -> impl Responder {
    let query_str = req.query_string();
    let params: Vec<(String, String)> = from_str(&query_str).expect("Failed to parse query string");

    let folder_path = "data";
    let config_file = "config.yaml";
    let clash_template = "template/clash.yaml";
    let singbox_template = "template/sing-box.json";

    // 参数
    let mut target = "".to_string();
    let mut node_count: usize = 300; // 您想要获取多少个节点？默认值是300
    let mut port: u16 = 0; // 这里设置0，随机端口，如果设置[80,65535)，则使用这个端口，除非端口跟tls或非tls端口冲突
    let mut tls_mode: String = "all".to_string(); // 选择哪些端口？true/1是选择TLS端口，false/0选择非TLS的端口，其它就不区分
    let mut proxy_type = "all".to_string(); // 不区分代理的类型（vles、trojan）
    let mut userid: u8 = 0;
    let mut template = true; // 是否使用模板文件，默认使用

    // 获取url的参数
    for (key, value) in params {
        if key.to_lowercase() == "target" {
            target = value.to_string();
        } else if key.to_lowercase() == "nodesize" || key.to_lowercase() == "nodecount" {
            node_count = value.parse::<usize>().unwrap_or(node_count);
        } else if key.to_lowercase() == "dport" || key.to_lowercase() == "defaultport" {
            let input_port = value.parse().expect("Failed to parse setport");
            match input_port >= 80 && input_port < 65535 {
                true => port = input_port,
                false => port = port,
            }
        } else if key.to_lowercase() == "tls" || key.to_lowercase() == "tlsmode" {
            let input_tls_mode = value.to_string();
            if ["true", "false", "1", "0"].contains(&input_tls_mode.as_str()) {
                tls_mode = match input_tls_mode.as_str() {
                    "1" | "true" => "true".to_string(),
                    "0" | "false" => "false".to_string(),
                    _ => "all".to_string(),
                };
            }
        } else if key.to_lowercase() == "proxy" || key.to_lowercase() == "proxytype" {
            // 选择那种协议的配置节点？是vless还是trojan
            let input_proxy_type = value.trim().to_string();
            if ["vless", "trojan"].contains(&input_proxy_type.as_str()) {
                proxy_type = match input_proxy_type.as_str() {
                    "vless" => "vless".to_string(),
                    "trojan" => "trojan".to_string(),
                    _ => "all".to_string(),
                };
            }
        } else if key.to_lowercase() == "userid" {
            let input_userid = value.parse::<u8>().unwrap();
            match input_userid {
                1..=255 => userid = input_userid,
                _ => userid = 0,
            }
        } else if key.to_lowercase() == "template" {
            template = value.parse::<bool>().unwrap_or(true);
        }
    }

    // 限制节点数量
    if target == "singbox" && node_count > 150 {
        node_count = 50;
    } else if target == "clash" && node_count > 150 {
        node_count = 100;
    }

    /*
    获取data文件夹中的数据
    ip_with_none_port_vec：从本地文件中，读取到没有端口的IP、域名
    ip_with_port_vec：从本地文件中，读取到有端口的IP（格式：IP,PORT）
     */
    let (ip_with_none_port_vec, ip_with_port_vec) =
        match utils::data::read_ip_domain_from_files(folder_path, &tls_mode) {
            Ok(result) => result,
            Err(err) => {
                eprintln!("Error reading IP files: {}", err);
                return HttpResponse::InternalServerError().finish();
            }
        };

    let config_data: YamlValue = utils::config::yaml_config_to_json(&config_file);
    let mut nodes_vec = Vec::new();
    let mut proxy_name_vec: Vec<String> = Vec::new();

    // 处理IP、域名，并生成节点信息，结果写入nodes_vec、proxy_name_vec中
    utils::manage_ips::batch_ips(
        ip_with_port_vec,
        ip_with_none_port_vec,
        &mut nodes_vec,
        &mut proxy_name_vec,
        config_data,
        target.clone(),
        port,
        userid,
        proxy_type,
        tls_mode,
        node_count,
    );

    // 处理输出的内容
    if target == "clash" {
        let mut html_body = String::new();
        match template {
            true => {
                let clash_template_string = utils::file::read_file_to_string(clash_template);
                if !nodes_vec.is_empty()
                    && !proxy_name_vec.is_empty()
                    && !clash_template_string.is_empty()
                {
                    let proxies_node_content = PROXYIES_NODE_INFO_REGEX
                        .replace_all(&clash_template_string, &nodes_vec.join("\n"));
                    html_body = proxies_node_content.replace(
                        "      - 127.0.0.1:1080",
                        &proxy_name_vec
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
        HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body(html_body)
    } else if target == "singbox" {
        let mut html_body = String::new();
        match template {
            true => {
                // sing-box配置模板
                let template_content =
                    fs::read_to_string(singbox_template).unwrap_or(String::new());
                let singbox_template: serde_json::Value =
                    serde_json::from_str(&template_content).unwrap_or(serde_json::Value::Null);
                if !nodes_vec.is_empty()
                    && !proxy_name_vec.is_empty()
                    && singbox_template.is_object()
                {
                    let mut singbox_config = singbox_template.clone();
                    if let Some(outbounds) = singbox_config["outbounds"].as_array_mut() {
                        // 将节点插入到outbounds中
                        for json_str in &nodes_vec {
                            let parsed_json =
                                serde_json::from_str(json_str).expect("Failed to parse JSON");
                            outbounds.insert(2, parsed_json); // 插入到第3个位置
                        }
                        outbounds.iter_mut().for_each(|item| {
                            if let Some(obj) = item.as_object_mut() {
                                if let Some(inside_outbounds) = obj
                                    .get_mut("outbounds")
                                    .and_then(serde_json::Value::as_array_mut)
                                {
                                    // 查找并删除目标值 "{all}"、并将新值合并进来
                                    if let Some(pos) = inside_outbounds
                                        .iter()
                                        .position(|x| x.as_str() == Some("{all}"))
                                    {
                                        // 删除"{all}"字符串
                                        inside_outbounds.remove(pos);

                                        // 将代理tag别名插入
                                        let json_values: Vec<serde_json::Value> = proxy_name_vec
                                            .iter()
                                            .map(|s| serde_json::Value::String(s.clone())) // 将每个转换为 serde_json::Value
                                            .collect();

                                        // 将新数据合并到目标数组
                                        inside_outbounds.extend(json_values);
                                    }
                                }
                            }
                        });
                    }
                    html_body = serde_json::to_string_pretty(&singbox_config).unwrap();
                }
            }
            false => {
                let mut outbounds = json!({"outbounds": []});
                if let Some(array) = outbounds["outbounds"].as_array_mut() {
                    for json_str in &nodes_vec {
                        let parsed_json =
                            serde_json::from_str(json_str).expect("Failed to parse JSON");
                        array.push(parsed_json);
                    }
                }
                html_body = serde_json::to_string_pretty(&outbounds).unwrap();
            }
        }
        HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body(html_body)
    } else {
        let html_body = nodes_vec.join("\n");
        HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body(html_body)
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 获取本机的私有IP地址
    let local_ip = match local_ip() {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("Failed to get local IP address: {}", e);
            return Ok(());
        }
    };
    // 绑定的端口
    let port = 10111;
    println!(
        "Server is running on http://{}:{} or http://127.0.0.1:{}",
        local_ip.to_string(),
        port,
        port
    );
    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(subconverter)
            .default_service(actix_web::web::route().to(default_route))
    })
    .bind(format!("0.0.0.0:{}", port))? // 监听所有 IPv4 地址
    .run()
    .await
}
