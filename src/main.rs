mod utils;

use actix_web::{get, App, HttpRequest, HttpResponse, HttpServer, Responder};
use regex::Regex;
use std::fs;
use utils::{config::yaml_config_to_json, convert::subconvert, data::read_ip_from_files};

async fn default_route() -> impl Responder {
    HttpResponse::NotFound().body("Not found.")
}

#[get("/sub")]
async fn subconverter(req: HttpRequest) -> impl Responder {
    let query_string = req.query_string();
    let params: Vec<(String, String)> =
        serde_urlencoded::from_str(&query_string).expect("Failed to parse query string");

    // 本地数据的存储路径
    let folder_path = "data";
    // 节点的配置文件（原来就是clash配置的）
    let node_config_file = "node-config.yaml";
    // 参数
    let mut target = "".to_string();
    let mut node_count: usize = 300;
    let mut port: u16 = 0; // 这里设置0，使用配置文件中的端口
    let mut tls_mode: String = "".to_string(); // 选择哪些端口？0为使用非TLS的端口、1为使用TLS的端口？
    let mut select_proxy_type = "all".to_string(); // 不区分代理的类型（vles、trojan）
    let mut account_number: u8 = 0; // 选择账号，默认为第一个账号
    for (key, value) in params {
        if key.to_lowercase() == "target" {
            // 转换为目标客户端，这里只有两个：v2ray、clash
            target = value.to_string();
        } else if key.to_lowercase() == "nodesize" || key.to_lowercase() == "nodecount" {
            // 您想要获取多少个节点？默认300个
            node_count = value.parse::<usize>().unwrap();
        } else if key.to_lowercase() == "dport" || key.to_lowercase() == "defaultport" {
            // 设置默认port，仅没有端口的IP使用
            port = value.parse::<u16>().unwrap();
        } else if key.to_lowercase() == "tls" || key.to_lowercase() == "tlsmode" {
            // true/tls/1是选择TLS端口，false/0选择非TLS的端口，其它就不区分
            tls_mode = value.to_string();
        } else if key.to_lowercase() == "proxy" || key.to_lowercase() == "proxytype" {
            // 选择那种协议的配置节点？是vless还是trojan
            let proxy_type = value.trim().to_string();
            if !proxy_type.is_empty() {
                select_proxy_type = proxy_type;
            }
        } else if key.to_lowercase() == "userid" {
            // 选择节点的配置，从1开始计数（代码会自动选择您要的节点信息来构建节点），1为第一个配置信息，2为第二个配置信息，以此类推
            account_number = value.parse::<u8>().unwrap();
        }
    }

    // 读取配置文件中的信息，并转换为serde_yaml::Value类型
    let json_data = yaml_config_to_json(&node_config_file);

    // 从本地data文件夹中读取数据
    // non_port_vec：从文件中，读取到没有端口的IP
    // ip_with_port_vec：从文件中，读取到有端口的IP（格式：IP,PORT）
    let (non_port_vec, ip_with_port_vec) = match read_ip_from_files(folder_path, &tls_mode) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("Error reading IP files: {}", err);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let mut nodes = Vec::new();
    let mut clash_proxy_name: Vec<String> = Vec::new();
    if ip_with_port_vec.len() != 0 && non_port_vec.len() == 0 {
        // 下面代码，用于处理有端口的
        let ip_and_port_re = Regex::new(r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3}),(\d{2,5})\b|(([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}),(\d{2,5})\b").unwrap();
        let ips_with_ports: Vec<String> =
            ip_with_port_vec.iter().take(node_count).cloned().collect(); // 获取前node_count个
        for ip_with_port in &ips_with_ports {
            for cap in ip_and_port_re.captures_iter(ip_with_port) {
                let cap_ip = cap
                    .get(1)
                    .map_or("".to_string(), |m| m.as_str().to_string());
                let cap_port = cap.get(2).map_or(0, |m| m.as_str().parse::<u16>().unwrap());
                let (proxy_name, node) = subconvert(
                    json_data.clone(),
                    target.clone(),
                    cap_ip,
                    cap_port,
                    select_proxy_type.clone(),
                    account_number.clone(),
                    tls_mode.clone(),
                );
                if !node.is_empty() && !nodes.contains(&node) {
                    nodes.push(node);
                }
                if target == "clash"
                    && !proxy_name.is_empty()
                    && !clash_proxy_name.contains(&proxy_name)
                {
                    clash_proxy_name.push(proxy_name);
                }
            }
        }
    } else if ip_with_port_vec.len() == 0 && non_port_vec.len() != 0 {
        // 下面代码，用于处理没有端口的
        let ips: Vec<String> = non_port_vec.iter().take(node_count).cloned().collect(); // 获取前node_count个
        for ip in &ips {
            let (proxy_name, node) = subconvert(
                json_data.clone(),
                target.clone(),
                ip.clone(),
                port,
                select_proxy_type.clone(),
                account_number.clone(),
                tls_mode.clone(),
            );
            if !node.is_empty() && !nodes.contains(&node) {
                nodes.push(node);
            }
            if target == "clash"
                && !proxy_name.is_empty()
                && !clash_proxy_name.contains(&proxy_name)
            {
                clash_proxy_name.push(proxy_name);
            }
        }
    } else if ip_with_port_vec.len() != 0 && non_port_vec.len() != 0 {
        // 下面的代码，用于处理既有端口的和没有端口的
        let ip_and_port_re = Regex::new(r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3}),(\d{2,5})\b|(([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}),(\d{2,5})\b").unwrap();
        // 获取前node_count个
        let ips_with_ports: Vec<String> =
            ip_with_port_vec.iter().take(node_count).cloned().collect();
        for ip_with_port in &ips_with_ports {
            for cap in ip_and_port_re.captures_iter(ip_with_port) {
                // 分离出IP和PORT
                let cap_ip = cap
                    .get(1)
                    .map_or("".to_string(), |m| m.as_str().to_string());
                let cap_port = cap.get(2).map_or(0, |m| m.as_str().parse::<u16>().unwrap());

                let (proxy_name, node) = subconvert(
                    json_data.clone(),
                    target.clone(),
                    cap_ip,
                    cap_port,
                    select_proxy_type.clone(),
                    account_number.clone(),
                    tls_mode.clone(),
                );
                if !node.is_empty() && !nodes.contains(&node) {
                    nodes.push(node);
                }
                if target == "clash"
                    && !proxy_name.is_empty()
                    && !clash_proxy_name.contains(&proxy_name)
                {
                    clash_proxy_name.push(proxy_name);
                }
            }
        }
        /* 如果ip_with_port_vec数量不足node_count数量的IP，则从non_port_vec中获取剩余数量的IP */
        let remaining_quantity = node_count - ips_with_ports.len();

        // 获取前remaining_quantity个IP
        let ips: Vec<String> = non_port_vec
            .iter()
            .take(remaining_quantity)
            .cloned()
            .collect();
        for ip in &ips {
            let (proxy_name, node) = subconvert(
                json_data.clone(),
                target.clone(),
                ip.clone(),
                port,
                select_proxy_type.clone(),
                account_number.clone(),
                tls_mode.clone(),
            );
            if !node.is_empty() && !nodes.contains(&node) {
                nodes.push(node);
            }
            if target == "clash"
                && !proxy_name.is_empty()
                && !clash_proxy_name.contains(&proxy_name)
            {
                clash_proxy_name.push(proxy_name);
            }
        }
    }
    if target == "clash" {
        match read_yaml_file("clash.yaml").await {
            Ok(content) => {
                let proxies_node_content = content.replace("  - {name: 127.0.0.1:1080, server: 127.0.0.1, port: 1080, type: ss, cipher: aes-128-gcm, password: abc123456}", &nodes.join("\n"));

                let clash_config = proxies_node_content.replace(
                    "      - 127.0.0.1:1080",
                    &clash_proxy_name
                        .iter_mut()
                        .map(|name| format!("      - {}", name))
                        .collect::<Vec<String>>()
                        .join("\n"),
                );
                if nodes.is_empty() {
                    // return HttpResponse::InternalServerError().finish();
                    HttpResponse::Ok()
                        .content_type("text/plain; charset=utf-8")
                        .body("")
                } else {
                    HttpResponse::Ok()
                        .content_type("text/plain; charset=utf-8")
                        .body(clash_config)
                }
            }
            Err(_) => todo!(),
        }
    } else {
        let html_body = nodes.join("\n");
        HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body(html_body)
    }
}

#[get("/")]
async fn index(req: HttpRequest) -> impl Responder {
    let host_address = req.connection_info().host().to_owned();
    let title = format!(
        "软件功能：将优选的IP(不是WARP的优选IP)，写入到 Cloudflare 搭建的 vless/trojan 协议的配置节点中，并转换为 v2ray、clash 订阅!\n\n"
    );
    let web_address = format!("web服务地址：http://{}\n\n", host_address);

    let syntax_info = format!("订阅地址格式：http://{}/sub?target=[v2ray,clash]&nodeSize=[1..?]&proxytype=[vless,trojan]&userid=[1..255]&tls=[true,false]&dport=[80..65535]\n\n", host_address);

    let example1 = format!("订阅示例：\n\nhttp://{}/sub?target=v2ray\n", host_address);
    let example2 = format!("http://{}/sub?target=clash\n",host_address);
    let example3 = format!("http://{}/sub?target=clash&userid=1\n",host_address);
    let example4 = format!("http://{}/sub?target=v2ray&userid=1\n",host_address);
    let example5 = format!("http://{}/sub?target=clash&proxy=trojan\n",host_address);
    let example6 = format!("http://{}/sub?target=clash&proxy=vless\n",host_address);
    let example7 = format!("http://{}/sub?target=v2ray&proxy=vless&userid=3\n",host_address);
    let example8 = format!("http://{}/sub?target=v2ray&nodesize=100\n",host_address);
    let example9 = format!("http://{}/sub?target=v2ray&tls=true&dport=8443\n",host_address);
    let example = format!("{}{}{}{}{}{}{}{}{}\n",example1,example2,example3,example4,example5,example6,example7,example8,example9);
    
    let param_introduction = format!(r#"url中的参数介绍：

1、target：【必选】转换的目标客户端，只支持转换为v2ray、clash，而且是TLS+WS的；vless节点的，支持不是TLS加密的。
2、nodesize（nodecount）：您要的节点数量，是从data目录下，读取到txt、csv文件的所有数据中，截取前n个数据来构建节点的信息。
注意： 
    (1)如果符合要求的txt、csv文件多起来，读取到数据比较多，文件之间的数据排序跟文件名有一点关系；
    (2)不是从data目录中读取到的数据中，随机选择n个数据；而是按照读取到的数据先后顺序，截取前n个数据来构建节点的信息。

3、proxy（proxytype）：选择什么协议的节点？只能选择vless、trojan，这里指您在配置文件中，存放的节点类型，符合要求的，才使用它。
4、userid：指定使用哪个配置文件中的节点，生成v2ray链接或clash配置文件？它是虚构的，是根据程序读取 node-config.yaml 的配置，数组下标+1来计算的。
    例如：
        userid=1就是使用第一个节点的配置信息，2就是使用第二个节点的配置信息，以此类推。
        userid值的范围是[0,255]，为0是随机节点的配置信息，超过配置的总个数也是随机节点的配置信息。
    注意：
        (1)proxy 和 userid 两个都设置且设置不当，可能导致生成空白页面，要传入正确的值才能生成节点信息。
           例如：proxy=vless&userid=2，配置文件中第2个节点不是vless，就不能生成节点的配置信息，导致空白页面出现。
        (2)userid值超出[0,255]范围，程序会报错，显示"该网页无法正常运作"。

5、tls（tlsmode）：用于控制使用哪些端口（包括使用哪些节点）。tls=true/1/tls表示使用tls加密，false/0表示不使用tls加密；如果为空/不传入该参数，就不区分tls和非tls。
6、dport（defaultport）：data目录下，读取到txt、csv文件的数据中，没有端口的情况，使用这里设置的默认端口。
    使用注意：
        (1)url地址中传入的端口，只覆盖从配置文件中读取到的PORT; 
        (2)data目录下读取到的数据，有端口的情况，不会使用dport设置的默认端口；
        (3)只有从data文件夹中读取的数据中，没有端口的情况，才使用dport设置的默认端口；
        (4)dport 和 tls 两个都设置且设置不当，可能导致生成空白页面，要传入符合条件的端口/tls模式，才能生成节点信息，
        例如：dport=443&tls=false，这种情况错误很明显，非tls加密的不包括[443, 2053, 2083, 2087, 2096, 8443]。
    
    端口的权重：data数据的端口 > url端口(dport) > 配置文件端口；配置文件中，没有设置有端口，就使用443端口。
    
温馨提示：

使用 Cloudflare workers 搭建的 trojan 节点，转换为 clash 使用，PROXYIP 地址可能会丢失（查询不到，也不能使用它作为落脚IP），跟没有设置 PROXYIP 效果一样。
导致一些网站无法打开，比如：ChatGPT、Cloudflare 等，但是生成的v2ray订阅，可以在v2rayN软件中正常使用，PROXYIP 的地址能查询到，而且能够正常使用 ChatGPT 等。"#);

    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(format!(
            "{}{}{}{}{}\n",
            title, web_address, syntax_info, example, param_introduction
        ))
}

async fn read_yaml_file(filename: &str) -> Result<String, std::io::Error> {
    fs::read_to_string(filename)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    const BIND: &str = "127.0.0.1:18085";
    println!("Server is running on http://{}", BIND);
    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(subconverter)
            .default_service(actix_web::web::route().to(default_route))
    })
    .bind(BIND)?
    .run()
    .await
}
