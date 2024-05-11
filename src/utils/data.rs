use encoding::all::GBK;
use encoding::{DecoderTrap, Encoding};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::io::prelude::*;
use std::io::BufReader;

lazy_static! {
    static ref IPV4_OR_IPV6_REGEX: Regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b").unwrap(); // 匹配ipv4地址或ipv6地址
    static ref IP_WITH_PORT_REGEX: Regex = Regex::new(
        r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3}),(\d{2,5})\b|(([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}),(\d{2,5})\b",
    )
    .unwrap(); // 匹配csv中的IP和端口（比如：192.168.1.1,80）
    static ref DOMAIN_REGEX: Regex = Regex::new(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b").unwrap(); // 粗略匹配一级域名、子域名，不保证后缀的域名真实存在
}

pub fn read_ip_domain_from_files(
    folder_path: &str,
    tls_mode: &str,
) -> io::Result<(Vec<String>, Vec<String>)> {
    // 读取指定文件夹下的所有文件
    let paths = fs::read_dir(folder_path)?;

    // 存储匹配到的 IP 地址和端口的向量
    let mut ip_with_port_vec: Vec<String> = Vec::new();
    // 存放单独的IP或域名
    let mut ips: Vec<String> = Vec::new();

    // 遍历文件夹中的每个文件
    for path in paths {
        let file_path = path?.path();
        let file_extension = file_path.extension().unwrap_or_default();
        // 获取文件名
        let file_name = file_path.file_name().unwrap().to_string_lossy();
        // 排除以 "ips-v" 开头的文件，排除ip.txt的文件
        if file_name.starts_with("ips-v")
            || file_name == "ip.txt"
            || file_name == "ipv6.txt"
            || file_name == "ipv4.txt"
            || file_name == "locations.json"
        {
            continue;
        }
        // 如果文件扩展名是 txt 或 csv，则读取文件内容并匹配IP:PORT
        if let Some(ext) = file_extension.to_str() {
            if ext == "txt" || ext == "csv" {
                if let Ok(bytes) = fs::read(&file_path) {
                    if let Ok(content) = std::str::from_utf8(&bytes) {
                        // 以下代码是处理csv/txt文件的格式是UTF-8编码的情况
                        extract_ip_port_from_file(
                            content,
                            tls_mode,
                            &mut ip_with_port_vec,
                            &mut ips,
                        );
                    } else {
                        // 以下代码是处理csv/txt文件的格式是GBK编码的情况
                        let file = File::open(file_path).expect("File not found");
                        let reader = BufReader::new(file);
                        for line in reader.split(b'\n').map(|l| l.unwrap()) {
                            let decoded_string = GBK.decode(&line, DecoderTrap::Strict).unwrap();
                            extract_ip_port_from_file(
                                &decoded_string,
                                tls_mode,
                                &mut ip_with_port_vec,
                                &mut ips,
                            );
                        }
                    }
                } else {
                    println!("Failed to read file: {:?}", file_path);
                }
            }
        }
    }
    // 去重
    let unique_ips_vec = de_weight(ips);
    let unique_ip_with_port_vec = de_weight(ip_with_port_vec);
    Ok((unique_ips_vec, unique_ip_with_port_vec))
}

// 提取的ip和端口存放到ip_with_port_vec中，只提取到IP/域名的就存放到ips中
fn extract_ip_port_from_file(
    content: &str,
    tls_mode: &str,
    ip_with_port_vec: &mut Vec<String>,
    ips: &mut Vec<String>,
) {
    if content.contains("IP地址,端口,TLS,数据中心,地区,城市,网络延迟")
        || content.contains("IP地址,端口,回源端口,TLS,数据中心,地区,城市,TCP延迟(ms),速度(MB/s)")
    {
        // 处理有端口的csv数据
        if tls_mode == "true" || tls_mode == "1" || tls_mode == "tls" {
            // tls的端口
            for cap in IP_WITH_PORT_REGEX.captures_iter(&content) {
                let cap_ip = cap.get(1).unwrap().as_str().to_string();
                let cap_port = cap.get(2).unwrap().as_str().parse::<u16>().unwrap();
                // 主要排除这些端口，因为CF常用的端口有13个(公开的)，但是还有一些非CF的端口，能通过这些端口使用CF的CDN服务，
                // 如果只使用contains()包含精准的端口匹配，不使用"!"反转条件，会把其它的端口都排除掉，不是我们想要的。
                if ![80, 8080, 8880, 2052, 2082, 2086, 2095].contains(&cap_port) {
                    ip_with_port_vec.push(format!("{},{}", cap_ip, cap_port));
                }
            }
        } else if tls_mode == "false" || tls_mode == "0" {
            // 非tls的端口
            for cap in IP_WITH_PORT_REGEX.captures_iter(&content) {
                let cap_ip = cap.get(1).unwrap().as_str().to_string();
                let cap_port = cap.get(2).unwrap().as_str().parse::<u16>().unwrap();

                if ![443, 2053, 2083, 2087, 2096, 8443].contains(&cap_port) {
                    ip_with_port_vec.push(format!("{},{}", cap_ip, cap_port));
                }
            }
        } else {
            // 全部端口(包括tls和非tls)，没有传入tls、tlsmode参数时，就走这里
            for cap in IP_WITH_PORT_REGEX.captures_iter(&content) {
                let cap_ip = cap.get(1).unwrap().as_str().to_string();
                let cap_port = cap.get(2).unwrap().as_str().parse::<u16>().unwrap();
                ip_with_port_vec.push(format!("{},{}", cap_ip, cap_port));
            }
        }
    } else {
        // 处理没有端口的csv数据，或者txt数据
        // 写入节点中的port，有三种情况：
        // 1、地址栏传入了dport（默认端口），就优选使用它
        // 2、地址栏没有传入dport，就使用配置文件中，读取到的port
        // 3、配置文件中没有port，就使用443端口
        // 权重：url的dport端口 > 配置文件中的端口 > 443端口
        for cap in IPV4_OR_IPV6_REGEX.captures_iter(&content) {
            if let Some(ip_port) = cap.get(0) {
                ips.push(ip_port.as_str().to_string());
            }
        }
        for cap in DOMAIN_REGEX.captures_iter(&content) {
            if let Some(ip_port) = cap.get(0) {
                ips.push(ip_port.as_str().to_string());
            }
        }
    }
}

fn de_weight(vec: Vec<String>) -> Vec<String> {
    // 使用 HashSet 去重
    let mut set: HashSet<String> = HashSet::new();
    let mut unique_vec: Vec<String> = Vec::new();

    for item in vec {
        if set.insert(item.clone()) {
            // 如果成功插入，说明是第一次出现，将其添加到 unique_vec 中
            unique_vec.push(item);
        }
    }
    unique_vec
}
