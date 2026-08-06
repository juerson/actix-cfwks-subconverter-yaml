use csv::ReaderBuilder;
use std::{
    collections::HashMap,
    error::Error,
    fs::{ self, File },
    io::{ BufRead, BufReader },
    path::Path,
    vec,
};
use regex::Regex;
use lazy_static::lazy_static;

#[derive(Default, Clone)]
pub struct MyData {
    pub addr: String,
    pub port: Option<u16>,
    pub alias: Option<String>,
}

#[derive(Default)]
pub struct FileData {
    pub addr: String, // IP地址或者域名地址
    pub port: Option<u16>,
    pub colo: Option<String>, // 数据中心(3位字母)
    pub loc: Option<String>, // 国家代码/地区代码(2位字母)
    pub region: Option<String>, // 地区
    pub city: Option<String>,
}

lazy_static! {
    // 匹配一个或多个空白字符
    pub static ref SPACE_REGEX: Regex = Regex::new(r"\s+").unwrap();
    // 匹配"IPv4 PORT"（可以1个以上的空格）
    pub static ref IPV4_PORT_SPACE_REGEX: Regex = Regex::new(r"^\s*([0-9.]+)\s+(\d+)\s*$").unwrap();
    // 匹配"IPv6 PORT"（可以1个以上的空格）
    pub static ref IPV6_PORT_SPACE_REGEX: Regex = Regex::new(
        r"^\s*((([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))\s*"
    ).unwrap();
    // 匹配"[IPv6]:PORT"
    pub static ref IPV6_PORT_BRACKET_REGEX: Regex = Regex::new(
        r"^\s*\[([0-9a-fA-F:.]+)\]:(\d+)\s*$"
    ).unwrap();
    // 匹配"IPv6,PORT"（逗号左右可以零个以上的空格）
    pub static ref IPV6_PORT_COMMA_REGEX: Regex = Regex::new(
        r"([0-9a-fA-F:]+:[0-9a-fA-F:]+)\s*,\s*(\d+)"
    ).unwrap();
}

/// csv文件列名的映射关系，特别是奇奇怪怪的列名
pub fn create_field_map() -> HashMap<&'static str, Vec<&'static str>> {
    // 可能的字段映射关系，以列名作为键，其它别名的列名作为值(向量)
    let mut field_map: HashMap<&str, Vec<&str>> = HashMap::new();
    field_map.insert("addr", vec!["IP", "IP地址", "IP 地址", "网络地址"]);
    field_map.insert("port", vec!["PORT", "端口"]);
    field_map.insert("colo", vec!["colo", "iata", "数据中心"]);
    field_map.insert("loc", vec!["cca2", "alpha-2", "Country Code", "CountryCode", "国家代码"]);
    field_map.insert("region", vec!["region", "区域", "地区"]);
    field_map.insert("city", vec!["city", "城市"]);
    field_map
}

fn process_csv(filename: &str, default_port: u16) -> Result<Vec<FileData>, Box<dyn Error>> {
    let file = File::open(filename)?;
    let mut rdr = ReaderBuilder::new().from_reader(file);

    // 读取文件头
    let headers = rdr.headers()?;

    // csv文件列名的映射关系，特别是奇奇怪怪的列名
    let field_map = create_field_map();

    // 尝试从标题中查找列索引(下标)
    let find_index = |key: &str| {
        field_map.get(key).and_then(|candidates|
            candidates.iter().find_map(|&field|
                headers.iter().position(
                    |header| header.trim().to_lowercase() == field.trim().to_lowercase() // 忽略字段中的大小写
                )
            )
        )
    };
    // 找csv标题的列名跟向量中哪个元素对应 => 在哪个索引(下标)中
    let addr_index = find_index("addr");
    let port_index = find_index("port");
    let colo_index = find_index("colo");
    let loc_index = find_index("loc");
    let region_index = find_index("region");
    let city_index = find_index("city");

    let mut result: Vec<FileData> = Vec::new();

    for record in rdr.records() {
        let record = record?;

        // 获取`IP地址`字段的值
        let addr_column = addr_index.and_then(|index| record.get(index)).unwrap_or("");

        if addr_column.is_empty() {
            continue;
        }

        // 获取`端口`字段的值
        let port_column: u16 = port_index
            .and_then(|index| record.get(index).and_then(|val| val.parse::<u16>().ok())) // 显示转换
            .unwrap_or(default_port); // 默认为`default_port`

        // 定义一个闭包来处理列的提取逻辑(只支持String数据类型的数据提取)
        let get_column_string = |index: Option<usize>| {
            index
                .and_then(|idx| record.get(idx).and_then(|val| val.parse().ok())) // 隐式转换
                .unwrap_or_else(|| "".to_string()) // 默认为空字符串
        };

        // 使用闭包提取列数据，没有找到对应的列时，返回空字符串
        let colo_column = get_column_string(colo_index);
        let loc_column = get_column_string(loc_index);
        let region_column = get_column_string(region_index);
        let city_column = get_column_string(city_index);

        let data = FileData {
            addr: addr_column.to_string(),
            port: Some(port_column),
            colo: Some(colo_column),
            loc: Some(loc_column),
            region: Some(region_column),
            city: Some(city_column),
        };
        result.push(data);
    }

    Ok(result)
}

fn process_txt(filename: &str, default_port: u16) -> Result<Vec<FileData>, Box<dyn Error>> {
    // 排除不需要的txt文件，注意：如果传入完整的路径，该功能不起作用
    if filename.starts_with("ips-v") || filename.starts_with("ipv") {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Skipping this file")));
    }
    let file = File::open(filename)?;
    let reader = BufReader::new(file);

    let mut seen_lines: Vec<String> = Vec::new();
    let mut result: Vec<FileData> = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed_line = line.trim().to_string();

        let contains_bool = trimmed_line.contains("/") || seen_lines.contains(&trimmed_line);
        if trimmed_line.is_empty() || contains_bool {
            continue;
        }

        // 提取地址和端口
        let parts: Vec<String> = if
            let Some(captures) = IPV6_PORT_COMMA_REGEX.captures(&trimmed_line)
        {
            // 判断是否为 "IPv6, PORT" 格式(逗号左右，可以0个以上的空格)
            let ipv6 = captures.get(1).map_or("", |m| m.as_str());
            let port = captures.get(2).map_or("", |m| m.as_str());
            vec![format!("[{}]", ipv6), port.to_string()]
        } else if IPV6_PORT_SPACE_REGEX.is_match(&trimmed_line) {
            // 判断是否为 "IPv6 PORT" 地址
            SPACE_REGEX.splitn(&trimmed_line, 2)
                .map(|s| {
                    let str_s = s.to_string();
                    let colon_count = str_s
                        .chars()
                        .filter(|&c| c == ':')
                        .count();
                    if colon_count > 1 {
                        if str_s.starts_with('[') && str_s.ends_with(']') {
                            str_s // 已经有方括号，直接返回
                        } else {
                            format!("[{}]", str_s) // 添加方括号
                        }
                    } else {
                        str_s // 不满足条件，直接返回
                    }
                })
                .collect()
        } else if let Some(captures) = IPV6_PORT_BRACKET_REGEX.captures(&trimmed_line) {
            // 判断是否为 "[IPv6]:PORT" 格式
            vec![
                format!("[{}]", captures.get(1).unwrap().as_str().to_string()),
                captures.get(2).unwrap().as_str().to_string()
            ]
        } else if let Some(captures) = IPV4_PORT_SPACE_REGEX.captures(&trimmed_line) {
            // 判断是否为 "IPv4 PORT" 格式
            vec![
                captures.get(1).unwrap().as_str().to_string(),
                captures.get(2).unwrap().as_str().to_string()
            ]
        } else if
            trimmed_line.contains(':') &&
            trimmed_line
                .chars()
                .filter(|&c| c == ':')
                .count() == 1
        {
            // 判断是否为 "IPv4:PORT" 或 "Domain:PORT" 格式
            trimmed_line
                .splitn(2, ':')
                .map(|s| s.to_string())
                .collect()
        } else if trimmed_line.contains(", ") {
            // 判断是否为 "IPv4, PORT" 、"[IPv6], PORT"、" "Domain, PORT" 格式
            trimmed_line
                .splitn(2, ", ")
                .map(|s| s.to_string())
                .collect()
        } else if trimmed_line.contains(',') {
            // 判断是否为 "IPv4,PORT" 、"[IPv6],PORT"、" "Domain,PORT" 格式
            trimmed_line
                .splitn(2, ',')
                .map(|s| s.to_string())
                .collect()
        } else if SPACE_REGEX.is_match(&trimmed_line) {
            // 判断是否为 "[IPv6] PORT" 或 "Domain PORT" 格式
            let value = SPACE_REGEX.splitn(&trimmed_line, 2)
                .map(|s| s.to_string())
                .collect();
            value
        } else {
            // 匹配 "IPv4"、"[ipv6]"、"Domain" 格式
            vec![trimmed_line.to_string(), default_port.to_string()]
        };

        if parts.len() == 2 {
            let final_line = format!("{}:{}", parts[0], parts[1]);
            if !seen_lines.contains(&final_line) && !parts[0].is_empty() {
                let data = FileData {
                    addr: parts[0].clone(),
                    port: parts[1].parse::<u16>().ok(),
                    ..Default::default() // 其它字段不管，使用默认值
                };
                seen_lines.push(final_line);
                result.push(data);
            }
        } else {
            println!("不支持提取 `{}` 的地址和端口！", trimmed_line);
        }
    }

    Ok(result)
}

fn process_file(filename: &str, default_port: u16) -> Result<Vec<FileData>, Box<dyn Error>> {
    let path = Path::new(filename);
    let extension = path.extension().and_then(|s| s.to_str());

    match extension {
        Some("csv") => process_csv(filename, default_port),
        Some("txt") => process_txt(filename, default_port),
        _ => Err("不支持的文件类型".into()),
    }
}

pub fn process_files_data(
    field_column: &str,
    default_port: u16,
    count: usize,
    target_path: &str
) -> Vec<MyData> {
    let mut results: Vec<MyData> = Vec::new(); // 存储结果
    let mut seen_addr: Vec<String> = Vec::new(); // 数据去重

    let path = Path::new(target_path);
    if path.is_file() && path.extension().map_or(false, |ext| ext == "txt" || ext == "csv") {
        // 如果路径是 TXT 或 CSV 文件，直接处理该文件
        match process_file(target_path, default_port) {
            Ok(data) => {
                for item in &data {
                    let addr: String = item.addr.clone();
                    let port: u16 = item.port.unwrap_or(default_port);
                    let addr_port = format!("{}:{}", addr, port);

                    // 数据去重，确保获取到数据没有重复的
                    if seen_addr.contains(&addr_port) {
                        continue;
                    } else {
                        seen_addr.push(addr_port.clone());
                    }

                    // 获取某个字段值作为节点的别名前缀使用，注意，找不到对应的字段，则默认为空值，后面需要做处理
                    let alias_prefix = match field_column {
                        "colo" => item.colo.clone(),
                        "loc" => item.loc.clone(),
                        "region" => item.region.clone(),
                        "city" => item.city.clone(),
                        _ => Some("".to_string()),
                    };

                    // （选择性）将需要的字段值，以MyData结构体形式存储
                    let data = MyData {
                        addr: addr.clone(),
                        port: Some(port),
                        alias: alias_prefix,
                    };

                    // 如果结果数量小于指定的数量，则添加数据，否则就返回，避免无意义的IO操作(读取数据)
                    if results.len() < count {
                        results.push(data.clone());
                    } else {
                        return results; // 直接返回结果，因为是处理单个文件
                    }
                }
            }
            Err(e) => eprintln!("处理文件 `{}` 出错: {}", target_path, e),
        }
    } else if path.is_dir() {
        // 如果路径是文件夹，执行原来的逻辑
        let msg = format!("文件夹 {} 不存在！", target_path);
        let entries = fs::read_dir(target_path).expect(&msg);
        'outer: for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();

            let is_txt_or_csv = path
                .extension()
                .map_or(false, |ext| ext == "txt" || ext == "csv");

            // 只处理txt和csv文件，process_file函数中，含有排除的txt文件
            if path.is_file() && is_txt_or_csv {
                let file_name = path.file_name().unwrap().to_string_lossy();
                let filename: String = format!("{}/{}", target_path, file_name);
                match process_file(&filename, default_port) {
                    Ok(data) => {
                        for item in &data {
                            let addr: String = item.addr.clone();
                            let port: u16 = item.port.unwrap_or(default_port);
                            let addr_port = format!("{}:{}", addr, port);

                            // 确保数据的唯一性（如果读取多文件，可能不同的文件，拥有相同的数据）
                            if seen_addr.contains(&addr_port) {
                                continue;
                            } else {
                                seen_addr.push(addr_port.clone());
                            }

                            // 获取某个字段值作为节点的别名前缀使用，注意，找不到对应的字段，则默认为空值，后面需要做处理
                            let alias_prefix = match field_column {
                                "colo" => item.colo.clone(), // 数据中心(3个字母)
                                "loc" => item.loc.clone(), // 国家代码(2个字母)
                                "region" => item.region.clone(), // 地区
                                "city" => item.city.clone(), // 城市
                                _ => Some("".to_string()),
                            };

                            // （选择性）将需要的字段值，以MyData结构体形式存储
                            let data = MyData {
                                addr: addr.clone(),
                                port: Some(port),
                                alias: alias_prefix,
                            };

                            // 获取足够的数据，就停止for循环
                            if results.len() < count {
                                results.push(data.clone());
                            } else {
                                break 'outer;
                            }
                        }
                    }
                    Err(e) => eprintln!("处理文件 `{}` 出错: {}", filename, e),
                }
            }
        }
    } else {
        eprintln!("路径 {} 不是有效的文件或文件夹。", target_path);
    }

    results
}
