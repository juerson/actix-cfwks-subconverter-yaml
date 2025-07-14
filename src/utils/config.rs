use serde_yaml::{Mapping, Value as YamlValue};
use std::{
    fs::File,
    io::{BufReader, Read},
};

// 为序列中的每个 Mapping 元素添加 id 字段
fn inject_id_field(array: &[YamlValue]) -> Vec<YamlValue> {
    let len = array.len();
    let width = (len.max(1).to_string().len()) as usize;

    array
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let mut map = if let YamlValue::Mapping(m) = item {
                m.clone()
            } else {
                Mapping::new()
            };
            let id_str = format!("{:0width$}", i + 1);
            map.insert(YamlValue::String("id".into()), YamlValue::String(id_str));

            YamlValue::Mapping(map)
        })
        .collect()
}

// 解析 YAML 文件并为顶层序列或 proxies 字段的序列添加 id，返回 Sequence
pub fn parse_file_to_yamlvlaue(file_path: &str) -> YamlValue {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return YamlValue::Null,
    };

    let mut yaml_content = String::new();
    if BufReader::new(file)
        .read_to_string(&mut yaml_content)
        .is_err()
    {
        return YamlValue::Null;
    }

    let yaml_value: YamlValue = match serde_yaml::from_str(&yaml_content) {
        Ok(value) => value,
        Err(_) => return YamlValue::Null,
    };

    match yaml_value {
        YamlValue::Sequence(seq) => YamlValue::Sequence(inject_id_field(&seq)),
        YamlValue::Mapping(map) => {
            if let Some(proxies) = map.get(&YamlValue::String("proxies".into())) {
                if let YamlValue::Sequence(seq) = proxies {
                    return YamlValue::Sequence(inject_id_field(seq));
                }
            }
            YamlValue::Null
        }
        _ => YamlValue::Null,
    }
}

// 支持按路径(".")的形式获取Yaml的值
pub fn get_yaml_value<'a>(yaml: &'a YamlValue, path: &str) -> Option<&'a YamlValue> {
    // 按 "." 分割路径，生成键数组
    let keys: Vec<&str> = path.split('.').collect();

    let mut current = yaml;
    for key in keys {
        // 查找忽略大小写的键
        current = current
            .as_mapping()?
            .iter()
            .find(|(k, _)| {
                k.as_str()
                    .map_or(false, |k_str| k_str.to_lowercase() == key.to_lowercase())
            })
            .map(|(_, v)| v)?;
    }
    Some(current)
}

// 多个keys备选查找函数
pub fn get_yaml_value_with_fallback<'a>(yaml: &'a YamlValue, paths: &[&str]) -> Option<&'a str> {
    paths
        .iter()
        .filter_map(|&path| get_yaml_value(yaml, path).and_then(|v| v.as_str()))
        .next()
}
