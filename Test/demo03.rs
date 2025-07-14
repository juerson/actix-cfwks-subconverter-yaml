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

fn main() {
    let mut yaml_value = parse_file_to_yamlvlaue("config.yaml");

    if let YamlValue::Sequence(sequence) = &mut yaml_value {
        if sequence.len() > 1 {
            if let YamlValue::Mapping(ref mut map) = sequence[1] {
                println!("{}", serde_yaml::to_string(&map).unwrap());
                map.remove(&YamlValue::String("id".into()));
                println!("{}", serde_yaml::to_string(&map).unwrap());
            }
        }
    }
}
