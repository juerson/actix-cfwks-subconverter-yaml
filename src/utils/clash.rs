use serde_yaml::Value as YamlValue;

// 原来就是clash配置的，直接修改对应的值即可
pub fn build_clash_yaml(
    yaml_value: &mut YamlValue,
    remarks: String,
    server_address: String,
    server_port: u16,
) -> &mut YamlValue {
    if let YamlValue::Mapping(map) = yaml_value {
        if let Some(name_value) = map.get_mut("name") {
            *name_value = YamlValue::String(remarks);
        }
        if let Some(server_value) = map.get_mut("server") {
            *server_value = YamlValue::String(server_address);
        }
        if let Some(port_value) = map.get_mut("port") {
            *port_value = YamlValue::Number(server_port.into());
        }
        map.remove(&YamlValue::String("id".into())); // 移除读取配置时私自添加的字段
    }
    yaml_value
}
