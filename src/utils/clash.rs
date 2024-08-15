use serde_yaml::Value;

// 原来就是clash配置的，直接修改对应的值即可
pub fn build_clash_json(
    yaml_value: &mut Value,
    set_remarks: String,
    set_server: String,
    set_port: u16,
) -> &mut Value {
    if let Some(name) = yaml_value.get_mut(&Value::String("name".to_string())) {
        match name {
            Value::String(ref mut name_str) => {
                *name_str = set_remarks.into();
            }
            _ => {
                println!("name字段不是字符串类型");
            }
        }
    } else {
        println!("name字段不存在");
    }
    if let Some(server) = yaml_value.get_mut(&Value::String("server".to_string())) {
        match server {
            Value::String(ref mut server_str) => {
                *server_str = set_server.into();
            }
            _ => {
                println!("server该字段不是字符串类型");
            }
        }
    } else {
        println!("server字段不存在");
    }
    if let Some(port) = yaml_value.get_mut(&Value::String("port".to_string())) {
        match port {
            Value::Number(ref mut port_num) => {
                *port_num = set_port.into();
            }
            _ => {
                println!("port字段不是数字类型");
            }
        }
    } else {
        println!("port字段不存在");
    }
    yaml_value
}
