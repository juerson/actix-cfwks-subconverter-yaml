pub mod build;
pub mod clash;
pub mod config;
pub mod convert;
pub mod file_data;
pub mod net_data;
pub mod qrcode;
pub mod singbox;
pub mod v2ray;
use std::{net::IpAddr, str::FromStr};

pub fn format_ip(ip: &str) -> String {
    match IpAddr::from_str(ip) {
        Ok(IpAddr::V6(_)) => format!("[{}]", ip),
        Ok(IpAddr::V4(_)) => ip.to_string(),
        Err(_) => ip.to_string(),
    }
}
