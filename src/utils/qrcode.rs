use base64::{engine::general_purpose, Engine};
use image::{ImageFormat, Luma};
use qrcode::QrCode;
use std::io::Cursor;

fn generate_qrcode_base64(url: &str) -> String {
    let code = QrCode::new(url).unwrap();
    let image = code.render::<Luma<u8>>().build();
    let mut buffer = Cursor::new(Vec::new());
    image.write_to(&mut buffer, ImageFormat::Png).unwrap();
    general_purpose::STANDARD.encode(buffer.get_ref())
}

/// 生成三个二维码
pub fn generate_html_with_qrcode(content: &str, url: &str) -> String {
    let v2ray_url = format!("{}/sub?target=v2ray", url.trim_end_matches('/'));
    let singbox_url = format!("{}/sub?target=singbox", url.trim_end_matches('/'));
    let clash_url = format!("{}/sub?target=clash", url.trim_end_matches('/'));

    let v2ray_qrcode = generate_qrcode_base64(&v2ray_url);
    let singbox_qrcode = generate_qrcode_base64(&singbox_url);
    let clash_qrcode = generate_qrcode_base64(&clash_url);

    format!(
        r#"
        <pre>{}</pre>
        <p>可以使用手机浏览器，扫描以下二维码查看：</p>
        <div style="display: flex; gap: 20px; flex-wrap: wrap; justify-content: center;">
            <div style="text-align: center;">
                <img src="data:image/png;base64,{}" />
                <p>v2Ray 订阅</p>
            </div>
            <div style="text-align: center;">
                <img src="data:image/png;base64,{}" />
                <p>sing-box 订阅</p>
            </div>
            <div style="text-align: center;">
                <img src="data:image/png;base64,{}" />
                <p>clash/mihomo 订阅</p>
            </div>
        </div>
        "#,
        content, v2ray_qrcode, singbox_qrcode, clash_qrcode
    )
}
