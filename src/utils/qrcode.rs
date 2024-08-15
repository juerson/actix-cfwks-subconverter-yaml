use base64::encode;
use image::{ImageFormat, Luma};
use qrcode::QrCode;
use std::io::Cursor;
/// 生成包含二维码和内容的 HTML 页面
pub fn generate_html_with_qrcode(content: &str, url: &str) -> String {
    // 生成二维码
    let code = QrCode::new(url).unwrap();

    // 渲染二维码为图像并转换为Base64字符串
    let image = code.render::<Luma<u8>>().build();
    let mut buffer = Cursor::new(Vec::new());
    image.write_to(&mut buffer, ImageFormat::Png).unwrap();
    let base64_qrcode = encode(buffer.get_ref());

    // 构建HTML内容
    format!(
        r#"
        <pre>{}</pre>
        <hr>
        <p>扫描以下二维码以便在手机上查看：</p>
        <img src="data:image/png;base64,{}" />
        "#,
        content, base64_qrcode
    )
}
