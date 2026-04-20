fn main() {
  use std::env;
  use std::path::Path;

  println!("cargo:rerun-if-changed=rscan.ico");

  // build.rs 在宿主机运行，不能用 cfg!(target_os) 判断最终产物平台。
  // 应使用 Cargo 注入的目标平台变量。
  let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
  if target_os != "windows" {
    return;
  }

  let icon_path = ["rscan.ico"]
    .iter()
    .find(|p| Path::new(p).exists())
    .copied();

  if let Some(path) = icon_path {
    let mut res = winres::WindowsResource::new();
    res.set_icon(path);
    if let Err(err) = res.compile() {
      println!("cargo:warning=Windows resource compile failed: {err}");
    }
  } else {
    println!("cargo:warning=No .ico file found (tried rscan.ico)");
  }
}