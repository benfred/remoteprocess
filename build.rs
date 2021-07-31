use std::env;

fn main() {
    // We only support native unwinding on some platforms
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    match target_arch.as_str() {
        "x86_64" | "arm" => {}
        _ => return,
    };
    let target = env::var("TARGET").unwrap();

    match env::var("CARGO_CFG_TARGET_OS").unwrap().as_ref() {
        "linux" => {
            // statically link libunwind if compiling for musl, dynamically link otherwise
            if env::var("CARGO_FEATURE_UNWIND").is_ok() {
                println!("cargo:rustc-cfg=use_libunwind");
                if env::var("CARGO_CFG_TARGET_ENV").unwrap() == "musl"
                    && env::var("CARGO_CFG_TARGET_VENDOR").unwrap() != "alpine"
                {
                    println!("cargo:rustc-link-search=native=/usr/local/lib");
                    println!(
                        "cargo:rustc-link-search=native=/usr/local/musl/{}/lib",
                        target
                    );
                    println!("cargo:rustc-link-lib=static=z");
                    println!("cargo:rustc-link-lib=static=unwind");
                    println!("cargo:rustc-link-lib=static=unwind-ptrace");
                    println!("cargo:rustc-link-lib=static=unwind-{}", target_arch);
                } else {
                    println!("cargo:rustc-link-lib=dylib=unwind");
                    println!("cargo:rustc-link-lib=dylib=unwind-ptrace");
                    println!("cargo:rustc-link-lib=dylib=unwind-{}", target_arch);
                }
            }
        }
        _ => {}
    }
}
