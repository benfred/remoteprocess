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
                    if target_arch == "x86_64" {
                        let out_dir = env::var("OUT_DIR").unwrap();
                        std::fs::copy("/usr/local/musl/x86_64-unknown-linux-musl/lib/libunwind.a", format!("{}/libunwind-remoteprocess.a", out_dir)).unwrap();
                        std::fs::copy("/usr/local/musl/x86_64-unknown-linux-musl/lib/libunwind-ptrace.a", format!("{}/libunwind-ptrace.a", out_dir)).unwrap();
                        std::fs::copy("/usr/local/musl/x86_64-unknown-linux-musl/lib/libunwind-x86_64.a", format!("{}/libunwind-x86_64.a", out_dir)).unwrap();
                        println!("cargo:rustc-link-lib=static=unwind-remoteprocess");
                        println!("cargo:rustc-link-search=native={}", out_dir);
                    } else {
                        println!(
                            "cargo:rustc-link-search=native=/usr/local/musl/{}/lib",
                            target
                        );
                        println!("cargo:rustc-link-lib=static=unwind");
                    }
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
