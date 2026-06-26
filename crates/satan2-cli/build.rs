// Inject build-time nonce for polymorphic builds.
// SATAN2_BUILD_NONCE env var (set by `make poly`) forces rustc to recompile
// with a unique constant, producing a distinct binary hash per variant.
fn main() {
    let nonce = std::env::var("SATAN2_BUILD_NONCE").unwrap_or_else(|_| "0000000000000000".into());
    println!("cargo:rustc-env=SATAN2_BUILD_NONCE={}", nonce);
    // Rebuild whenever the nonce changes
    println!("cargo:rerun-if-env-changed=SATAN2_BUILD_NONCE");
}
