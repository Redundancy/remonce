#[cfg(test)]
mod tests {
    use crate::tsa;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_verify_golden_token_with_digicert() {
        let _ = tracing_subscriber::fmt::try_init();
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let golden_dir = manifest_dir.join("golden");

        // 1. Load Token
        let token_path = golden_dir.join("token.der");
        if !token_path.exists() {
            println!(
                "Skipping golden test: golden/token.der not found. Run 'cargo run --bin generate-golden' first."
            );
            return;
        }
        let token_bytes = std::fs::read(&token_path).expect("Failed to read golden/token.der");

        // 2. Load CA (Intermediate)
        // We try both 2025 and 2021 filenames if they exist, or just use what we have.
        // For this test, we assume 'intermediate_2025.crt' is the one we downloaded.
        // Or 'digicert_g4.crt' if we rename it.
        // Let's look for any .crt in golden dir that looks like a CA.

        let mut trusted_roots = Vec::new();

        // Load Root G4
        let root_path = golden_dir.join("DigiCertTrustedRootG4.crt");
        if root_path.exists() {
            let root_der = std::fs::read(&root_path).expect("Failed to read Root CA");
            trusted_roots.push(root_der);
        }

        // Load Intermediate 2025
        let int_path = golden_dir.join("intermediate_2025.crt");
        if int_path.exists() {
            let int_der = std::fs::read(&int_path).expect("Failed to read Intermediate CA");
            trusted_roots.push(int_der);
        } else {
            println!(
                "WARNING: Intermediate CA not found. Verification might fail if Root is not enough."
            );
        }

        // 3. Define Input (Must match what generate-golden used)
        let input_data = b"golden-test-input-v1";

        // 4. Verify
        let result = tsa::verify_timestamp(&token_bytes, input_data, &trusted_roots);

        match result {
            Ok(ts) => println!("Golden Test: Verification SUCCESS! Timestamp: {}", ts),
            Err(e) => panic!("Golden verifiable failed: {}", e),
        }
    }
}
