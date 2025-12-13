use remonse::config;
use remonse::tsa;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Generating Golden TSA Token...");

    // Load config relative to where we run it (project root usually)
    let config_path = Path::new("config.toml");
    if !config_path.exists() {
        eprintln!("Error: config.toml not found in current directory.");
        std::process::exit(1);
    }

    let config_content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config.toml: {}", e))?;
    let config: config::Config = toml::from_str(&config_content)
        .map_err(|e| format!("Failed to parse config.toml: {}", e))?;

    let client = reqwest::Client::new();

    // Innocuous input: "golden-test-input-v1"
    let input_data = b"golden-test-input-v1";
    let hash = Sha256::digest(input_data);
    println!("Input Hash (SHA256): {}", hex::encode(hash));

    println!("Requesting timestamp from: {}", config.tsa_url);
    // request_timestamp expects raw data, it hashes it internally
    let token_bytes = tsa::request_timestamp(&client, &config.tsa_url, input_data).await?;

    let golden_dir = Path::new("golden");
    if !golden_dir.exists() {
        fs::create_dir(golden_dir)?;
    }

    let token_path = golden_dir.join("token.der");
    let mut file = fs::File::create(&token_path)?;
    file.write_all(&token_bytes)?;
    println!("Saved Golden Token to: {:?}", token_path.canonicalize()?);

    let hash_path = golden_dir.join("input_hash.hex");
    let mut hash_file = fs::File::create(&hash_path)?;
    hash_file.write_all(hex::encode(hash).as_bytes())?;
    println!("Saved Input Hash to: {:?}", hash_path.canonicalize()?);

    println!("Verifying generated token (self-test)...");

    // Load trust anchors
    let trusted_roots = tsa::load_trust_anchors(config.tsa_ca_path.as_deref());

    // verify_timestamp expects raw data and checks its hash against msgImprint
    match tsa::verify_timestamp(&token_bytes, input_data, &trusted_roots) {
        Ok(ts) => println!("Verification SUCCESS! Timestamp: {}", ts),
        Err(e) => {
            println!("Verification FAILED: {}", e);
            // We save it anyway, but warn
            eprintln!(
                "WARNING: The generated token FAILED verification. It might be invalid or config is missing CA."
            );
            return Err(Box::new(e) as Box<dyn std::error::Error>);
        }
    }

    println!("Golden Token generation complete.");
    Ok(())
}
