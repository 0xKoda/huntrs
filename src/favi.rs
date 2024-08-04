use reqwest::Client;
use serde_json::Value;
use std::error::Error;
use base64::{engine::general_purpose, Engine as _};
use murmurhash3::murmurhash3_x86_32;

pub async fn calculate_favicon_hash(domain: &str) -> Result<i32, Box<dyn Error + Send + Sync>> {
    let favicon_url = format!("https://{}/favicon.ico", domain);
    let client = Client::new();
    let response = client.get(&favicon_url).send().await?;
    
    if response.status().is_success() {
        let favicon_content = response.bytes().await?;
        
        let favicon_base64 = general_purpose::STANDARD_NO_PAD.encode(favicon_content)
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i > 0 && i % 76 == 0 {
                    Some('\n')
                } else {
                    None
                }.into_iter().chain(std::iter::once(c))
            })
            .collect::<String>() + "\n";  
        
        let hash = murmurhash3_x86_32(favicon_base64.as_bytes(), 0);
        
        Ok(hash as i32)
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to retrieve favicon: HTTP {}", response.status()),
        )))
    }
}

pub async fn search_shodan_for_favicon(
    hash: i32,
    api_key: &str,
) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let client = Client::new();
    let url = format!(
        "https://api.shodan.io/shodan/host/search?key={}&query=http.favicon.hash:{}",
        api_key, hash
    );

    println!("[*] Sending request to Shodan API: {}", url);

    let response = client.get(&url).send().await?;

    println!(
        "[*] Received response from Shodan API. Status: {}",
        response.status()
    );

    let response_text = response.text().await?;

    let json: Value = serde_json::from_str(&response_text)?;

    println!("[*] Parsed JSON response");

    let mut results = Vec::new();
    if let Some(matches) = json["matches"].as_array() {
        println!("[*] Found {} matches", matches.len());
        for (index, match_item) in matches.iter().enumerate() {
            if let Some(ip) = match_item["ip_str"].as_str() {
                println!("[*] Match {}: IP = {}", index + 1, ip);
                results.push(ip.to_string());
            } else {
                println!("[*] Match {} does not have an 'ip_str' field", index + 1);
            }
        }
    } else {
        println!("[-] No 'matches' array found in the response");
    }

    println!("[*] Total results found: {}", results.len());

    Ok(results)
}