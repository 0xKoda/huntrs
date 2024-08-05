use crate::Cache;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

const MNEMONIC_API_BASE_URL: &str = "https://api.mnemonic.no/pdns/v3/";

pub async fn fetch_passive_dns(
    client: &Client,
    query: &str,
    cache: Arc<Mutex<Cache>>,
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    {
        let cache_lock = cache.lock().await;
        if let Some(cached_data) = cache_lock.pdns_cache.get(query) {
            return Ok(cached_data.clone());
        }
    }

    let url = format!("{}{}", MNEMONIC_API_BASE_URL, query);
    let response = client.get(&url).send().await?;
    let json: Value = response.json().await?;

    if let Some(data) = json.get("data") {
        let mut cache_lock = cache.lock().await;
        cache_lock
            .pdns_cache
            .insert(query.to_string(), data.clone());
        Ok(data.clone())
    } else {
        println!("[-] No 'data' field found in PDNS response for {}", query);
        Ok(Value::Array(vec![]))
    }
}

pub fn process_pdns_data(
    pdns_data: Value,
    cloudflare_ranges: &[String],
    non_cloudflare_hosts: &mut HashSet<Ipv4Addr>,
) {
    if let Some(data_array) = pdns_data.as_array() {
        for record in data_array {
            if let (Some("a"), Some(answer)) =
                (record["rrtype"].as_str(), record["answer"].as_str())
            {
                if let Ok(ip) = answer.parse::<Ipv4Addr>() {
                    if !crate::utils::is_ip_in_ranges(&ip, cloudflare_ranges) {
                        non_cloudflare_hosts.insert(ip);
                    }
                }
            }
        }
    }
}
