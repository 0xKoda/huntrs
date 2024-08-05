use crate::{Args, Cache};
use futures::future::join_all;
use ipnetwork::Ipv4Network;
use rand::Rng;
use reqwest::header::{HeaderMap, USER_AGENT};
use reqwest::Client;
use scraper::{Html, Selector};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

use crate::pdns::{fetch_passive_dns, process_pdns_data};

const HTTP_TIMEOUT_SECONDS: u64 = 3;
const RESPONSE_SIMILARITY_THRESHOLD: f32 = 0.9;

pub async fn fetch_subdomains_from_crtsh(
    client: &Client,
    domain: &str,
) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let response = client.get(&url).send().await?;
    let certs: Vec<Value> = response.json().await?;
    let mut subdomains = Vec::new();
    for cert in certs {
        if let Some(name_value) = cert["name_value"].as_str() {
            subdomains.extend(name_value.split('\n').map(String::from));
        }
    }

    Ok(subdomains)
}

pub async fn get_cloudflare_ip_ranges() -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let client = Client::new();
    let url = "https://www.cloudflare.com/ips-v4";
    let response = client.get(url).send().await?;
    let ip_ranges: Vec<String> = response.text().await?.lines().map(String::from).collect();
    Ok(ip_ranges)
}

pub fn is_ip_in_ranges(ip: &Ipv4Addr, ranges: &[String]) -> bool {
    ranges.iter().any(|range| {
        Ipv4Network::from_str(range)
            .map(|network| network.contains(*ip))
            .unwrap_or(false)
    })
}

pub async fn resolve_domain(domain: &str) -> Result<Vec<Ipv4Addr>, Box<dyn Error + Send + Sync>> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let response = resolver.lookup_ip(domain).await?;
    Ok(response
        .iter()
        .filter_map(|ip| ip.to_string().parse::<Ipv4Addr>().ok())
        .collect())
}

pub fn get_user_agent() -> String {
    let user_agents = vec![
        "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
    ];
    user_agents[rand::thread_rng().gen_range(0..user_agents.len())].to_string()
}

pub fn html_similarity(a: &str, b: &str) -> f32 {
    let doc_a = Html::parse_document(a);
    let doc_b = Html::parse_document(b);

    let selector = Selector::parse("*").unwrap();
    let elements_a: Vec<_> = doc_a.select(&selector).collect();
    let elements_b: Vec<_> = doc_b.select(&selector).collect();

    let mut matching = 0;
    let total = elements_a.len().max(elements_b.len());

    for (el_a, el_b) in elements_a.iter().zip(elements_b.iter()) {
        if el_a.value().name() == el_b.value().name() {
            matching += 1;
        }
    }

    matching as f32 / total as f32
}

pub fn print_origins(origins: &[(Ipv4Addr, String)]) {
    for (ip, reason) in origins {
        println!("  - {} ({})", ip, reason);
    }
    println!();
}

pub fn save_origins_to_file(
    origins: &[(Ipv4Addr, String)],
    output_file: Option<&str>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(file_path) = output_file {
        let mut file = File::create(file_path)?;
        for (ip, _) in origins {
            writeln!(file, "{}", ip)?;
        }
        println!(
            "[*] Wrote {} likely origins to output file {}",
            origins.len(),
            file_path
        );
    }
    Ok(())
}

pub async fn is_using_cloudflare(domain: &str) -> bool {
    let client = Client::new();
    let url = format!("https://{}", domain);
    let response = client.head(&url).send().await;
    match response {
        Ok(resp) => {
            let headers = resp.headers();
            headers
                .get("Server")
                .map_or(false, |h| h.to_str().unwrap_or("").contains("cloudflare"))
        }
        Err(_) => false,
    }
}

pub fn prompt_continue() -> Result<bool, Box<dyn Error + Send + Sync>> {
    let mut input = String::new();
    println!("Continue with checks? (yes/no): ");
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("yes"))
}

pub fn prompt_subdomain_selection() -> Result<String, Box<dyn Error + Send + Sync>> {
    let mut input = String::new();
    println!("More than 5 subdomains found. Search: (all/main/top5): ");
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub async fn get_domain_historical_ip_address(
    domain: &str,
) -> Result<Vec<Ipv4Addr>, Box<dyn Error + Send + Sync>> {
    let url = format!("https://viewdns.info/iphistory/?domain={}", domain);
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36".parse()?);

    println!("[*] Checking ViewDNS for historical IP addresses...");
    let response = client.get(&url).headers(headers).send().await?;

    if !response.status().is_success() {
        println!(
            "[DEBUG] ViewDNS request failed with status: {}",
            response.status()
        );
        return Ok(vec![]);
    }

    let html = response.text().await?;
    println!(
        "[DEBUG] ViewDNS raw HTML response length: {} characters",
        html.len()
    );

    let document = Html::parse_document(&html);
    let table_selector = Selector::parse("table[border='1']").unwrap();
    let row_selector = Selector::parse("tr").unwrap();
    let cell_selector = Selector::parse("td").unwrap();

    let mut historical_ips = Vec::new();

    if let Some(table) = document.select(&table_selector).next() {
        for row in table.select(&row_selector).skip(1) {
            // Skip header row
            let cells: Vec<_> = row.select(&cell_selector).collect();
            if cells.len() >= 4 {
                if let Ok(ip) = cells[0].text().next().unwrap_or("").parse::<Ipv4Addr>() {
                    historical_ips.push(ip);
                    println!("[*] Found historical IP: {}", ip);
                    println!(
                        "    Location: {}",
                        cells[1].text().next().unwrap_or("Unknown")
                    );
                    println!("    Owner: {}", cells[2].text().next().unwrap_or("Unknown"));
                    println!(
                        "    Last seen: {}",
                        cells[3].text().next().unwrap_or("Unknown")
                    );
                }
            }
        }
    } else {
        println!("[DEBUG] No table with border='1' found in the HTML");
    }

    println!(
        "[DEBUG] Total historical IPs found: {}",
        historical_ips.len()
    );
    Ok(historical_ips)
}

pub async fn get_asn_info(ip: &Ipv4Addr) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
    let client = Client::new();
    let url = format!("https://ipinfo.io/{}/org", ip);

    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36".parse()?);

    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .await?
        .text()
        .await?;

    let parts: Vec<&str> = response.trim().splitn(2, ' ').collect();
    let asn = parts
        .get(0)
        .map(|&s| s.to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let org_name = parts
        .get(1)
        .map(|&s| s.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    Ok((asn, org_name))
}

pub fn save_results_to_file(
    results: &HashSet<Ipv4Addr>,
    filename: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut file = File::create(filename)?;
    for ip in results {
        writeln!(file, "{}", ip)?;
    }
    println!(
        "[*] Wrote {} non-Cloudflare IPs to output file {}",
        results.len(),
        filename
    );
    Ok(())
}

pub async fn retrieve_original_page(
    domain: &str,
) -> Result<reqwest::Response, Box<dyn Error + Send + Sync>> {
    let url = format!("https://{}", domain);
    println!("[*] Retrieving target homepage at {}", url);

    let client = Client::new();
    let response = client
        .get(&url)
        .header("User-Agent", get_user_agent())
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .header("Accept-Language", "en-US,en;q=0.5")
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECONDS))
        .send()
        .await?;

    if response.status() != 200 {
        println!(
            "[-] {} responded with an unexpected HTTP status code {}",
            url,
            response.status()
        );
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unexpected status code",
        )));
    }

    if response.url().as_str() != url {
        println!("[*] \"{}\" redirected to \"{}\"", url, response.url());
    }

    Ok(response)
}

pub async fn process_subdomains(
    selected_subdomains: &[String],
    cloudflare_ranges: &[String],
    args: &Args,
    client: &Client,
    cache: Arc<Mutex<Cache>>,
) -> HashSet<Ipv4Addr> {
    let tasks: Vec<_> = selected_subdomains
        .iter()
        .map(|subdomain| {
            let subdomain = subdomain.clone();
            let cloudflare_ranges = cloudflare_ranges.to_vec();
            let args = args.clone();
            let client = client.clone();
            let cache = cache.clone();
            tokio::spawn(async move {
                process_single_subdomain(&subdomain, &cloudflare_ranges, &args, &client, cache)
                    .await
            })
        })
        .collect();

    let results = join_all(tasks).await;
    results
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(Result::ok)
        .fold(HashSet::new(), |mut acc, set| {
            acc.extend(set);
            acc
        })
}

pub async fn process_single_subdomain(
    subdomain: &str,
    cloudflare_ranges: &[String],
    args: &Args,
    client: &Client,
    cache: Arc<Mutex<Cache>>,
) -> Result<HashSet<Ipv4Addr>, Box<dyn Error + Send + Sync>> {
    let mut non_cloudflare_hosts = HashSet::new();
    if args.viewdns {
        match get_domain_historical_ip_address(subdomain).await {
            Ok(ips) => {
                for ip in ips {
                    if !is_ip_in_ranges(&ip, cloudflare_ranges) {
                        non_cloudflare_hosts.insert(ip);
                    }
                }
            }
            Err(e) => println!("Error fetching historical IPs: {}", e),
        }
    } else if args.both {
        match get_domain_historical_ip_address(subdomain).await {
            Ok(historical_ips) => {
                for ip in historical_ips {
                    if !is_ip_in_ranges(&ip, cloudflare_ranges) {
                        non_cloudflare_hosts.insert(ip);
                    }
                }
            }
            Err(e) => println!("Error fetching historical IPs: {}", e),
        }
        if let Ok(pdns_data) = fetch_passive_dns(client, subdomain, cache).await {
            process_pdns_data(pdns_data, cloudflare_ranges, &mut non_cloudflare_hosts);
        }
    } else {
        if let Ok(pdns_data) = fetch_passive_dns(client, subdomain, cache).await {
            process_pdns_data(pdns_data, cloudflare_ranges, &mut non_cloudflare_hosts);
        }
    }
    Ok(non_cloudflare_hosts)
}

pub async fn find_origins(
    domain: String,
    candidates: &HashSet<Ipv4Addr>,
) -> Result<Vec<(Ipv4Addr, String)>, Box<dyn Error + Send + Sync>> {
    println!("\n[*] Testing candidate origin servers");
    let original_response = match retrieve_original_page(&domain).await {
        Ok(response) => response,
        Err(_) => {
            println!("[-] Failed to retrieve original page for {}", domain);
            return Ok(vec![]);
        }
    };
    let host_header_value = original_response
        .url()
        .host_str()
        .unwrap_or(&domain)
        .to_string();
    let original_text = original_response.text().await?;

    let tasks: Vec<_> = candidates
        .iter()
        .map(|&host| {
            let host_header_value = host_header_value.clone();
            let original_text = original_text.clone();
            let domain = domain.clone();
            tokio::spawn(async move {
                check_origin(host, &domain, &host_header_value, &original_text).await
            })
        })
        .collect();

    let results = join_all(tasks).await;
    let origins: Vec<(Ipv4Addr, String)> = results
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(|r| r.ok())
        .flatten()
        .collect();

    Ok(origins)
}

pub async fn check_origin(
    host: Ipv4Addr,
    domain: &str,
    host_header_value: &str,
    original_text: &str,
) -> Result<Option<(Ipv4Addr, String)>, Box<dyn Error + Send + Sync>> {
    println!("  - {}", host);
    let url = format!("https://{}", host);
    let client = Client::new();
    let response = client
        .get(&url)
        .header("Host", host_header_value)
        .header("User-Agent", get_user_agent())
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECONDS))
        .send()
        .await;

    match response {
        Ok(resp) => {
            if resp.status() != 200 {
                println!(
                    "      responded with an unexpected HTTP status code {}",
                    resp.status()
                );
                return Ok(None);
            }

            let response_text = resp.text().await?;
            if response_text == *original_text {
                Ok(Some((
                    host,
                    format!("HTML content identical to {}", domain),
                )))
            } else if !response_text.is_empty() {
                let similarity = html_similarity(&response_text, original_text);
                if similarity > RESPONSE_SIMILARITY_THRESHOLD {
                    Ok(Some((
                        host,
                        format!(
                            "HTML content is {:.2}% structurally similar to {}",
                            similarity * 100.0,
                            domain
                        ),
                    )))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            if e.is_timeout() {
                println!("      timed out after {} seconds", HTTP_TIMEOUT_SECONDS);
            } else {
                println!("      unable to retrieve");
            }
            Ok(None)
        }
    }
}

pub async fn print_finished_message(
    domain: &str,
    non_cloudflare_hosts: &HashSet<Ipv4Addr>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("\n\x1b[33mDomain Target\x1b[0m: \x1b[32m{}\x1b[0m", domain);
    println!("-----------------------------------");
    println!("\x1b[33mNon-Cloudflare IPs:\x1b[0m");

    let tasks: Vec<_> = non_cloudflare_hosts
        .iter()
        .map(|&ip| tokio::spawn(async move { get_asn_info(&ip).await }))
        .collect();

    let results = join_all(tasks).await;

    for (result, &ip) in results.into_iter().zip(non_cloudflare_hosts.iter()) {
        match result {
            Ok(Ok((asn, org_name))) => {
                println!("\x1b[32m{}\x1b[0m", ip);
                println!(
                    "\x1b[33mOrganisation\x1b[0m: \x1b[32m{} - {}\x1b[0m",
                    asn, org_name
                );
                println!();
            }
            _ => {
                println!("\x1b[32m{}\x1b[0m", ip);
                println!("\x1b[33mOrganisation\x1b[0m: \x1b[32mUnknown\x1b[0m");
                println!();
            }
        }
    }

    Ok(())
}

pub async fn perform_reverse_ip_lookup(ip: &str) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let url = format!("https://viewdns.info/reverseip/?host={}&t=1", ip);
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36".parse()?);

    println!("[*] Checking ViewDNS for reverse IP lookup...");
    let response = client.get(&url).headers(headers).send().await?;

    if !response.status().is_success() {
        println!(
            "[DEBUG] ViewDNS request failed with status: {}",
            response.status()
        );
        return Ok(vec![]);
    }

    let html = response.text().await?;
    let document = Html::parse_document(&html);
    let table_selector = Selector::parse("table#null").unwrap();
    let row_selector = Selector::parse("tr").unwrap();
    let cell_selector = Selector::parse("td").unwrap();

    let mut domains = Vec::new();

    if let Some(table) = document.select(&table_selector).next() {
        for row in table.select(&row_selector).skip(2) { 
            let cells: Vec<_> = row.select(&cell_selector).collect();
            if cells.len() >= 1 {
                if let Some(domain) = cells[0].text().next() {
                    let domain = domain.trim();
                    if !domain.is_empty() {
                        domains.push(domain.to_string());
                    }
                }
            }
        }
    } else {
        println!("[DEBUG] No table with id 'null' found in the HTML");
    }

    println!(
        "[DEBUG] Total domains found: {}",
        domains.len()
    );
    Ok(domains)
}
