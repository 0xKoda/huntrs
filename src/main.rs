use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

mod favi;
mod pdns;
mod utils;

use crate::favi::{calculate_favicon_hash, search_shodan_for_favicon};
use crate::pdns::{fetch_passive_dns, process_pdns_data};
use crate::utils::{
    fetch_subdomains_from_crtsh, find_origins, get_cloudflare_ip_ranges, is_ip_in_ranges,
    is_using_cloudflare, print_finished_message, print_origins, process_subdomains,
    prompt_continue, prompt_subdomain_selection, save_origins_to_file, save_results_to_file,
};

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    domain: String,

    #[clap(short, long)]
    output: Option<String>,

    #[clap(long)]
    use_cloudfront: bool,

    #[clap(short, long)]
    viewdns: bool,

    #[clap(short, long)]
    both: bool,

    #[clap(short = 'g', long)]
    origin: bool,

    #[clap(long)]
    txt: bool,

    #[clap(long)]
    favi: bool,

    #[clap(long, requires = "favi")]
    key: Option<String>,
}

pub struct Cache {
    pdns_cache: HashMap<String, serde_json::Value>,
}

impl Cache {
    fn new() -> Self {
        Self {
            pdns_cache: HashMap::new(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();

    if args.favi {
        if let Some(api_key) = &args.key {
            match calculate_favicon_hash(&args.domain).await {
                Ok(hash) => {
                    println!("[*] Favicon hash for {}: {}", args.domain, hash);
                    match search_shodan_for_favicon(hash, api_key).await {
                        Ok(results) => {
                            println!(
                                "\x1b[33m[*] Found {} results with the same favicon hash:\x1b[0m",
                                results.len()
                            );
                            for ip in results {
                                println!("  - \x1b[32m{}\x1b[0m", ip);
                            }
                        }
                        Err(e) => println!("Error searching Shodan: {}", e),
                    }
                }
                Err(e) => println!("Error calculating favicon hash: {}", e),
            }
            return Ok(());
        } else {
            println!("Error: Shodan API key is required when using the -favi flag");
            return Ok(());
        }
    }

    let cache = Arc::new(Mutex::new(Cache::new()));

    if !is_using_cloudflare(&args.domain).await {
        println!("[-] Domain is not on Cloudflare.");
        let proceed = prompt_continue()?;
        if !proceed {
            return Ok(());
        }
    }

    let client = reqwest::Client::new();
    let subdomains = fetch_subdomains_from_crtsh(&client, &args.domain).await?;
    let unique_subdomains: HashSet<String> = subdomains.into_iter().collect();
    println!("[*] Found {} unique subdomains", unique_subdomains.len());

    let subdomain_selection = if unique_subdomains.len() > 5 {
        prompt_subdomain_selection()?
    } else {
        "all".to_string()
    };

    let cloudflare_ranges = get_cloudflare_ip_ranges().await?;
    println!(
        "[*] Fetched {} Cloudflare IP ranges",
        cloudflare_ranges.len()
    );

    let selected_subdomains = match subdomain_selection.as_str() {
        "all" => unique_subdomains.into_iter().collect(),
        "main" => vec![args.domain.clone()],
        "top5" => unique_subdomains.into_iter().take(5).collect(),
        _ => unique_subdomains.into_iter().collect(),
    };

    let non_cloudflare_hosts = process_subdomains(
        &selected_subdomains,
        &cloudflare_ranges,
        &args,
        &client,
        cache.clone(),
    )
    .await;

    println!(
        "[*] Found {} non-Cloudflare IPs",
        non_cloudflare_hosts.len()
    );

    for ip in &non_cloudflare_hosts {
        println!("\x1b[32m  - {}\x1b[0m", ip);
    }

    if args.origin {
        match find_origins(args.domain.clone(), &non_cloudflare_hosts).await {
            Ok(origins) => {
                if origins.is_empty() {
                    println!("[-] Did not find any origin server.");
                } else {
                    println!(
                        "\n[*] Found {} likely origin servers of {}!",
                        origins.len(),
                        args.domain
                    );
                    print_origins(&origins);
                    save_origins_to_file(&origins, args.output.as_deref())?;
                }

                println!("\n[*] Performing PDNS lookup on origin IPs");
                let pdns_tasks: Vec<_> = origins
                    .iter()
                    .map(|(ip, _)| {
                        let client = client.clone();
                        let cache = cache.clone();
                        let ip = *ip;
                        tokio::spawn(async move {
                            match fetch_passive_dns(&client, &ip.to_string(), cache).await {
                                Ok(pdns_data) => Ok((ip, pdns_data)),
                                Err(e) => Err(e),
                            }
                        })
                    })
                    .collect();

                let pdns_results = futures::future::join_all(pdns_tasks).await;
                for result in pdns_results {
                    if let Ok(Ok((ip, pdns_data))) = result {
                        println!("\nPDNS results for {}:", ip);
                        if let Some(data_array) = pdns_data.as_array() {
                            for record in data_array {
                                println!(
                                    "  - {} (Last seen: {})",
                                    record["query"], record["lastSeenTimestamp"]
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => println!("Error finding origins: {}", e),
        }
    }

    if args.txt {
        save_results_to_file(&non_cloudflare_hosts, "results.txt")?;
    }

    print_finished_message(&args.domain, &non_cloudflare_hosts).await?;

    Ok(())
}
