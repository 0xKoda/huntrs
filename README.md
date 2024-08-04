# Huntrs: Exposing Origin Servers Behind Cloudflare

Huntrs is a powerful Rust-based CLI designed to uncover origin servers hidden behind Cloudflare and find hosts with matching favicon hashes. It leverages OSINT techniques, specifically SSL Certificates, Passive DNS History, and favicon hash searches to identify potential origin servers or other infrastructure.

## Features

- Uncover origin servers of sites hidden behind Cloudflare
- Find hosts with the same favicon hash
- Analyze SSL certificates via crt.sh
- Utilize Passive DNS History for deeper insights
- Option to check for Cloudfront origin servers
- Flexible output options (console, text file)

## Description
This tool serves two primary functions:
- Identifying origin servers via pdns and SSL certs
- Identifying servers via favicon hash 

Cloudflare provides an additional layer of security by masking the true IP addresses of origin servers. However, if not properly configured, origin servers may still be exposed. Huntrs helps find origin servers behind cloudflare.

Favicon hashes provide a timeless method for uncovering potentially related servers. 

## Installation

### Prerequisites

Ensure you have the latest version of Rust installed.

### Building from Source
```bash
cargo build --release
```

The binary will be available in `target/release/huntrs`.

## Usage

### Basic Syntax
```bash
huntrs [OPTIONS] <DOMAIN>
```

### Examples

1. Find origin servers for example.com:
```bash
huntrs example.com
```

2. Find origin servers by favicon hash:
```bash
   huntrs example.com --favi --key <shodan key>
```

### Options

- `-o, --output <OUTPUT>`: Specify the output file
- `--use-cloudfront`: Check for Cloudfront origin servers
- `-v, --viewdns`: Use only ViewDNS history
- `-b, --both`: Use both Passive DNS sources for deeper results
- `-g, --origin`: Show only origin server information
- `--txt`: Output results to a text file
- `-h, --help`: Print help information
- `-V, --version`: Print version information
- `--favi`: Perform favicon search
- `--key <SHODAN_KEY>`: Shodan API key for favicon search

## Interactive Mode

If Huntrs finds more than 5 subdomains to scan, it will prompt you to choose:
- `all`: Scan all subdomains
- `top5`: Scan only the top 5 subdomains
- `main`: Scan only the main domain

## Contributing

Contributions are welcome! 

## Disclaimer

This tool is provided as is and is for educational purposes only.