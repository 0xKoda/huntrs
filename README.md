# Huntrs: Web OSINT

Huntrs leverages OSINT techniques to identify and uncover related infrastructure. Namely, it serves 2 primary purposes, to identify origin servers of domains behind Cloudflare, and identify similar hosts via fashicon hash searches.

## Features

[*] Uncover origin servers of sites hidden behind Cloudflare
    - Analyze SSL certificates for subdomains
    - Utilize Passive DNS History to identify potential servers
    - Flexible output options (console, text file)

[*] Uncover related hosts by favicon hash
    - Calculate favicon murmur3 hash for a domain
    - Search Shodan for related servers by hash

## Description
Cloudflare provides an additional layer of security by masking the true IP addresses of origin servers. However, if not properly configured, origin servers may still be exposed. Huntrs helps find these origin servers.

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