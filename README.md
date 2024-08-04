# Huntrs: Exposing Origin Servers Behind Cloudflare

Cloudflare provides an additional layer of security by masking the true IP addresses of origin servers. However, if not properly configured, origin servers may still be exposed, making them vulnerable to attacks. **Huntrs** is a Rust-based CLI tool designed to leverage OSINT techniques, specifically SSL Certificates and Passive DNS History, to identify and list potential origin servers that might be hidden behind Cloudflare.

Huntrs also can find origin servers by Favicon hash matches. 

## Description

Huntrs helps security professionals and researchers discover origin servers that could be exposed despite using Cloudflare's protective network. By analyzing SSL certificates via crt.sh and utilizing Passive DNS History, the tool finds subdomains and checks for any origin servers that may not be protected by Cloudflare. This information is crucial for identifying potential vulnerabilities and ensuring that sensitive infrastructure is adequately shielded. It is also extremely helpful in identifying and examining infrastructure used for nefarious means.

Huntrs also can find origin servers by Favicon hash matches.

## Usage

### Prerequisites

Ensure you have the latest version of Rust installed.

### Installation

You can either download the pre-built binary or build Huntrs from the source.

To build from source, use:

```bash
cargo build --release
```

### Running Huntrs
```bash
huntrs [OPTIONS] <DOMAIN>
```
### Example
To find origin servers for example.com, simply run:

```bash
cargo run example.com
```

To find origin servers by `favicon` for example.com, simply run:

```bash
cargo run example.com --favi --key <shodan key>
```

### Options

- `-o, --output <OUTPUT>`: Specify the output file.
- `--use-cloudfront`: Check for Cloudfront origin servers.
- `-v, --viewdns`: Use only ViewDNS history.
- `-b, --both`: Use both Passive DNS sources for deeper results.
- `-g, --origin`: Show only origin server information.
- `--txt`: Output results to a text file.
- `-h, --help`: Print the help information.
- `-V, --version`: Print the version information.
- `--favi`: Perform favicon search
- `--key`: Insert Shodan API key for favi search



## Contributing
Contributions are welcome! Feel free to fork the repository and submit a Pull Request with your improvements or new features.
