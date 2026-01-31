# go-sgRule

AWS EC2 Security Group Rule Manager - Automate security group rule creation from CSV files.

## Overview

go-sgRule reads firewall rules from a CSV file and automatically creates inbound/outbound security group rules in AWS EC2. It finds security groups based on private IP addresses and applies rules concurrently.

## Features

- ✅ CSV-based rule definitions
- ✅ Automatic security group discovery from IP addresses
- ✅ Concurrent rule processing
- ✅ Support for CIDR ranges and individual IPs
- ✅ Structured logging with timestamps
- ✅ Error handling without panics
- ✅ AWS SDK v2 (latest)

## Prerequisites

- Go 1.19+
- AWS credentials configured (`~/.aws/credentials` or environment variables)
- AWS IAM permissions for EC2: `DescribeNetworkInterfaces`, `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`

## Installation

```bash
go get github.com/shakilbd009/go-sgrule
cd go-sgrule
go build -o sgrule
```

## Usage

```bash
# Set AWS region (optional, defaults to us-east-2)
export AWS_REGION=us-east-1

# Run with CSV file
./sgrule rules.csv
```

## CSV Format

The CSV file should have the following columns:

| Column | Description | Example |
|--------|-------------|---------|
| dest_ip | Destination private IP address | 10.0.1.10 |
| protocol | Protocol (tcp, udp, icmp) | tcp |
| description | Rule description | Web server access |
| port | Port number | 80 |
| source_ips | Space-separated IPs/CIDRs | 0.0.0.0/0 192.168.1.0/24 |
| direction | inbound or outbound | inbound |

### Example CSV

```csv
dest_ip,protocol,description,port,source_ips,direction
10.0.1.10,tcp,Web server,80,0.0.0.0/0,inbound
10.0.1.10,tcp,Web server SSL,443,0.0.0.0/0,inbound
10.0.1.11,tcp,Database access,5432,10.0.0.0/8,outbound
```

## How It Works

1. **Parse CSV**: Reads and validates the CSV file
2. **Find Security Groups**: Looks up security groups by private IP address
3. **Build Rules**: Converts IPs to CIDR format (adds /32 if missing)
4. **Apply Rules**: Creates ingress/egress rules concurrently
5. **Log Results**: Outputs structured logs with timestamps

## Error Handling

- File not found: Clear error message with exit
- Invalid CSV format: Row-level error reporting
- AWS API errors: Descriptive error messages
- Missing security groups: Specific IP mentioned in error

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region for API calls | us-east-2 |
| `AWS_PROFILE` | AWS credentials profile | default |

## Improvements from Original

- **Error Handling**: Returns errors instead of panicking
- **Logging**: Structured logging with timestamps
- **Configuration**: AWS region via environment variable
- **Code Organization**: Cleaner function separation
- **Validation**: Better input validation
- **Documentation**: Comprehensive README

## License

MIT

## Author

Shakil Akram - Learning Go by building real tools
