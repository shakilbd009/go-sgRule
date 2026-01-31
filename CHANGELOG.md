# go-sgRule Changelog

## v2.0.0 (2026-01-31)

### Improvements
- **Error Handling**: Replaced panic() with proper error returns
- **Logging**: Added structured logging with timestamps
- **Configuration**: AWS region configurable via environment variable
- **Input Validation**: Better CSV validation with clear error messages
- **Code Quality**: Cleaner function separation and documentation
- **Dependencies**: Updated to AWS SDK v2 latest

### Breaking Changes
- Command line interface changed from flags to positional argument
- AWS region now set via `AWS_REGION` env var instead of hardcoded constant
- Log output format changed to structured logging

### Technical Details
- Replaced deprecated `aws/external` package with `config` package
- Replaced `ec2.IpRange` with `types.IpRange`
- Removed global panic recovery in favor of explicit error handling
- Added proper context propagation throughout

## v1.0.0 (2020-04-22)

### Initial Release
- CSV-based security group rule management
- Concurrent rule processing with goroutines
- AWS SDK v2 integration
- Basic error recovery with panic/recover
