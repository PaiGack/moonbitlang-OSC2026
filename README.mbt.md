# paigack/ssh_client

A MoonBit SSH client library entry for the MoonBit 2026 Open Source Competition.

## Project Overview

This project aims to implement SSH protocol support for the MoonBit ecosystem.

## Status

🚧 **Early Stage** — Project structure initialized, transport layer implementation in progress.

## Features (Planned)

- SSH transport layer with TCP connection support
- SSH client functionality for the MoonBit ecosystem

## Project Structure

```
code/
├── cmd/main/main.mbt       # Main program entry point
├── ssh_client.mbt         # Library code (SSH client implementation)
├── ssh_client_test.mbt    # Blackbox tests
├── ssh_client_wbtest.mbt  # Whitebox tests
└── moon.mod               # Module metadata
```

## Getting Started

```bash
# Build the project
moon build

# Run tests
moon test

# Run the main program
moon run cmd/main

# Format code
moon fmt
```

## Requirements

- MoonBit toolchain installed
- TCP network access for SSH connections

## License

See [LICENSE](LICENSE) file for details.