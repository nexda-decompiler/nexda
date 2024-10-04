# Nexda Reverse Engineering Framework

Nexda is a versatile reverse engineering framework built in C++ and CMake. It is designed for both beginners and experienced developers, providing tools to analyze binaries, generate hex dumps, and perform memory analysis. With its modular architecture, Nexda allows users to extend its capabilities to suit their specific needs.

## Features

- **Binary Analysis**: Examine and dissect executable files to understand their structure and functionality.
- **Hex Dump Generation**: Create hex representations of binary data for detailed inspection and analysis.
- **Memory Analysis**: Monitor and analyze memory usage of running applications to identify performance bottlenecks and memory leaks.

## Getting Started

To get started with Nexda, clone the repository and build the project using CMake:

```bash
git clone https://github.com/nexda-decompiler/nexda.git
cd nexda
mkdir build && cd build
cmake ..
make
```

## Usage

After building the project, you can run Nexda tools using the command line, like the binary analyzer:

```bash
cd bin
./nexda-binanalyze input.exe
```

Refer to the documentation for a detailed list of options and usage examples.

## Contributing

Contributions are welcome! Please read the [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Nexda is licensed under the Apache 2.0 License. See [LICENSE](LICENSE) for more details.

## Acknowledgments

- CMake for the build system.
- Contributors and users for their feedback and support.