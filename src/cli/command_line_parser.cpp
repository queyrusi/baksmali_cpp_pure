#include "command_line_parser.hpp"
#include <iostream>
#include <cstring>
#include <filesystem>

std::optional<BaksmaliOptions> CommandLineParser::parse(int argc, char* argv[]) {
    BaksmaliOptions options;
    
    if (argc < 2) {
        print_help();
        return std::nullopt;
    }
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            print_help();
            return std::nullopt;
        } else if (arg == "--version" || arg == "-v") {
            print_version();
            return std::nullopt;
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                return std::nullopt;
            }
            options.output_directory = argv[++i];
        } else if (arg == "--api-level") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                return std::nullopt;
            }
            options.api_level = std::stoi(argv[++i]);
        } else if (arg == "--jobs" || arg == "-j") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                return std::nullopt;
            }
            options.job_count = std::stoi(argv[++i]);
        } else if (arg == "--debug-info") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                return std::nullopt;
            }
            options.debug_info = (std::string(argv[++i]) == "true");
        } else if (arg == "--register-info") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                return std::nullopt;
            }
            options.register_info = (std::string(argv[++i]) == "true");
        } else if (arg == "--parameter-registers") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                return std::nullopt;
            }
            options.parameter_registers = (std::string(argv[++i]) == "true");
        } else if (arg == "--code-offsets") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires a value" << std::endl;
                return std::nullopt;
            }
            options.code_offsets = (std::string(argv[++i]) == "true");
        } else if (arg == "--sequential-labels") {
            options.use_sequential_labels = true;
        } else if (arg == "--verbose") {
            options.verbose = true;
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Error: Unknown option " << arg << std::endl;
            return std::nullopt;
        } else {
            // Input file
            if (options.input_file.empty()) {
                options.input_file = arg;
            } else {
                std::cerr << "Error: Multiple input files specified" << std::endl;
                return std::nullopt;
            }
        }
    }
    
    if (options.input_file.empty()) {
        std::cerr << "Error: No input file specified" << std::endl;
        return std::nullopt;
    }
    
    if (!std::filesystem::exists(options.input_file)) {
        std::cerr << "Error: Input file does not exist: " << options.input_file << std::endl;
        return std::nullopt;
    }
    
    return options;
}

void CommandLineParser::print_help() {
    std::cout << "baksmali_cpp - A C++ implementation of baksmali\n\n";
    std::cout << "Usage: baksmali [options] <dex-file>\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help              Show this help message\n";
    std::cout << "  -v, --version           Show version information\n";
    std::cout << "  -o, --output <dir>      Output directory (default: out)\n";
    std::cout << "  --api-level <level>     API level (default: 15)\n";
    std::cout << "  -j, --jobs <count>      Number of threads (default: auto)\n";
    std::cout << "  --debug-info <bool>     Include debug info (default: true)\n";
    std::cout << "  --register-info <bool>  Include register info (default: false)\n";
    std::cout << "  --parameter-registers <bool> Use parameter registers (default: true)\n";
    std::cout << "  --code-offsets <bool>   Include code offsets (default: false)\n";
    std::cout << "  --sequential-labels     Use sequential labels instead of addresses\n";
    std::cout << "  --verbose               Verbose output\n";
}

void CommandLineParser::print_version() {
    std::cout << "baksmali_cpp version 1.0.0\n";
    std::cout << "Compatible with baksmali 2.5.2\n";
}