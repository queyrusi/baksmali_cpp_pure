#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct BaksmaliOptions {
    std::string input_file;
    std::string output_directory = "out";
    
    // API level (default: 15, matching Java version)
    int api_level = 15;
    
    // Threading
    int job_count = 0; // 0 = auto-detect
    
    // Formatting options
    bool debug_info = true;
    bool register_info = false;
    bool parameter_registers = true;
    bool code_offsets = false;
    bool implicit_references = false;
    bool normalize_virtual_methods = false;
    
    // Processing modes
    bool allow_odex = false;
    bool deodex = false;
    
    // Output options
    bool use_sequential_labels = false;
    
    // Class filtering
    std::vector<std::string> classes;
    
    // Verbose output
    bool verbose = false;
};