#include "baksmali.hpp"
#include "formatter/baksmali_writer.hpp"
#include "adaptors/class_definition.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <thread>
#include <algorithm>
#include <cctype>
#include <unordered_map>

Baksmali::Baksmali(const BaksmaliOptions& options) : options_(options) {}

bool Baksmali::disassemble() {
    if (!load_dex_file()) {
        return false;
    }
    
    if (!create_output_directory()) {
        return false;
    }
    
    if (options_.verbose) {
        std::cout << "Disassembling " << dex_file_->classes().size() << " classes..." << std::endl;
    }
    
    // Use parallel processing if multiple jobs are requested
    if (options_.job_count != 1) {
        auto futures = disassemble_classes_parallel();
        
        bool success = true;
        for (auto& future : futures) {
            if (!future.get()) {
                success = false;
            }
        }
        return success;
    } else {
        // Single-threaded processing
        bool success = true;
        for (const auto& class_def : dex_file_->classes()) {
            if (!disassemble_class(class_def)) {
                success = false;
            }
        }
        return success;
    }
}

bool Baksmali::load_dex_file() {
    dex_file_ = DexFile::open(options_.input_file);
    if (!dex_file_) {
        std::cerr << "Error: Failed to load DEX file: " << options_.input_file << std::endl;
        return false;
    }
    
    if (options_.verbose) {
        std::cout << "Loaded DEX file with " << dex_file_->classes().size() << " classes" << std::endl;
    }
    
    return true;
}

bool Baksmali::create_output_directory() {
    try {
        std::filesystem::create_directories(options_.output_directory);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error: Failed to create output directory: " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::future<bool>> Baksmali::disassemble_classes_parallel() {
    std::vector<std::future<bool>> futures;
    
    // Determine number of threads
    int job_count = options_.job_count;
    if (job_count <= 0) {
        job_count = std::thread::hardware_concurrency();
        if (job_count <= 0) {
            job_count = 4; // fallback
        }
    }
    
    // Create thread pool using std::async
    const auto& classes = dex_file_->classes();
    futures.reserve(classes.size());
    
    for (const auto& class_def : classes) {
        futures.emplace_back(
            std::async(std::launch::async, [this, &class_def]() {
                return disassemble_class(class_def);
            })
        );
    }
    
    return futures;
}

bool Baksmali::disassemble_class(const DexClass& class_def) {
    try {
        std::string output_filename = get_unique_output_filename(class_def.class_name);
        std::string full_path = options_.output_directory + "/" + output_filename;
        
        // Create parent directories if needed
        std::filesystem::create_directories(std::filesystem::path(full_path).parent_path());
        
        std::ofstream output(full_path);
        if (!output.is_open()) {
            std::cerr << "Error: Cannot create output file: " << full_path << std::endl;
            return false;
        }
        
        ClassDefinition class_adapter(class_def, options_);
        class_adapter.write_to(output);
        
        if (options_.verbose) {
            std::cout << "Generated: " << output_filename << std::endl;
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error disassembling class " << class_def.class_name << ": " << e.what() << std::endl;
        return false;
    }
}

std::string Baksmali::get_output_filename(const std::string& class_descriptor) {
    std::string filename = class_descriptor;

    // Remove leading 'L' and trailing ';' if present
    if (filename.length() > 2 && filename[0] == 'L' && filename.back() == ';') {
        filename = filename.substr(1, filename.length() - 2);
    }

    // Replace '/' with filesystem separator and '$' with '$'
    std::replace(filename.begin(), filename.end(), '/', std::filesystem::path::preferred_separator);

    // Add .smali extension
    filename += ".smali";

    return filename;
}

std::string Baksmali::get_unique_output_filename(const std::string& class_descriptor) {
    std::string base_filename = get_output_filename(class_descriptor);

    // Check for collision using case-insensitive comparison for filesystem safety
    std::string lowercase_filename = base_filename;
    std::transform(lowercase_filename.begin(), lowercase_filename.end(), lowercase_filename.begin(), ::tolower);

    std::lock_guard<std::mutex> lock(filename_mutex_);
    auto it = filename_counters_.find(lowercase_filename);
    if (it == filename_counters_.end()) {
        // First time seeing this filename
        filename_counters_[lowercase_filename] = 0;
        return base_filename;
    } else {
        // Collision detected, increment counter and append suffix
        it->second++;
        std::string name_without_ext = base_filename.substr(0, base_filename.length() - 6); // Remove ".smali"
        return name_without_ext + "." + std::to_string(it->second) + ".smali";
    }
}