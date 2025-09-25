#pragma once

#include "baksmali_options.hpp"
#include "dex/dex_file.hpp"
#include <memory>
#include <vector>
#include <future>
#include <unordered_map>
#include <string>
#include <mutex>

class Baksmali {
public:
    explicit Baksmali(const BaksmaliOptions& options);
    
    bool disassemble();
    
private:
    BaksmaliOptions options_;
    std::unique_ptr<DexFile> dex_file_;
    std::unordered_map<std::string, int> filename_counters_;
    std::mutex filename_mutex_;

    bool load_dex_file();
    bool create_output_directory();
    std::vector<std::future<bool>> disassemble_classes_parallel();
    bool disassemble_class(const DexClass& class_def);
    std::string get_output_filename(const std::string& class_descriptor);
    std::string get_unique_output_filename(const std::string& class_descriptor);
};