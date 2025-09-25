#pragma once

#include "../baksmali_options.hpp"
#include <optional>
#include <memory>

class CommandLineParser {
public:
    std::optional<BaksmaliOptions> parse(int argc, char* argv[]);
    
private:
    void print_help();
    void print_version();
};