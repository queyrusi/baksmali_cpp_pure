#include "cli/command_line_parser.hpp"
#include "baksmali.hpp"
#include <iostream>
#include <memory>

int main(int argc, char* argv[]) {
    try {
        CommandLineParser parser;
        auto options = parser.parse(argc, argv);
        
        if (!options) {
            return 1;
        }
        
        Baksmali baksmali(*options);
        return baksmali.disassemble() ? 0 : 1;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}