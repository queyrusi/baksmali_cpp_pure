#pragma once

#include "../dex/dex_structures.hpp"
#include "../baksmali_options.hpp"
#include <string>
#include <ostream>
#include <memory>

class BaksmaliWriter {
public:
    explicit BaksmaliWriter(std::ostream& output, const BaksmaliOptions& options);
    
    // Class definition writing
    void write_class_header(const DexClass& class_def);
    void write_class_footer();
    
    // Field writing
    void write_fields(const std::vector<DexField>& fields, bool is_static);
    void write_field(const DexField& field);
    
    // Method writing
    void write_methods(const std::vector<DexMethod>& methods, bool is_direct);
    void write_method(const DexMethod& method);
    void write_method_code(const DexMethod& method);
    
    // Instruction writing
    void write_instruction(const DexInstruction& instruction, uint32_t address);
    void write_instruction_with_method(const DexInstruction& instruction, uint32_t address, const struct DexMethod* method, const class DexFile* dex_file);
    
    // Utility methods
    void write_access_flags(uint32_t flags, bool is_class = false);
    void write_type_descriptor(const std::string& type);
    void write_string_literal(const std::string& str);
    void write_comment(const std::string& comment);
    void write_blank_line();
    
    // Indentation
    void indent();
    void dedent();
    void write_indented(const std::string& text);
    
private:
    std::ostream& output_;
    const BaksmaliOptions& options_;
    int indent_level_;
    
    std::string format_method_signature(const DexMethod& method);
    std::string format_field_descriptor(const DexField& field);
    std::string escape_string(const std::string& str);
    std::string get_access_flags_string(uint32_t flags, bool is_class = false);
};