#include "baksmali_writer.hpp"
#include "../dex/dalvik_opcodes.hpp"
#include "../dex/dex_file.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <iostream>

BaksmaliWriter::BaksmaliWriter(std::ostream& output, const BaksmaliOptions& options)
    : output_(output), options_(options), indent_level_(0) {}

void BaksmaliWriter::write_class_header(const DexClass& class_def) {
    output_ << ".class ";
    write_access_flags(class_def.access_flags, true);
    output_ << class_def.class_name << "\n";
    
    if (!class_def.superclass_name.empty()) {
        output_ << ".super " << class_def.superclass_name << "\n";
    }
    
    for (const auto& interface : class_def.interfaces) {
        output_ << ".implements " << interface << "\n";
    }
}

void BaksmaliWriter::write_class_footer() {
    // No specific footer needed for classes
}

void BaksmaliWriter::write_fields(const std::vector<DexField>& fields, bool is_static) {
    for (const auto& field : fields) {
        write_field(field);
    }
}

void BaksmaliWriter::write_field(const DexField& field) {
    output_ << ".field ";
    write_access_flags(field.access_flags);
    output_ << field.name << ":" << field.type << "\n";
    // Java baksmali doesn't output .end field for simple fields
    // output_ << ".end field\n\n";
    output_ << "\n";
}

void BaksmaliWriter::write_methods(const std::vector<DexMethod>& methods, bool is_direct) {
    for (const auto& method : methods) {
        write_method(method);
    }
}

void BaksmaliWriter::write_method(const DexMethod& method) {
    output_ << ".method ";
    write_access_flags(method.access_flags);
    output_ << method.name << method.signature << "\n";
    
    if (method.code) {
        write_method_code(method);
    }
    
    output_ << ".end method\n\n";
}

void BaksmaliWriter::write_method_code(const DexMethod& method) {
    if (!method.code) return;
    
    indent();
    write_indented(".registers " + std::to_string(method.code->registers_size));
    write_blank_line();
    
    // Write instructions with method context for proper parameter register formatting
    // Java baksmali adds blank lines after every instruction except the last one
    const auto& instructions = method.code->instructions;
    for (size_t i = 0; i < instructions.size(); ++i) {
        write_instruction_with_method(instructions[i], instructions[i].address, &method, nullptr); // TODO: Pass DexFile

        // Add blank line after every instruction except the last one (matching Java baksmali behavior)
        if (i != instructions.size() - 1) {
            write_blank_line();
        }
    }
    
    dedent();
}

void BaksmaliWriter::write_instruction(const DexInstruction& instruction, uint32_t address) {
    write_indented(instruction.mnemonic);
    // TODO: Add operand formatting
}

void BaksmaliWriter::write_instruction_with_method(const DexInstruction& instruction, uint32_t address, const DexMethod* method, const DexFile* dex_file) {
    // Convert operands from uint32_t to uint16_t for the formatter
    std::vector<uint16_t> operands_16;
    for (uint32_t op : instruction.operands) {
        operands_16.push_back(static_cast<uint16_t>(op));
    }
    
    // Re-format the instruction with method context for parameter registers
    std::string formatted = DalvikInstructionParser::format_instruction_with_method(
        operands_16.data(), address, dex_file, method);
    write_indented(formatted);
}

void BaksmaliWriter::write_access_flags(uint32_t flags, bool is_class) {
    if (flags & ACC_PUBLIC) output_ << "public ";
    if (flags & ACC_PRIVATE) output_ << "private ";
    if (flags & ACC_PROTECTED) output_ << "protected ";
    if (flags & ACC_STATIC) output_ << "static ";
    if (flags & ACC_FINAL) output_ << "final ";
    if (flags & ACC_SYNCHRONIZED) output_ << "synchronized ";
    if (flags & ACC_VOLATILE) output_ << "volatile ";
    if (flags & ACC_BRIDGE) output_ << "bridge ";
    if (flags & ACC_TRANSIENT) output_ << "transient ";
    if (flags & ACC_VARARGS) output_ << "varargs ";
    if (flags & ACC_NATIVE) output_ << "native ";
    if (flags & ACC_INTERFACE) output_ << "interface ";
    if (flags & ACC_ABSTRACT) output_ << "abstract ";
    if (flags & ACC_STRICT) output_ << "strict ";
    if (flags & ACC_SYNTHETIC) output_ << "synthetic ";
    if (flags & ACC_ANNOTATION) output_ << "annotation ";
    if (flags & ACC_ENUM) output_ << "enum ";
    if (flags & ACC_CONSTRUCTOR) output_ << "constructor ";
    if (flags & ACC_DECLARED_SYNCHRONIZED) output_ << "declared-synchronized ";
}

void BaksmaliWriter::write_type_descriptor(const std::string& type) {
    output_ << type;
}

void BaksmaliWriter::write_string_literal(const std::string& str) {
    output_ << "\"" << escape_string(str) << "\"";
}

void BaksmaliWriter::write_comment(const std::string& comment) {
    output_ << "# " << comment << "\n";
}

void BaksmaliWriter::write_blank_line() {
    output_ << "\n";
}

void BaksmaliWriter::indent() {
    indent_level_++;
}

void BaksmaliWriter::dedent() {
    if (indent_level_ > 0) {
        indent_level_--;
    }
}

void BaksmaliWriter::write_indented(const std::string& text) {
    for (int i = 0; i < indent_level_; ++i) {
        output_ << "    ";
    }
    output_ << text << "\n";
}

std::string BaksmaliWriter::format_method_signature(const DexMethod& method) {
    return method.signature;
}

std::string BaksmaliWriter::format_field_descriptor(const DexField& field) {
    return field.name + ":" + field.type;
}

std::string BaksmaliWriter::escape_string(const std::string& str) {
    std::string result;
    result.reserve(str.length() * 2);

    for (size_t i = 0; i < str.length(); ++i) {
        char c = str[i];

        if (c == '\r') {
            result += "\\r";
            if (i + 1 < str.length() && str[i + 1] == '\n') {
                result += "\\n";
                ++i;
            }
            continue;
        }
        if (c == '\n') {
            result += "\\n";
            continue;
        }

        if (c == '\\' && i + 1 < str.length() && str[i + 1] == 'u' && i + 5 < str.length()) {
            bool is_unicode = true;
            for (size_t j = 2; j <= 5; ++j) {
                char hex = str[i + j];
                if (!((hex >= '0' && hex <= '9') ||
                      (hex >= 'a' && hex <= 'f') ||
                      (hex >= 'A' && hex <= 'F'))) {
                    is_unicode = false;
                    break;
                }
            }
            if (is_unicode) {
                result += '\\';
                result += 'u';
                result.append(str, i + 2, 4);
                i += 5;
                continue;
            }
        }

        switch (c) {
            case '"': result += "\\\""; break;
            case '\'': result += "\\'"; break;
            case '\\': result += "\\\\"; break;  // Standard escaping: \\ -> \\\\\n            case '\t': result += "\\t"; break;
            default: result += c; break;
        }
    }

    return result;
}

std::string BaksmaliWriter::get_access_flags_string(uint32_t flags, bool is_class) {
    std::string result;
    
    if (flags & ACC_PUBLIC) result += "public ";
    if (flags & ACC_PRIVATE) result += "private ";
    if (flags & ACC_PROTECTED) result += "protected ";
    if (flags & ACC_STATIC) result += "static ";
    if (flags & ACC_FINAL) result += "final ";
    if (flags & ACC_SYNCHRONIZED) result += "synchronized ";
    if (flags & ACC_VOLATILE) result += "volatile ";
    if (flags & ACC_BRIDGE) result += "bridge ";
    if (flags & ACC_TRANSIENT) result += "transient ";
    if (flags & ACC_VARARGS) result += "varargs ";
    if (flags & ACC_NATIVE) result += "native ";
    if (flags & ACC_INTERFACE) result += "interface ";
    if (flags & ACC_ABSTRACT) result += "abstract ";
    if (flags & ACC_STRICT) result += "strict ";
    if (flags & ACC_SYNTHETIC) result += "synthetic ";
    if (flags & ACC_ANNOTATION) result += "annotation ";
    if (flags & ACC_ENUM) result += "enum ";
    if (flags & ACC_CONSTRUCTOR) result += "constructor ";
    if (flags & ACC_DECLARED_SYNCHRONIZED) result += "declared-synchronized ";
    
    return result;
}
