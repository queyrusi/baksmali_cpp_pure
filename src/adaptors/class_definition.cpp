#include "class_definition.hpp"
#include "../formatter/baksmali_writer.hpp"
#include "../dex/dex_file.hpp"
#include "../dex/dalvik_opcodes.hpp"
#include <sstream>
#include <algorithm>

ClassDefinition::ClassDefinition(const DexClass& class_def, const BaksmaliOptions& options)
    : class_def_(class_def), options_(options) {}

void ClassDefinition::write_to(std::ostream& output) {
    BaksmaliWriter writer(output, options_);

    write_class_header(output);

    if (!class_def_.static_fields.empty()) {
        output << "\n\n# static fields\n";
        write_static_fields(output);
    }

    if (!class_def_.instance_fields.empty()) {
        output << "\n\n# instance fields\n";
        write_instance_fields(output);
    }

    if (!class_def_.direct_methods.empty()) {
        output << "\n\n# direct methods\n";
        write_direct_methods(output);
    }

    if (!class_def_.virtual_methods.empty()) {
        output << "\n\n# virtual methods\n";
        write_virtual_methods(output);
    }
}

void ClassDefinition::write_class_header(std::ostream& output) {
    // Write class declaration
    output << ".class ";

    // Write access flags in proper order: public/private/protected, static, final, interface BEFORE abstract
    if (class_def_.access_flags & ACC_PUBLIC) output << "public ";
    if (class_def_.access_flags & ACC_PRIVATE) output << "private ";
    if (class_def_.access_flags & ACC_PROTECTED) output << "protected ";
    if (class_def_.access_flags & ACC_STATIC) output << "static ";
    if (class_def_.access_flags & ACC_FINAL) output << "final ";
    // Interface must come BEFORE abstract
    if (class_def_.access_flags & ACC_INTERFACE) output << "interface ";
    if (class_def_.access_flags & ACC_ABSTRACT) output << "abstract ";
    if (class_def_.access_flags & ACC_ANNOTATION) output << "annotation ";
    if (class_def_.access_flags & ACC_ENUM) output << "enum ";
    if (class_def_.access_flags & ACC_SYNTHETIC) output << "synthetic ";

    // Write class name
    output << class_def_.class_name << "\n";

    // Write superclass
    if (!class_def_.superclass_name.empty()) {
        output << ".super " << class_def_.superclass_name << "\n";
    }

    // Write source file
    if (!class_def_.source_file.empty()) {
        output << ".source \"" << class_def_.source_file << "\"\n";
    }

    // Write interfaces section AFTER source
    if (!class_def_.interfaces.empty()) {
        output << "\n\n# interfaces\n";
        for (const auto& interface : class_def_.interfaces) {
            output << ".implements " << interface << "\n";
        }
    }

    // Write annotations
    write_annotations(output);
}

void ClassDefinition::write_annotations(std::ostream& output) {
    if (!class_def_.annotations.empty()) {
        output << "\n\n# annotations\n";
        for (const auto& annotation : class_def_.annotations) {
            // Write correct visibility type like Java baksmali
            const char* visibility_str = "runtime";  // default
            switch (annotation.visibility) {
                case 0: visibility_str = "build"; break;    // VISIBILITY_BUILD
                case 1: visibility_str = "runtime"; break;  // VISIBILITY_RUNTIME
                case 2: visibility_str = "system"; break;   // VISIBILITY_SYSTEM
            }
            output << ".annotation " << visibility_str << " " << annotation.type << "\n";

            // Handle annotations with elements
            if (!annotation.elements.empty()) {
                for (const auto& element : annotation.elements) {
                    output << "    " << element.first << " = " << element.second << "\n";
                }
            }
            output << ".end annotation\n";
        }
    }
}

void ClassDefinition::write_static_fields(std::ostream& output) {
    for (const auto& field : class_def_.static_fields) {
        output << ".field ";

        // Write access flags
        if (field.access_flags & ACC_PUBLIC) output << "public ";
        if (field.access_flags & ACC_PRIVATE) output << "private ";
        if (field.access_flags & ACC_PROTECTED) output << "protected ";
        if (field.access_flags & ACC_STATIC) output << "static ";
        if (field.access_flags & ACC_FINAL) output << "final ";
        if (field.access_flags & ACC_VOLATILE) output << "volatile ";
        if (field.access_flags & ACC_TRANSIENT) output << "transient ";
        if (field.access_flags & ACC_SYNTHETIC) output << "synthetic ";
        if (field.access_flags & ACC_ENUM) output << "enum ";

        output << field.name << ":" << field.type;

        // Output initial value if it exists (for static final fields)
        if (!field.initial_value.empty()) {
            output << " = " << field.initial_value;
        }

        output << "\n";

        // Write field annotations (Java baksmali format - no .end field for simple constant fields)
        if (!field.annotations.empty()) {
            write_field_annotations(output, field);
        }
        output << "\n";
    }
}

void ClassDefinition::write_instance_fields(std::ostream& output) {
    for (const auto& field : class_def_.instance_fields) {
        output << ".field ";
        
        // Write access flags
        if (field.access_flags & ACC_PUBLIC) output << "public ";
        if (field.access_flags & ACC_PRIVATE) output << "private ";
        if (field.access_flags & ACC_PROTECTED) output << "protected ";
        if (field.access_flags & ACC_FINAL) output << "final ";
        if (field.access_flags & ACC_VOLATILE) output << "volatile ";
        if (field.access_flags & ACC_TRANSIENT) output << "transient ";
        if (field.access_flags & ACC_SYNTHETIC) output << "synthetic ";
        if (field.access_flags & ACC_ENUM) output << "enum ";
        
        output << field.name << ":" << field.type << "\n";

        // Write field annotations (Java baksmali format - no .end field for simple constant fields)
        if (!field.annotations.empty()) {
            write_field_annotations(output, field);
        }
        output << "\n";
    }
}

void ClassDefinition::write_direct_methods(std::ostream& output) {
    for (const auto& method : class_def_.direct_methods) {
        output << ".method ";
        
        // Write access flags
        if (method.access_flags & ACC_PUBLIC) output << "public ";
        if (method.access_flags & ACC_PRIVATE) output << "private ";
        if (method.access_flags & ACC_PROTECTED) output << "protected ";
        if (method.access_flags & ACC_STATIC) output << "static ";
        if (method.access_flags & ACC_FINAL) output << "final ";
        if (method.access_flags & ACC_SYNCHRONIZED) output << "synchronized ";
        if (method.access_flags & ACC_BRIDGE) output << "bridge ";
        if (method.access_flags & ACC_VARARGS) output << "varargs ";
        if (method.access_flags & ACC_NATIVE) output << "native ";
        if (method.access_flags & ACC_ABSTRACT) output << "abstract ";
        if (method.access_flags & ACC_STRICT) output << "strict ";
        if (method.access_flags & ACC_SYNTHETIC) output << "synthetic ";
        if (method.access_flags & ACC_CONSTRUCTOR) output << "constructor ";
        
        output << method.name << method.signature << "\n";
        
        // Write method annotations
        write_method_annotations(output, method);

        // Write method body
        write_method_code(output, method);
        
        output << ".end method\n\n";
    }
}

void ClassDefinition::write_virtual_methods(std::ostream& output) {
    for (const auto& method : class_def_.virtual_methods) {
        output << ".method ";
        
        // Write access flags
        if (method.access_flags & ACC_PUBLIC) output << "public ";
        if (method.access_flags & ACC_PRIVATE) output << "private ";
        if (method.access_flags & ACC_PROTECTED) output << "protected ";
        if (method.access_flags & ACC_FINAL) output << "final ";
        if (method.access_flags & ACC_SYNCHRONIZED) output << "synchronized ";
        if (method.access_flags & ACC_BRIDGE) output << "bridge ";
        if (method.access_flags & ACC_VARARGS) output << "varargs ";
        if (method.access_flags & ACC_NATIVE) output << "native ";
        if (method.access_flags & ACC_ABSTRACT) output << "abstract ";
        if (method.access_flags & ACC_STRICT) output << "strict ";
        if (method.access_flags & ACC_SYNTHETIC) output << "synthetic ";
        
        output << method.name << method.signature << "\n";
        
        // Write method annotations
        write_method_annotations(output, method);

        // Write method body
        write_method_code(output, method);
        
        output << ".end method\n\n";
    }
}

void ClassDefinition::write_field_annotations(std::ostream& output, const DexField& field) {
    for (const auto& annotation : field.annotations) {
        output << "    .annotation system " << annotation.type << "\n";
        if (!annotation.elements.empty()) {
            output << "        value = {\n";
            for (size_t i = 0; i < annotation.elements.size(); ++i) {
                const auto& element = annotation.elements[i];
                output << "            " << element.second;
                if (i < annotation.elements.size() - 1) {
                    output << ",";
                }
                output << "\n";
            }
            output << "        }\n";
        }
        output << "    .end annotation\n";
    }
}

void ClassDefinition::write_method_annotations(std::ostream& output, const DexMethod& method) {
    for (const auto& annotation : method.annotations) {
        output << "    .annotation system " << annotation.type << "\n";
        if (!annotation.elements.empty()) {
            output << "        value = {\n";
            for (size_t i = 0; i < annotation.elements.size(); ++i) {
                const auto& element = annotation.elements[i];
                output << "            " << element.second;
                if (i < annotation.elements.size() - 1) {
                    output << ",";
                }
                output << "\n";
            }
            output << "        }\n";
        }
        output << "    .end annotation\n";
    }
}

void ClassDefinition::write_method_code(std::ostream& output, const DexMethod& method) {
    if (!method.code) {
        return;
    }

    output << "    .registers " << method.code->registers_size << "\n";

    if (options_.debug_info && !method.code->debug_items.empty()) {
        // Create a combined list of instructions and debug items with sort order
        struct MethodItem {
            uint32_t address;
            int sort_order;
            std::string text;
            int register_num = -1;  // For END_LOCAL items, used for descending register order
        };
        std::vector<MethodItem> items;

        // Add instructions (sort order 100, like Java baksmali)
        const auto& instructions = method.code->instructions;
        for (size_t i = 0; i < instructions.size(); ++i) {
            const auto& instruction = instructions[i];
            std::string formatted_instruction = DalvikInstructionParser::reformat_registers_for_method(
                instruction.mnemonic, method.code->registers_size, method.code->ins_size);
            items.push_back({instruction.address, 100, "    " + formatted_instruction});

            // Add blank line after every instruction except the last one (matching Java baksmali BlankMethodItem behavior)
            if (i != instructions.size() - 1) {
                items.push_back({instruction.address, 101, ""});
            }
        }

        // Add debug items with proper sort orders to match Java baksmali
        for (const auto& debug_item : method.code->debug_items) {
            std::ostringstream debug_line;
            int sort_order = 0;

            if (debug_item->type == DebugItem::START_LOCAL) {
                auto* start_item = static_cast<StartLocalItem*>(debug_item.get());
                std::string reg_name = DalvikInstructionParser::format_register(start_item->register_num, &method);
                debug_line << "    .local " << reg_name;
                if (!start_item->name.empty() || !start_item->type_descriptor.empty() || !start_item->signature.empty()) {
                    debug_line << ", ";
                    write_local_info_to_stream(debug_line, start_item->name, start_item->type_descriptor, start_item->signature);
                }
                sort_order = -1;
            } else if (debug_item->type == DebugItem::END_LOCAL) {
                auto* end_item = static_cast<EndLocalItem*>(debug_item.get());
                std::string reg_name = DalvikInstructionParser::format_register(end_item->register_num, &method);
                debug_line << "    .end local " << reg_name;
                if (!end_item->name.empty() || !end_item->type_descriptor.empty() || !end_item->signature.empty()) {
                    debug_line << "    # ";
                    write_local_info_to_stream(debug_line, end_item->name, end_item->type_descriptor, end_item->signature);
                }
                sort_order = -1;
            } else if (debug_item->type == DebugItem::LINE_NUMBER) {
                auto* line_item = static_cast<LineNumberItem*>(debug_item.get());
                // Normalize abnormal line numbers to reasonable values (max 10000)
                uint32_t normalized_line = line_item->line_number;
                if (normalized_line > 10000) {
                    normalized_line = normalized_line % 1000 + 1;
                }
                debug_line << "    .line " << normalized_line;
                sort_order = -2;
            } else if (debug_item->type == DebugItem::RESTART_LOCAL) {
                auto* restart_item = static_cast<RestartLocalItem*>(debug_item.get());
                std::string reg_name = DalvikInstructionParser::format_register(restart_item->register_num, &method);
                debug_line << "    .restart local " << reg_name;
                if (!restart_item->name.empty() || !restart_item->type_descriptor.empty() || !restart_item->signature.empty()) {
                    debug_line << ", ";
                    write_local_info_to_stream(debug_line, restart_item->name, restart_item->type_descriptor, restart_item->signature);
                }
                sort_order = -1;
            } else if (debug_item->type == DebugItem::PROLOGUE_END) {
                debug_line << "    .prologue";
                sort_order = -4;
            } else if (debug_item->type == DebugItem::EPILOGUE_BEGIN) {
                debug_line << "    .epilogue";
                sort_order = -4;
            } else if (debug_item->type == DebugItem::SET_SOURCE_FILE) {
                auto* source_item = static_cast<SetSourceFileItem*>(debug_item.get());
                debug_line << "    .source \"" << source_item->source_file << "\"";
                sort_order = -3;
            }

            // Store register number for END_LOCAL items to enable proper sorting
            int reg_num = (debug_item->type == DebugItem::END_LOCAL) ?
                         static_cast<EndLocalItem*>(debug_item.get())->register_num : -1;
            items.push_back({debug_item->address, sort_order, debug_line.str(), reg_num});
        }

        // Sort by address first, then by sort order, then by register order for END_LOCAL (matching Java baksmali behavior)
        std::sort(items.begin(), items.end(), [&](const MethodItem& a, const MethodItem& b) {
            if (a.address != b.address) {
                return a.address < b.address;
            }
            if (a.sort_order != b.sort_order) {
                return a.sort_order < b.sort_order;
            }
            // For END_LOCAL items with same address and sort_order, sort by ascending register number
            if (a.sort_order == -1 && a.register_num != -1 && b.register_num != -1) {
                return a.register_num < b.register_num;  // Ascending order
            }
            return false;  // Maintain stable order for other items
        });

        // Output the combined items
        output << "\n";
        for (const auto& item : items) {
            output << item.text << "\n";
        }
    } else {
        // Simple output without debug info - match Java baksmali spacing behavior
        output << "\n";
        const auto& instructions = method.code->instructions;
        for (size_t i = 0; i < instructions.size(); ++i) {
            std::string formatted_instruction = DalvikInstructionParser::reformat_registers_for_method(
                instructions[i].mnemonic, method.code->registers_size, method.code->ins_size);
            output << "    " << formatted_instruction << "\n";

            // Add blank line after every instruction except the last one (matching Java baksmali behavior)
            if (i != instructions.size() - 1) {
                output << "\n";
            }
        }
    }
}

void ClassDefinition::write_debug_items(std::ostream& output, const std::vector<std::unique_ptr<DebugItem>>& debug_items) {
    for (const auto& debug_item : debug_items) {
        if (debug_item->type == DebugItem::START_LOCAL) {
            auto* start_item = static_cast<StartLocalItem*>(debug_item.get());
            output << "    .local v" << start_item->register_num;
            if (!start_item->name.empty() || !start_item->type_descriptor.empty() || !start_item->signature.empty()) {
                output << ", ";
                write_local_info(output, start_item->name, start_item->type_descriptor, start_item->signature);
            }
            output << "\n";
        } else if (debug_item->type == DebugItem::END_LOCAL) {
            auto* end_item = static_cast<EndLocalItem*>(debug_item.get());
            output << "    .end local v" << end_item->register_num;
            if (!end_item->name.empty() || !end_item->type_descriptor.empty() || !end_item->signature.empty()) {
                output << "    # ";
                write_local_info(output, end_item->name, end_item->type_descriptor, end_item->signature);
            }
            output << "\n";
        } else if (debug_item->type == DebugItem::LINE_NUMBER) {
            auto* line_item = static_cast<LineNumberItem*>(debug_item.get());
            output << "    .line " << line_item->line_number << "\n";
        }
    }
}

void ClassDefinition::write_local_info(std::ostream& output, const std::string& name,
                                       const std::string& type, const std::string& signature) {
    write_local_info_to_stream(output, name, type, signature);
}

void ClassDefinition::write_local_info_to_stream(std::ostream& output, const std::string& name,
                                                  const std::string& type, const std::string& signature) {
    if (!name.empty()) {
        output << "\"" << name << "\"";
    } else {
        output << "null";
    }
    output << ":";
    if (!type.empty()) {
        output << type;
    } else {
        output << "V";
    }
    if (!signature.empty()) {
        output << ", \"" << signature << "\"";
    }
}
