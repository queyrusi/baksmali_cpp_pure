#include "dex_file.hpp"
#include "dex_structures.hpp"
#include "dalvik_opcodes.hpp"
#include <fstream>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <map>
#include <sstream>

// Utility function to escape strings for smali output
std::string escape_string_for_smali(const std::string& str) {
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

        // Check if this is already an escaped sequence
        if (c == '\\' && i + 1 < str.length()) {
            char next = str[i + 1];
            // If it's already a valid escape sequence, keep it as-is
            if (next == 'n' || next == 'r' || next == 't' ||
                next == '"' || next == '\'' || next == '\\') {
                result += c;
                result += next;
                ++i;
                continue;
            } else if (next == 'u' && i + 5 < str.length()) {
                bool isValidUnicode = true;
                for (size_t j = 2; j <= 5; ++j) {
                    char hex = str[i + j];
                    if (!((hex >= '0' && hex <= '9') ||
                          (hex >= 'a' && hex <= 'f') ||
                          (hex >= 'A' && hex <= 'F'))) {
                        isValidUnicode = false;
                        break;
                    }
                }

                if (isValidUnicode) {
                    result += '\\';
                    result += 'u';
                    result.append(str, i + 2, 4);
                    i += 5;
                    continue;
                }
            }
        }

        // Only escape actual control characters, not already-escaped sequences
        switch (c) {
            case '"': result += "\\\""; break;
            case '\'': result += "\\'"; break;
            case '\\': result += "\\\\"; break;  // Standard escaping: \\ -> \\\\\n            case '\t': result += "\\t"; break;
            default: result += c; break;
        }
    }

    return result;
}

std::unique_ptr<DexFile> DexFile::open(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file: " << filename << std::endl;
        return nullptr;
    }
    
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    auto dex_file = std::unique_ptr<DexFile>(new DexFile());
    dex_file->file_data_.resize(size);
    
    if (!file.read(reinterpret_cast<char*>(dex_file->file_data_.data()), size)) {
        std::cerr << "Error: Cannot read file: " << filename << std::endl;
        return nullptr;
    }
    
    if (!dex_file->parse_header()) {
        return nullptr;
    }
    
    if (!dex_file->parse_string_ids() ||
        !dex_file->parse_type_ids() ||
        !dex_file->parse_proto_ids() ||
        !dex_file->parse_field_ids() ||
        !dex_file->parse_method_ids() ||
        !dex_file->parse_class_defs()) {
        return nullptr;
    }
    
    return dex_file;
}

DexFile::~DexFile() = default;

bool DexFile::parse_header() {
    if (file_data_.size() < sizeof(DexHeader)) {
        std::cerr << "Error: File too small for DEX header" << std::endl;
        return false;
    }
    
    header_ = std::make_unique<DexHeader>();
    std::memcpy(header_.get(), file_data_.data(), sizeof(DexHeader));
    
    // Validate magic number
    if (std::memcmp(header_->magic, DEX_FILE_MAGIC_V035, 8) != 0 &&
        std::memcmp(header_->magic, DEX_FILE_MAGIC_V037, 8) != 0 &&
        std::memcmp(header_->magic, DEX_FILE_MAGIC_V038, 8) != 0 &&
        std::memcmp(header_->magic, DEX_FILE_MAGIC_V039, 8) != 0) {
        std::cerr << "Error: Invalid DEX magic number" << std::endl;
        return false;
    }
    
    // Validate file size
    if (header_->file_size != file_data_.size()) {
        std::cerr << "Error: DEX file size mismatch" << std::endl;
        return false;
    }
    
    // Validate header size
    if (header_->header_size != sizeof(DexHeader)) {
        std::cerr << "Error: Invalid DEX header size" << std::endl;
        return false;
    }
    
    return true;
}

// ULEB128 decoder
uint32_t decode_uleb128(const uint8_t*& ptr) {
    uint32_t result = 0;
    int shift = 0;
    uint8_t byte;
    
    do {
        byte = *ptr++;
        result |= (byte & 0x7F) << shift;
        shift += 7;
    } while (byte & 0x80);
    
    return result;
}

bool DexFile::parse_string_ids() {
    if (header_->string_ids_size == 0) {
        return true;
    }
    
    const uint8_t* data = file_data_.data() + header_->string_ids_off;
    strings_.reserve(header_->string_ids_size);
    
    for (uint32_t i = 0; i < header_->string_ids_size; ++i) {
        // Bounds check for string ID array access
        if (header_->string_ids_off + (i + 1) * sizeof(DexStringId) > file_data_.size()) {
            std::cerr << "Error: String ID array access out of bounds" << std::endl;
            return false;
        }
        
        const DexStringId* string_id = reinterpret_cast<const DexStringId*>(data + i * sizeof(DexStringId));
        
        if (string_id->string_data_off >= file_data_.size()) {
            std::cerr << "Error: Invalid string data offset" << std::endl;
            return false;
        }
        
        const uint8_t* string_data = file_data_.data() + string_id->string_data_off;
        const uint8_t* ptr = string_data;
        uint32_t utf16_size = decode_uleb128(ptr);

        // Read the UTF-8 string safely - ptr now points past the ULEB128
        const char* str_start = reinterpret_cast<const char*>(ptr);
        const char* file_end = reinterpret_cast<const char*>(file_data_.data() + file_data_.size());
        size_t max_len = file_end - str_start;
        size_t str_len = strnlen(str_start, max_len);

        if (str_start + str_len >= file_end) {
            std::cerr << "Error: String extends beyond file boundary" << std::endl;
            return false;
        }

        // Convert non-ASCII characters to Unicode escape sequences (matching Java baksmali behavior)
        std::string str;
        str.reserve(str_len * 2); // Reserve space for potential escaping

        // Debug output removed for production

        for (size_t j = 0; j < str_len; ++j) {
            unsigned char c = static_cast<unsigned char>(str_start[j]);

            if (c < 0x80) {
                // ASCII character - add as-is
                str.push_back(c);
            } else {
                // Non-ASCII UTF-8 sequence - convert to Unicode escape
                // Handle UTF-8 decoding to get the Unicode code point
                uint32_t codepoint = 0;
                size_t remaining = str_len - j;

                if ((c & 0xE0) == 0xC0 && remaining >= 2) {
                    // 2-byte UTF-8 sequence
                    codepoint = ((c & 0x1F) << 6) | (str_start[j + 1] & 0x3F);
                    j += 1;
                } else if ((c & 0xF0) == 0xE0 && remaining >= 3) {
                    // 3-byte UTF-8 sequence
                    codepoint = ((c & 0x0F) << 12) | ((str_start[j + 1] & 0x3F) << 6) | (str_start[j + 2] & 0x3F);
                    j += 2;
                } else if ((c & 0xF8) == 0xF0 && remaining >= 4) {
                    // 4-byte UTF-8 sequence
                    codepoint = ((c & 0x07) << 18) | ((str_start[j + 1] & 0x3F) << 12) | ((str_start[j + 2] & 0x3F) << 6) | (str_start[j + 3] & 0x3F);
                    j += 3;
                } else {
                    // Invalid UTF-8 or truncated - treat as single byte
                    codepoint = c;
                }

                // Format as Unicode escape sequence
                char escape[7];
                snprintf(escape, sizeof(escape), "\\u%04x", codepoint & 0xFFFF);
                str.append(escape);
            }
        }

        strings_.push_back(std::move(str));
    }
    
    return true;
}

bool DexFile::parse_type_ids() {
    if (header_->type_ids_size == 0) {
        return true;
    }
    
    const uint8_t* data = file_data_.data() + header_->type_ids_off;
    type_names_.reserve(header_->type_ids_size);
    
    for (uint32_t i = 0; i < header_->type_ids_size; ++i) {
        // Bounds check for type ID array access
        if (header_->type_ids_off + (i + 1) * sizeof(DexTypeId) > file_data_.size()) {
            std::cerr << "Error: Type ID array access out of bounds" << std::endl;
            return false;
        }
        
        const DexTypeId* type_id = reinterpret_cast<const DexTypeId*>(data + i * sizeof(DexTypeId));
        
        if (type_id->descriptor_idx >= strings_.size()) {
            std::cerr << "Error: Invalid type descriptor index: " << type_id->descriptor_idx << " >= " << strings_.size() << std::endl;
            return false;
        }
        
        type_names_.push_back(strings_[type_id->descriptor_idx]);
    }
    
    return true;
}

bool DexFile::parse_proto_ids() {
    if (header_->proto_ids_size == 0) {
        return true;
    }
    
    const uint8_t* data = file_data_.data() + header_->proto_ids_off;
    proto_signatures_.reserve(header_->proto_ids_size);
    
    for (uint32_t i = 0; i < header_->proto_ids_size; ++i) {
        const DexProtoId* proto_id = reinterpret_cast<const DexProtoId*>(data + i * sizeof(DexProtoId));
        
        std::string signature = "(";
        
        // Parse parameters
        if (proto_id->parameters_off != 0) {
            const uint8_t* param_data = file_data_.data() + proto_id->parameters_off;
            uint32_t param_count = *reinterpret_cast<const uint32_t*>(param_data);
            param_data += sizeof(uint32_t);
            
            for (uint32_t j = 0; j < param_count; ++j) {
                uint16_t type_idx = *reinterpret_cast<const uint16_t*>(param_data);
                param_data += sizeof(uint16_t);
                
                if (type_idx < type_names_.size()) {
                    signature += type_names_[type_idx];
                }
            }
        }
        
        signature += ")";
        
        // Add return type
        if (proto_id->return_type_idx < type_names_.size()) {
            signature += type_names_[proto_id->return_type_idx];
        }
        
        proto_signatures_.push_back(signature);
    }
    
    return true;
}

bool DexFile::parse_field_ids() {
    if (header_->field_ids_size == 0) {
        return true;
    }
    
    const uint8_t* data = file_data_.data() + header_->field_ids_off;
    field_names_.reserve(header_->field_ids_size);
    
    for (uint32_t i = 0; i < header_->field_ids_size; ++i) {
        const DexFieldId* field_id = reinterpret_cast<const DexFieldId*>(data + i * sizeof(DexFieldId));
        
        if (field_id->name_idx >= strings_.size()) {
            std::cerr << "Error: Invalid field name index" << std::endl;
            return false;
        }
        
        field_names_.push_back(strings_[field_id->name_idx]);
    }
    
    return true;
}

bool DexFile::parse_method_ids() {
    if (header_->method_ids_size == 0) {
        return true;
    }
    
    const uint8_t* data = file_data_.data() + header_->method_ids_off;
    method_names_.reserve(header_->method_ids_size);
    
    for (uint32_t i = 0; i < header_->method_ids_size; ++i) {
        const DexMethodId* method_id = reinterpret_cast<const DexMethodId*>(data + i * sizeof(DexMethodId));
        
        if (method_id->name_idx >= strings_.size()) {
            std::cerr << "Error: Invalid method name index" << std::endl;
            return false;
        }
        
        method_names_.push_back(strings_[method_id->name_idx]);
    }
    
    return true;
}

bool DexFile::parse_class_defs() {
    if (header_->class_defs_size == 0) {
        return true;
    }
    
    const uint8_t* data = file_data_.data() + header_->class_defs_off;
    classes_.reserve(header_->class_defs_size);
    
    for (uint32_t i = 0; i < header_->class_defs_size; ++i) {
        const DexClassDef* class_def = reinterpret_cast<const DexClassDef*>(data + i * sizeof(DexClassDef));
        
        DexClass dex_class;
        dex_class.class_idx = class_def->class_idx;
        dex_class.access_flags = class_def->access_flags;
        
        if (class_def->class_idx < type_names_.size()) {
            dex_class.class_name = type_names_[class_def->class_idx];
        }
        
        if (class_def->superclass_idx != 0xFFFFFFFF && class_def->superclass_idx < type_names_.size()) {
            dex_class.superclass_name = type_names_[class_def->superclass_idx];
        }
        
        if (class_def->source_file_idx != 0xFFFFFFFF && class_def->source_file_idx < strings_.size()) {
            dex_class.source_file = strings_[class_def->source_file_idx];
        }
        
        // Parse interfaces
        if (class_def->interfaces_off != 0) {
            parse_interfaces(class_def->interfaces_off, dex_class);
        }
        
        // Parse class data (fields and methods)
        if (class_def->class_data_off != 0) {
            parse_class_data(class_def->class_data_off, dex_class);
        }
        
        // Parse annotations
        if (class_def->annotations_off != 0) {
            parse_annotations_directory(class_def->annotations_off, dex_class);
        }

        // Parse static values to get initial values for static final fields
        if (class_def->static_values_off != 0) {
            parse_static_values(class_def->static_values_off, dex_class);
        }

        classes_.push_back(std::move(dex_class));
    }
    
    // Add annotations after all classes are parsed
    for (auto& dex_class : classes_) {
        add_member_classes_annotation(dex_class);
    }
    
    return true;
}

std::string DexFile::get_string(uint32_t string_idx) const {
    if (string_idx >= strings_.size()) {
        return "";
    }
    return strings_[string_idx];
}

std::string DexFile::get_type_name(uint32_t type_idx) const {
    if (type_idx >= type_names_.size()) {
        return "";
    }
    return type_names_[type_idx];
}

std::string DexFile::get_method_name(uint32_t method_idx) const {
    if (method_idx >= method_names_.size()) {
        return "";
    }
    return method_names_[method_idx];
}

std::string DexFile::get_field_name(uint32_t field_idx) const {
    if (field_idx >= field_names_.size()) {
        return "";
    }
    return field_names_[field_idx];
}

std::string DexFile::get_method_reference(uint32_t method_idx) const {
    if (method_idx >= header_->method_ids_size) {
        return "";
    }
    
    const uint8_t* method_data = file_data_.data() + header_->method_ids_off + method_idx * sizeof(DexMethodId);
    const DexMethodId* method_id = reinterpret_cast<const DexMethodId*>(method_data);
    
    std::string result;
    
    // Add class name
    if (method_id->class_idx < type_names_.size()) {
        result += type_names_[method_id->class_idx];
    }
    
    result += "->";
    
    // Add method name
    if (method_id->name_idx < strings_.size()) {
        result += strings_[method_id->name_idx];
    }
    
    // Add signature
    if (method_id->proto_idx < proto_signatures_.size()) {
        result += proto_signatures_[method_id->proto_idx];
    }
    
    return result;
}

std::string DexFile::get_field_reference(uint32_t field_idx) const {
    if (field_idx >= header_->field_ids_size) {
        return "";
    }
    
    const uint8_t* field_data = file_data_.data() + header_->field_ids_off + field_idx * sizeof(DexFieldId);
    const DexFieldId* field_id = reinterpret_cast<const DexFieldId*>(field_data);
    
    std::string result;
    
    // Add class name
    if (field_id->class_idx < type_names_.size()) {
        result += type_names_[field_id->class_idx];
    }
    
    result += "->";
    
    // Add field name
    if (field_id->name_idx < strings_.size()) {
        result += strings_[field_id->name_idx];
    }
    
    result += ":";
    
    // Add field type
    if (field_id->type_idx < type_names_.size()) {
        result += type_names_[field_id->type_idx];
    }
    
    return result;
}

bool DexFile::parse_interfaces(uint32_t interfaces_off, DexClass& dex_class) {
    if (interfaces_off >= file_data_.size()) {
        return false;
    }
    
    const uint8_t* ptr = file_data_.data() + interfaces_off;
    uint32_t size = *reinterpret_cast<const uint32_t*>(ptr);
    ptr += sizeof(uint32_t);
    
    for (uint32_t i = 0; i < size; ++i) {
        uint16_t type_idx = *reinterpret_cast<const uint16_t*>(ptr);
        ptr += sizeof(uint16_t);
        
        if (type_idx < type_names_.size()) {
            dex_class.interfaces.push_back(type_names_[type_idx]);
        }
    }
    
    return true;
}

bool DexFile::parse_class_data(uint32_t class_data_off, DexClass& dex_class) {
    if (class_data_off >= file_data_.size()) {
        return false;
    }
    
    const uint8_t* ptr = file_data_.data() + class_data_off;
    
    // Read ULEB128 counts
    uint32_t static_fields_size = decode_uleb128(ptr);
    uint32_t instance_fields_size = decode_uleb128(ptr);
    uint32_t direct_methods_size = decode_uleb128(ptr);
    uint32_t virtual_methods_size = decode_uleb128(ptr);
    
    // Parse static fields
    if (!parse_encoded_fields(ptr, static_fields_size, dex_class.static_fields, true)) {
        return false;
    }
    
    // Parse instance fields
    if (!parse_encoded_fields(ptr, instance_fields_size, dex_class.instance_fields, false)) {
        return false;
    }
    
    // Parse direct methods
    if (!parse_encoded_methods(ptr, direct_methods_size, dex_class.direct_methods, true)) {
        return false;
    }
    
    // Parse virtual methods
    if (!parse_encoded_methods(ptr, virtual_methods_size, dex_class.virtual_methods, false)) {
        return false;
    }
    
    return true;
}

bool DexFile::parse_encoded_fields(const uint8_t*& ptr, uint32_t count, std::vector<DexField>& fields, bool is_static) {
    fields.reserve(count);
    uint32_t field_idx = 0;
    
    for (uint32_t i = 0; i < count; ++i) {
        DexField field;
        
        uint32_t field_idx_diff = decode_uleb128(ptr);
        field_idx += field_idx_diff;
        field.field_idx = field_idx;
        
        field.access_flags = decode_uleb128(ptr);
        
        // Get field information from field_ids
        if (field_idx < header_->field_ids_size) {
            const uint8_t* field_data = file_data_.data() + header_->field_ids_off + field_idx * sizeof(DexFieldId);
            const DexFieldId* field_id = reinterpret_cast<const DexFieldId*>(field_data);
            
            if (field_id->name_idx < strings_.size()) {
                field.name = strings_[field_id->name_idx];
            }
            
            if (field_id->type_idx < type_names_.size()) {
                field.type = type_names_[field_id->type_idx];
            }
            
            if (field_id->class_idx < type_names_.size()) {
                field.class_name = type_names_[field_id->class_idx];
            }
        }
        
        fields.push_back(std::move(field));
    }
    
    return true;
}

bool DexFile::parse_encoded_methods(const uint8_t*& ptr, uint32_t count, std::vector<DexMethod>& methods, bool is_direct) {
    methods.reserve(count);
    uint32_t method_idx = 0;
    
    for (uint32_t i = 0; i < count; ++i) {
        DexMethod method;
        
        uint32_t method_idx_diff = decode_uleb128(ptr);
        method_idx += method_idx_diff;
        method.method_idx = method_idx;
        
        method.access_flags = decode_uleb128(ptr);
        uint32_t code_off = decode_uleb128(ptr);
        
        // Get method information from method_ids
        if (method_idx < header_->method_ids_size) {
            const uint8_t* method_data = file_data_.data() + header_->method_ids_off + method_idx * sizeof(DexMethodId);
            const DexMethodId* method_id = reinterpret_cast<const DexMethodId*>(method_data);
            
            if (method_id->name_idx < strings_.size()) {
                method.name = strings_[method_id->name_idx];
            }
            
            if (method_id->class_idx < type_names_.size()) {
                method.class_name = type_names_[method_id->class_idx];
            }
            
            // Get method signature from proto_id
            if (method_id->proto_idx < proto_signatures_.size()) {
                method.signature = proto_signatures_[method_id->proto_idx];
            } else {
                method.signature = "()V"; // Fallback
            }
        }
        
        // Parse code if present
        if (code_off != 0 && code_off < file_data_.size()) {
            method.code = parse_code_item(code_off, &method);
        }
        
        methods.push_back(std::move(method));
    }
    
    return true;
}

std::unique_ptr<DexCode> DexFile::parse_code_item(uint32_t code_off, DexMethod* method_context) {
    if (code_off >= file_data_.size()) {
        return nullptr;
    }
    
    const uint8_t* ptr = file_data_.data() + code_off;
    const DexCodeItem* code_header = reinterpret_cast<const DexCodeItem*>(ptr);
    
    auto code = std::make_unique<DexCode>();
    code->registers_size = code_header->registers_size;
    code->ins_size = code_header->ins_size;
    code->outs_size = code_header->outs_size;
    code->tries_size = code_header->tries_size;
    code->debug_info_off = code_header->debug_info_off;
    code->insns_size = code_header->insns_size;
    
    // Parse instructions
    if (code_header->insns_size > 0) {
        // Skip past the fixed-size code_item header (16 bytes)
        // registers_size(2) + ins_size(2) + outs_size(2) + tries_size(2) + debug_info_off(4) + insns_size(4) = 16
        const uint16_t* insns = reinterpret_cast<const uint16_t*>(ptr + 16);
        parse_instructions(insns, code_header->insns_size, code->instructions);
    }

    // Parse debug info if available
    if (code_header->debug_info_off != 0) {
        parse_debug_info(code_header->debug_info_off, *code, method_context);
    }

    return code;
}

void DexFile::parse_instructions(const uint16_t* insns, uint32_t insns_size, std::vector<DexInstruction>& instructions) {
    uint32_t offset = 0;
    
    while (offset < insns_size) {
        DexInstruction instruction;
        instruction.address = offset; // Debug info uses code units, keep same scale
        instruction.opcode = insns[offset] & 0xFF;
        
        int width = DalvikInstructionParser::get_instruction_width(instruction.opcode);
        
        // Store raw instruction data
        instruction.operands.clear();
        for (int i = 0; i < width && (offset + i) < insns_size; ++i) {
            instruction.operands.push_back(insns[offset + i]);
        }
        
        // Format the instruction mnemonic
        instruction.mnemonic = DalvikInstructionParser::format_instruction(&insns[offset], instruction.address, this);
        
        instructions.push_back(instruction);
        offset += width;
    }
}

void DexFile::parse_debug_info(uint32_t debug_info_off, DexCode& code, const DexMethod* method_context) {
    if (debug_info_off >= file_data_.size()) {
        return;
    }

    const uint8_t* ptr = file_data_.data() + debug_info_off;
    const uint8_t* end = file_data_.data() + file_data_.size();

    uint32_t line_start = decode_uleb128(ptr);
    uint32_t parameters_size = decode_uleb128(ptr);

    std::vector<std::string> parameter_names;
    parameter_names.reserve(parameters_size);
    for (uint32_t i = 0; i < parameters_size; ++i) {
        uint32_t name_idx = decode_uleb128(ptr);
        if (name_idx != 0 && name_idx <= strings_.size()) {
            parameter_names.push_back(strings_[name_idx - 1]);
        } else {
            parameter_names.emplace_back();
        }
    }

    auto parse_parameter_types = [](const std::string& proto) {
        std::vector<std::string> types;
        if (proto.empty()) {
            return types;
        }
        auto paren_pos = proto.find('(');
        if (paren_pos == std::string::npos) {
            return types;
        }
        size_t index = paren_pos + 1;
        while (index < proto.size() && proto[index] != ')') {
            size_t type_start = index;
            while (index < proto.size() && proto[index] == '[') {
                ++index;
            }
            if (index >= proto.size()) {
                break;
            }
            if (proto[index] == 'L') {
                size_t semi = proto.find(';', index);
                if (semi == std::string::npos) {
                    break;
                }
                index = semi + 1;
            } else {
                ++index;
            }
            types.push_back(proto.substr(type_start, index - type_start));
        }
        return types;
    };

    std::vector<std::string> parameter_types;
    if (method_context) {
        parameter_types = parse_parameter_types(method_context->signature);
    }

    enum class LocalKind {
        NONE,
        START,
        END,
        RESTART
    };

    struct LocalState {
        std::string name;
        std::string type_descriptor;
        std::string signature;
        LocalKind kind = LocalKind::NONE;
    };

    size_t register_count = code.registers_size;
    std::vector<LocalState> locals(register_count);
    LocalState empty_state;
    std::fill(locals.begin(), locals.end(), empty_state);

    int parameter_index = 0;
    size_t param_name_index = 0;

    if (method_context && !(method_context->access_flags & ACC_STATIC)) {
        LocalState this_state;
        this_state.name = "this";
        this_state.type_descriptor = method_context->class_name;
        this_state.kind = LocalKind::START;
        if (parameter_index < static_cast<int>(register_count)) {
            locals[parameter_index] = this_state;
        }
        ++parameter_index;
    }

    for (const auto& type : parameter_types) {
        LocalState param_state;
        if (param_name_index < parameter_names.size()) {
            param_state.name = parameter_names[param_name_index];
        }
        ++param_name_index;
        param_state.type_descriptor = type;
        param_state.kind = LocalKind::START;
        if (parameter_index < static_cast<int>(register_count)) {
            locals[parameter_index] = param_state;
        }
        ++parameter_index;
    }

    if (parameter_index < static_cast<int>(register_count)) {
        int local_index = static_cast<int>(register_count) - 1;
        while (--parameter_index > -1) {
            LocalState current = locals[parameter_index];
            bool is_wide = current.type_descriptor == "J" || current.type_descriptor == "D";
            if (is_wide) {
                --local_index;
                if (local_index == parameter_index) {
                    break;
                }
            }
            if (local_index >= 0 && local_index < static_cast<int>(register_count)) {
                locals[local_index] = current;
            }
            locals[parameter_index] = empty_state;
            --local_index;
        }
    }

    uint32_t address = 0;
    int32_t line = static_cast<int32_t>(line_start);

    while (ptr < end) {
        uint8_t opcode = *ptr++;

        switch (opcode) {
            case DBG_END_SEQUENCE:
                return;

            case DBG_ADVANCE_PC: {
                uint32_t addr_diff = decode_uleb128(ptr);
                address += addr_diff;
                break;
            }

            case DBG_ADVANCE_LINE: {
                int32_t line_diff = static_cast<int32_t>(decode_uleb128(ptr));
                line += line_diff;
                break;
            }

            case DBG_START_LOCAL: {
                uint32_t register_num = decode_uleb128(ptr);
                uint32_t name_idx = decode_uleb128(ptr);
                uint32_t type_idx = decode_uleb128(ptr);

                std::string name = (name_idx != 0 && name_idx <= strings_.size()) ? strings_[name_idx - 1] : "";
                std::string type = (type_idx != 0 && type_idx <= type_names_.size()) ? type_names_[type_idx - 1] : "";

                if (register_num < locals.size()) {
                    locals[register_num] = {name, type, "", LocalKind::START};
                }

                auto item = std::make_unique<StartLocalItem>(address, register_num, name, type);
                code.debug_items.push_back(std::move(item));
                break;
            }

            case DBG_START_LOCAL_EXTENDED: {
                uint32_t register_num = decode_uleb128(ptr);
                uint32_t name_idx = decode_uleb128(ptr);
                uint32_t type_idx = decode_uleb128(ptr);
                uint32_t sig_idx = decode_uleb128(ptr);

                std::string name = (name_idx != 0 && name_idx <= strings_.size()) ? strings_[name_idx - 1] : "";
                std::string type = (type_idx != 0 && type_idx <= type_names_.size()) ? type_names_[type_idx - 1] : "";
                std::string signature = (sig_idx != 0 && sig_idx <= strings_.size()) ? strings_[sig_idx - 1] : "";

                if (register_num < locals.size()) {
                    locals[register_num] = {name, type, signature, LocalKind::START};
                }

                auto item = std::make_unique<StartLocalItem>(address, register_num, name, type, signature);
                code.debug_items.push_back(std::move(item));
                break;
            }

            case DBG_END_LOCAL: {
                uint32_t register_num = decode_uleb128(ptr);
                LocalState previous_state;
                bool replace_entry = false;

                if (register_num < locals.size()) {
                    previous_state = locals[register_num];
                    replace_entry = (locals[register_num].kind != LocalKind::END);
                }

                LocalState comment_state = replace_entry ? previous_state : LocalState{};

                auto item = std::make_unique<EndLocalItem>(address, register_num,
                                                           comment_state.name,
                                                           comment_state.type_descriptor,
                                                           comment_state.signature);
                code.debug_items.push_back(std::move(item));

                if (replace_entry && register_num < locals.size()) {
                    locals[register_num] = {previous_state.name,
                                            previous_state.type_descriptor,
                                            previous_state.signature,
                                            LocalKind::END};
                }
                break;
            }

            case DBG_RESTART_LOCAL: {
                uint32_t register_num = decode_uleb128(ptr);
                LocalState restart_state;
                if (register_num < locals.size()) {
                    restart_state = locals[register_num];
                }

                auto restart_item = std::make_unique<RestartLocalItem>(address, register_num,
                                                                        restart_state.name,
                                                                        restart_state.type_descriptor,
                                                                        restart_state.signature);
                code.debug_items.push_back(std::move(restart_item));

                if (register_num < locals.size()) {
                    locals[register_num] = {restart_state.name,
                                            restart_state.type_descriptor,
                                            restart_state.signature,
                                            LocalKind::RESTART};
                }
                break;
            }

            case DBG_SET_PROLOGUE_END: {
                auto prologue_item = std::make_unique<PrologueEndItem>(address);
                code.debug_items.push_back(std::move(prologue_item));
                break;
            }

            case DBG_SET_EPILOGUE_BEGIN: {
                auto epilogue_item = std::make_unique<EpilogueBeginItem>(address);
                code.debug_items.push_back(std::move(epilogue_item));
                break;
            }

            case DBG_SET_FILE: {
                uint32_t file_name_idx = decode_uleb128(ptr);
                if (file_name_idx != 0 && file_name_idx <= strings_.size()) {
                    auto source_item = std::make_unique<SetSourceFileItem>(address, strings_[file_name_idx - 1]);
                    code.debug_items.push_back(std::move(source_item));
                }
                break;
            }

            default:
                if (opcode >= DBG_FIRST_SPECIAL) {
                    uint8_t adjusted_opcode = opcode - DBG_FIRST_SPECIAL;
                    int32_t line_diff = (adjusted_opcode % 15) - 4;
                    uint32_t addr_diff = adjusted_opcode / 15;

                    line += line_diff;
                    address += addr_diff;

                    if (line >= 0 && line < 65536) {
                        auto item = std::make_unique<LineNumberItem>(address, static_cast<uint32_t>(line));
                        code.debug_items.push_back(std::move(item));
                    }
                } else {
                    return;
                }
                break;
        }
    }
}

void DexFile::add_member_classes_annotation(DexClass& dex_class) {
    // Look for inner classes that match this class
    std::vector<std::string> member_classes;
    std::string base_name = dex_class.class_name;
    
    // Remove L and ; from class name if present
    if (base_name.length() > 2 && base_name[0] == 'L' && base_name.back() == ';') {
        base_name = base_name.substr(1, base_name.length() - 2);
    }
    
    // Look for classes that start with this class name + "$"
    for (const auto& other_class : classes_) {
        std::string other_name = other_class.class_name;
        if (other_name.length() > 2 && other_name[0] == 'L' && other_name.back() == ';') {
            other_name = other_name.substr(1, other_name.length() - 2);
        }
        
        if (other_name.find(base_name + "$") == 0 && other_name != base_name) {
            member_classes.push_back("L" + other_name + ";");
        }
    }
    
    // Add MemberClasses annotation if we found any
    if (!member_classes.empty()) {
        // Sort member classes: numeric suffixes first (1, 2, 3...), then alphabetic (a, b, c...)
        std::sort(member_classes.begin(), member_classes.end(), [](const std::string& a, const std::string& b) {
            // Extract suffix after last '$'
            auto pos_a = a.rfind('$');
            auto pos_b = b.rfind('$');
            
            if (pos_a != std::string::npos && pos_b != std::string::npos) {
                std::string suffix_a = a.substr(pos_a + 1);
                std::string suffix_b = b.substr(pos_b + 1);
                
                // Remove trailing ';' if present
                if (suffix_a.back() == ';') suffix_a.pop_back();
                if (suffix_b.back() == ';') suffix_b.pop_back();
                
                // Check if both are numeric
                bool is_numeric_a = !suffix_a.empty() && std::all_of(suffix_a.begin(), suffix_a.end(), ::isdigit);
                bool is_numeric_b = !suffix_b.empty() && std::all_of(suffix_b.begin(), suffix_b.end(), ::isdigit);
                
                if (is_numeric_a && is_numeric_b) {
                    return std::stoi(suffix_a) < std::stoi(suffix_b);
                } else if (is_numeric_a && !is_numeric_b) {
                    return true; // numeric comes before alphabetic
                } else if (!is_numeric_a && is_numeric_b) {
                    return false; // alphabetic comes after numeric
                } else {
                    return suffix_a < suffix_b; // both alphabetic, sort alphabetically
                }
            }
            
            return a < b; // fallback to string comparison
        });
        
        DexAnnotation annotation;
        annotation.type = "Ldalvik/annotation/MemberClasses;";
        
        for (const auto& member : member_classes) {
            annotation.elements.push_back({"", member});
        }
        
        dex_class.annotations.push_back(annotation);
    }
}

bool DexFile::parse_annotations_directory(uint32_t annotations_off, DexClass& dex_class) {
    if (annotations_off >= file_data_.size()) {
        return false;
    }
    
    const uint8_t* ptr = file_data_.data() + annotations_off;
    const DexAnnotationsDirectoryItem* dir = reinterpret_cast<const DexAnnotationsDirectoryItem*>(ptr);
    ptr += sizeof(DexAnnotationsDirectoryItem);
    
    // Parse class annotations
    if (dir->class_annotations_off != 0) {
        parse_class_annotations(dir->class_annotations_off, dex_class);
    }
    
    // Parse field annotations
    for (uint32_t i = 0; i < dir->fields_size; ++i) {
        const DexFieldAnnotation* field_ann = reinterpret_cast<const DexFieldAnnotation*>(ptr);
        ptr += sizeof(DexFieldAnnotation);
        
        // Find the corresponding field and add annotations
        for (auto& field : dex_class.static_fields) {
            if (field.field_idx == field_ann->field_idx) {
                parse_field_annotations(field_ann->annotations_off, field_ann->field_idx, field);
                break;
            }
        }
        for (auto& field : dex_class.instance_fields) {
            if (field.field_idx == field_ann->field_idx) {
                parse_field_annotations(field_ann->annotations_off, field_ann->field_idx, field);
                break;
            }
        }
    }
    
    // Parse method annotations
    for (uint32_t i = 0; i < dir->annotated_methods_size; ++i) {
        const DexMethodAnnotation* method_ann = reinterpret_cast<const DexMethodAnnotation*>(ptr);
        ptr += sizeof(DexMethodAnnotation);
        
        // Find the corresponding method and add annotations
        for (auto& method : dex_class.direct_methods) {
            if (method.method_idx == method_ann->method_idx) {
                parse_method_annotations(method_ann->annotations_off, method_ann->method_idx, method);
                break;
            }
        }
        for (auto& method : dex_class.virtual_methods) {
            if (method.method_idx == method_ann->method_idx) {
                parse_method_annotations(method_ann->annotations_off, method_ann->method_idx, method);
                break;
            }
        }
    }
    
    // Skip parameter annotations for now
    ptr += dir->annotated_parameters_size * sizeof(DexParameterAnnotation);
    
    return true;
}

bool DexFile::parse_field_annotations(uint32_t annotations_off, uint32_t field_idx, DexField& field) {
    return parse_annotation_set(annotations_off, field.annotations);
}

bool DexFile::parse_method_annotations(uint32_t annotations_off, uint32_t method_idx, DexMethod& method) {
    return parse_annotation_set(annotations_off, method.annotations);
}

bool DexFile::parse_class_annotations(uint32_t annotations_off, DexClass& dex_class) {
    return parse_annotation_set(annotations_off, dex_class.annotations);
}

bool DexFile::parse_annotation_set(uint32_t annotations_off, std::vector<DexAnnotation>& annotations) {
    if (annotations_off >= file_data_.size()) {
        return false;
    }
    
    const uint8_t* ptr = file_data_.data() + annotations_off;
    const DexAnnotationSetItem* set = reinterpret_cast<const DexAnnotationSetItem*>(ptr);
    ptr += sizeof(DexAnnotationSetItem);
    
    for (uint32_t i = 0; i < set->size; ++i) {
        const DexAnnotationOffItem* off_item = reinterpret_cast<const DexAnnotationOffItem*>(ptr);
        ptr += sizeof(DexAnnotationOffItem);
        
        DexAnnotation annotation;
        if (parse_annotation_item(off_item->annotation_off, annotation)) {
            annotations.push_back(std::move(annotation));
        }
    }
    
    return true;
}

bool DexFile::parse_annotation_item(uint32_t annotation_off, DexAnnotation& annotation) {
    if (annotation_off >= file_data_.size()) {
        return false;
    }
    
    const uint8_t* ptr = file_data_.data() + annotation_off;
    const DexAnnotationItem* item = reinterpret_cast<const DexAnnotationItem*>(ptr);
    ptr += sizeof(DexAnnotationItem);
    
    // Process ALL annotations like Java baksmali - no visibility filtering
    annotation.visibility = item->visibility;

    return parse_encoded_annotation(ptr, annotation);
}

bool DexFile::parse_encoded_annotation(const uint8_t*& ptr, DexAnnotation& annotation) {
    // Parse type_idx (ULEB128)
    uint32_t type_idx = decode_uleb128(ptr);
    if (type_idx < type_names_.size()) {
        annotation.type = type_names_[type_idx];
    }

    // Parse size (ULEB128) - number of name-value pairs
    uint32_t size = decode_uleb128(ptr);

    // Parse elements
    for (uint32_t i = 0; i < size; ++i) {
        // Parse name_idx (ULEB128)
        uint32_t name_idx = decode_uleb128(ptr);
        std::string element_name;
        if (name_idx < strings_.size()) {
            element_name = strings_[name_idx];
        }

        // Parse the encoded value directly - don't assume it's an array
        std::string value = parse_encoded_value(ptr);

        // Store the name-value pair
        annotation.elements.push_back({element_name, value});
    }

    return true;
}

std::vector<std::string> DexFile::parse_encoded_array(const uint8_t*& ptr) {
    uint8_t value_type = *ptr++;
    uint8_t value_arg = (value_type & 0xe0) >> 5;
    value_type &= 0x1f;

    std::vector<std::string> array_values;

    if (value_type == 0x1c) { // VALUE_ARRAY
        uint32_t size = decode_uleb128(ptr);

        for (uint32_t i = 0; i < size; ++i) {
            array_values.push_back(parse_encoded_value(ptr));
        }
    } else {
        // Not an array, just return the single value
        // Move pointer back to re-parse as single value
        --ptr;
        array_values.push_back(parse_encoded_value(ptr));
    }

    return array_values;
}

std::string DexFile::parse_encoded_value(const uint8_t*& ptr) {
    uint8_t value_type = *ptr++;
    uint8_t value_arg = (value_type & 0xe0) >> 5;
    value_type &= 0x1f;
    
    switch (value_type) {
        case 0x17: { // VALUE_STRING
            // Parse string index based on value_arg (size - 1)
            uint32_t string_idx = 0;
            for (int i = 0; i <= value_arg; ++i) {
                string_idx |= static_cast<uint32_t>(*ptr++) << (i * 8);
            }
            
            if (string_idx < strings_.size()) {
                std::string str = strings_[string_idx];
                // Escape control characters and backslashes for smali format
                std::string result;
                result.reserve(str.size() * 2);
                for (size_t i = 0; i < str.size(); ++i) {
                    char ch = str[i];

                    if (ch == '\r') {
                        result += "\\r";
                        if (i + 1 < str.size() && str[i + 1] == '\n') {
                            result += "\\n";
                            ++i;
                        }
                        continue;
                    }
                    if (ch == '\n') {
                        result += "\\n";
                        continue;
                    }
                    if (ch == '\t') {
                        result += "\\t";
                        continue;
                    }

                    if (ch == '\\' && i + 1 < str.size() && str[i + 1] == 'u' && i + 5 < str.size()) {
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

                    if (ch == '"') {
                        result += "\\\"";
                        continue;
                    }
                    if (ch == '\'') {
                        result += "\\'";
                        continue;
                    }
                    if (ch == '\\') {
                        result += "\\\\";
                        continue;
                    }

                    result += ch;
                }
                return "\"" + result + "\"";
            }
            return "\"\"";
        }
        
        case 0x00: { // VALUE_BYTE
            int8_t value = 0;
            for (int i = 0; i <= value_arg; ++i) {
                value |= static_cast<int8_t>(*ptr++) << (i * 8);
            }
            // Sign extend if necessary
            if (value_arg < 0 && (value & (1 << (7 + value_arg * 8)))) {
                value |= ~((1 << (8 + value_arg * 8)) - 1);
            }
            return std::to_string(value) + "t";
        }

        case 0x02: { // VALUE_SHORT
            int16_t value = 0;
            for (int i = 0; i <= value_arg; ++i) {
                value |= static_cast<int16_t>(*ptr++) << (i * 8);
            }
            // Sign extend if necessary
            if (value_arg < 1 && (value & (1 << (7 + value_arg * 8)))) {
                value |= ~((1 << (8 + value_arg * 8)) - 1);
            }
            return std::to_string(value) + "s";
        }

        case 0x03: { // VALUE_CHAR
            uint16_t value = 0;
            for (int i = 0; i <= value_arg; ++i) {
                value |= static_cast<uint16_t>(*ptr++) << (i * 8);
            }
            return std::to_string(value);
        }

        case 0x04: { // VALUE_INT
            int32_t value = 0;
            for (int i = 0; i <= value_arg; ++i) {
                value |= static_cast<int32_t>(*ptr++) << (i * 8);
            }
            // Sign extend if necessary
            if (value_arg < 3 && (value & (1 << (7 + value_arg * 8)))) {
                value |= ~((1 << (8 + value_arg * 8)) - 1);
            }
            // Format as hex to match Java baksmali
            std::ostringstream oss;
            oss << "0x" << std::hex << value;
            return oss.str();
        }

        case 0x06: { // VALUE_LONG
            int64_t value = 0;
            for (int i = 0; i <= value_arg; ++i) {
                value |= static_cast<int64_t>(*ptr++) << (i * 8);
            }
            // Sign extend if necessary
            if (value_arg < 7 && (value & (1LL << (7 + value_arg * 8)))) {
                value |= ~((1LL << (8 + value_arg * 8)) - 1);
            }
            return std::to_string(value) + "L";
        }

        case 0x18: { // VALUE_TYPE (class type)
            uint32_t type_idx = 0;
            for (int i = 0; i <= value_arg; ++i) {
                type_idx |= static_cast<uint32_t>(*ptr++) << (i * 8);
            }
            if (type_idx < type_names_.size()) {
                return type_names_[type_idx];
            }
            return "UnknownType@" + std::to_string(type_idx);
        }

        case 0x1b: { // VALUE_ENUM
            uint32_t field_idx = 0;
            for (int i = 0; i <= value_arg; ++i) {
                field_idx |= static_cast<uint32_t>(*ptr++) << (i * 8);
            }
            return ".enum " + get_field_reference(field_idx);
        }

        case 0x1c: { // VALUE_ARRAY
            uint32_t size = decode_uleb128(ptr);
            if (size == 0) {
                return "{}";
            }

            std::string result = "{\n";
            for (uint32_t i = 0; i < size; ++i) {
                result += "        " + parse_encoded_value(ptr);
                if (i < size - 1) result += ",";
                result += "\n";
            }
            result += "    }";
            return result;
        }

        case 0x1e: { // VALUE_NULL
            return "null";
        }

        case 0x1f: { // VALUE_BOOLEAN
            return (value_arg == 1) ? "true" : "false";
        }

        default: {
            // Skip completely unknown value types
            for (int i = 0; i <= value_arg; ++i) {
                ++ptr;
            }
            return "\"\"";
        }
    }
}

bool DexFile::parse_static_values(uint32_t static_values_off, DexClass& dex_class) {
    if (static_values_off >= file_data_.size()) {
        return false;
    }

    const uint8_t* ptr = file_data_.data() + static_values_off;

    // The static values are stored as an encoded_array_item
    // First ULEB128 is the size (number of values)
    uint32_t size = decode_uleb128(ptr);

    // Match static values to static fields by index
    // The values are in the same order as the static fields
    for (uint32_t i = 0; i < size && i < dex_class.static_fields.size(); ++i) {
        std::string value = parse_encoded_value(ptr);

        // Assign values to all static fields, not just static final
        // This matches Java baksmali behavior more closely
        if (dex_class.static_fields[i].access_flags & ACC_STATIC) {
            dex_class.static_fields[i].initial_value = value;
        }
    }

    return true;
}
