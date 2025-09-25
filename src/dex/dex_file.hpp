#pragma once

#include "dex_structures.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <memory>

// DEX file format constants (matching AOSP definitions)
constexpr uint32_t DEX_FILE_MAGIC_SIZE = 8;
constexpr char DEX_FILE_MAGIC_V035[] = {'d','e','x','\n','0','3','5','\0'};
constexpr char DEX_FILE_MAGIC_V037[] = {'d','e','x','\n','0','3','7','\0'};
constexpr char DEX_FILE_MAGIC_V038[] = {'d','e','x','\n','0','3','8','\0'};
constexpr char DEX_FILE_MAGIC_V039[] = {'d','e','x','\n','0','3','9','\0'};

// Access flags
enum AccessFlags : uint32_t {
    ACC_PUBLIC = 0x1,
    ACC_PRIVATE = 0x2,
    ACC_PROTECTED = 0x4,
    ACC_STATIC = 0x8,
    ACC_FINAL = 0x10,
    ACC_SYNCHRONIZED = 0x20,
    ACC_VOLATILE = 0x40,
    ACC_BRIDGE = 0x40,
    ACC_TRANSIENT = 0x80,
    ACC_VARARGS = 0x80,
    ACC_NATIVE = 0x100,
    ACC_INTERFACE = 0x200,
    ACC_ABSTRACT = 0x400,
    ACC_STRICT = 0x800,
    ACC_SYNTHETIC = 0x1000,
    ACC_ANNOTATION = 0x2000,
    ACC_ENUM = 0x4000,
    ACC_CONSTRUCTOR = 0x10000,
    ACC_DECLARED_SYNCHRONIZED = 0x20000
};

// Forward declarations
struct DexHeader;
struct DexClass;
struct DexMethod;
struct DexField;
struct DexInstruction;

class DexFile {
public:
    static std::unique_ptr<DexFile> open(const std::string& filename);
    
    ~DexFile();
    
    // Accessors
    const DexHeader& header() const { return *header_; }
    const std::vector<DexClass>& classes() const { return classes_; }
    
    // String retrieval
    std::string get_string(uint32_t string_idx) const;
    std::string get_type_name(uint32_t type_idx) const;
    std::string get_method_name(uint32_t method_idx) const;
    std::string get_field_name(uint32_t field_idx) const;

    // String count getter
    uint32_t get_string_count() const { return strings_.size(); }
    
    // Reference formatting (for smali output)
    std::string get_method_reference(uint32_t method_idx) const;
    std::string get_field_reference(uint32_t field_idx) const;
    
private:
    DexFile() = default;
    
    bool parse_header();
    bool parse_string_ids();
    bool parse_type_ids();
    bool parse_proto_ids();
    bool parse_field_ids();
    bool parse_method_ids();
    bool parse_class_defs();
    
    // Helper methods for detailed parsing
    bool parse_interfaces(uint32_t interfaces_off, DexClass& dex_class);
    bool parse_class_data(uint32_t class_data_off, DexClass& dex_class);
    bool parse_encoded_fields(const uint8_t*& ptr, uint32_t count, std::vector<DexField>& fields, bool is_static);
    bool parse_encoded_methods(const uint8_t*& ptr, uint32_t count, std::vector<DexMethod>& methods, bool is_direct);
    std::unique_ptr<DexCode> parse_code_item(uint32_t code_off, DexMethod* method_context = nullptr);
    void parse_instructions(const uint16_t* insns, uint32_t insns_size, std::vector<DexInstruction>& instructions);
    void parse_debug_info(uint32_t debug_info_off, DexCode& code, const DexMethod* method_context);
    void add_member_classes_annotation(DexClass& dex_class);
    bool parse_static_values(uint32_t static_values_off, DexClass& dex_class);
    
    // Annotation parsing methods
    bool parse_annotations_directory(uint32_t annotations_off, DexClass& dex_class);
    bool parse_field_annotations(uint32_t annotations_off, uint32_t field_idx, DexField& field);
    bool parse_method_annotations(uint32_t annotations_off, uint32_t method_idx, DexMethod& method);
    bool parse_class_annotations(uint32_t annotations_off, DexClass& dex_class);
    bool parse_annotation_set(uint32_t annotations_off, std::vector<DexAnnotation>& annotations);
    bool parse_annotation_item(uint32_t annotation_off, DexAnnotation& annotation);
    bool parse_encoded_annotation(const uint8_t*& ptr, DexAnnotation& annotation);
    std::string parse_encoded_value(const uint8_t*& ptr);
    std::vector<std::string> parse_encoded_array(const uint8_t*& ptr);
    
    std::vector<uint8_t> file_data_;
    std::unique_ptr<DexHeader> header_;
    std::vector<DexClass> classes_;
    
    // String table
    std::vector<std::string> strings_;
    std::vector<std::string> type_names_;
    std::vector<std::string> method_names_;
    std::vector<std::string> field_names_;
    
    // Additional cached data
    std::vector<std::string> proto_signatures_;
};
