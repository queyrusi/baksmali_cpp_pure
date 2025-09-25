#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

#pragma pack(push, 1)

// DEX file header (108 bytes)
struct DexHeader {
    uint8_t magic[8];           // DEX magic and version
    uint32_t checksum;          // Checksum of rest of file
    uint8_t signature[20];      // SHA-1 signature
    uint32_t file_size;         // Size of entire file
    uint32_t header_size;       // Size of header (should be 0x70)
    uint32_t endian_tag;        // Endianness tag
    uint32_t link_size;         // Size of link section
    uint32_t link_off;          // Offset of link section
    uint32_t map_off;           // Offset of map list
    uint32_t string_ids_size;   // Count of strings in string_ids
    uint32_t string_ids_off;    // Offset of string_ids section
    uint32_t type_ids_size;     // Count of type_ids
    uint32_t type_ids_off;      // Offset of type_ids section
    uint32_t proto_ids_size;    // Count of proto_ids
    uint32_t proto_ids_off;     // Offset of proto_ids section
    uint32_t field_ids_size;    // Count of field_ids
    uint32_t field_ids_off;     // Offset of field_ids section
    uint32_t method_ids_size;   // Count of method_ids
    uint32_t method_ids_off;    // Offset of method_ids section
    uint32_t class_defs_size;   // Count of class_defs
    uint32_t class_defs_off;    // Offset of class_defs section
    uint32_t data_size;         // Size of data section
    uint32_t data_off;          // Offset of data section
};

struct DexStringId {
    uint32_t string_data_off;   // Offset to string data
};

struct DexTypeId {
    uint32_t descriptor_idx;    // Index into string_ids for type descriptor
};

struct DexProtoId {
    uint32_t shorty_idx;        // Index into string_ids for shorty descriptor
    uint32_t return_type_idx;   // Index into type_ids for return type
    uint32_t parameters_off;    // Offset to type_list for parameters
};

struct DexFieldId {
    uint16_t class_idx;         // Index into type_ids for class
    uint16_t type_idx;          // Index into type_ids for field type
    uint32_t name_idx;          // Index into string_ids for field name
};

struct DexMethodId {
    uint16_t class_idx;         // Index into type_ids for class
    uint16_t proto_idx;         // Index into proto_ids for method prototype
    uint32_t name_idx;          // Index into string_ids for method name
};

struct DexClassDef {
    uint32_t class_idx;         // Index into type_ids for this class
    uint32_t access_flags;      // OR of AccessFlags
    uint32_t superclass_idx;    // Index into type_ids for superclass
    uint32_t interfaces_off;    // Offset to type_list for interfaces
    uint32_t source_file_idx;   // Index into string_ids for source file name
    uint32_t annotations_off;   // Offset to annotations_directory_item
    uint32_t class_data_off;    // Offset to class_data_item
    uint32_t static_values_off; // Offset to encoded_array_item
};

struct DexEncodedField {
    uint32_t field_idx_diff;    // ULEB128 field index difference
    uint32_t access_flags;      // ULEB128 access flags
};

struct DexEncodedMethod {
    uint32_t method_idx_diff;   // ULEB128 method index difference
    uint32_t access_flags;      // ULEB128 access flags
    uint32_t code_off;          // ULEB128 offset to code_item
};

struct DexClassData {
    uint32_t static_fields_size;    // ULEB128 count of static fields
    uint32_t instance_fields_size;  // ULEB128 count of instance fields
    uint32_t direct_methods_size;   // ULEB128 count of direct methods
    uint32_t virtual_methods_size;  // ULEB128 count of virtual methods
    // followed by the fields and methods
};

// Raw DEX code_item structure (from file format)
struct DexCodeItem {
    uint16_t registers_size;    // Number of registers used by this code
    uint16_t ins_size;          // Number of words of incoming arguments
    uint16_t outs_size;         // Number of words of outgoing arguments
    uint16_t tries_size;        // Number of try_items for this instance
    uint32_t debug_info_off;    // Offset to debug info sequence
    uint32_t insns_size;        // Size of instruction array in 16-bit units
    // followed by instructions array in the file
};

// Forward declaration first
struct DebugItem;

// Parsed code representation (for our use)
struct DexCode {
    uint16_t registers_size;    // Number of registers used by this code
    uint16_t ins_size;          // Number of words of incoming arguments
    uint16_t outs_size;         // Number of words of outgoing arguments
    uint16_t tries_size;        // Number of try_items for this instance
    uint32_t debug_info_off;    // Offset to debug info sequence
    uint32_t insns_size;        // Size of instruction array in 16-bit units

    std::vector<struct DexInstruction> instructions; // Parsed instructions
    std::vector<std::unique_ptr<DebugItem>> debug_items; // Debug information
};

#pragma pack(pop)

// High-level structures (not packed)
struct DexInstruction {
    uint16_t opcode;
    std::vector<uint32_t> operands;
    uint32_t address;
    std::string mnemonic;
};

// Debug info opcodes (from AOSP)
enum DebugInfoOpcode : uint8_t {
    DBG_END_SEQUENCE = 0x00,
    DBG_ADVANCE_PC = 0x01,
    DBG_ADVANCE_LINE = 0x02,
    DBG_START_LOCAL = 0x03,
    DBG_START_LOCAL_EXTENDED = 0x04,
    DBG_END_LOCAL = 0x05,
    DBG_RESTART_LOCAL = 0x06,
    DBG_SET_PROLOGUE_END = 0x07,
    DBG_SET_EPILOGUE_BEGIN = 0x08,
    DBG_SET_FILE = 0x09,
    DBG_FIRST_SPECIAL = 0x0a
};

// Debug items
struct DebugItem {
    enum Type { START_LOCAL, END_LOCAL, LINE_NUMBER, RESTART_LOCAL, PROLOGUE_END, EPILOGUE_BEGIN, SET_SOURCE_FILE } type;
    uint32_t address;
    int sort_order;
};

struct StartLocalItem : DebugItem {
    uint32_t register_num;
    std::string name;
    std::string type_descriptor;
    std::string signature;

    StartLocalItem(uint32_t addr, uint32_t reg, const std::string& n = "",
                   const std::string& t = "", const std::string& s = "")
        : register_num(reg), name(n), type_descriptor(t), signature(s) {
        type = START_LOCAL;
        address = addr;
        sort_order = 1;
    }
};

struct EndLocalItem : DebugItem {
    uint32_t register_num;
    std::string name;
    std::string type_descriptor;
    std::string signature;

    EndLocalItem(uint32_t addr, uint32_t reg, const std::string& n = "",
                 const std::string& t = "", const std::string& s = "")
        : register_num(reg), name(n), type_descriptor(t), signature(s) {
        type = END_LOCAL;
        address = addr;
        sort_order = 2;
    }
};

struct LineNumberItem : DebugItem {
    uint32_t line_number;

    LineNumberItem(uint32_t addr, uint32_t line) : line_number(line) {
        type = LINE_NUMBER;
        address = addr;
        sort_order = 0;
    }
};

struct RestartLocalItem : DebugItem {
    uint32_t register_num;
    std::string name;
    std::string type_descriptor;
    std::string signature;

    RestartLocalItem(uint32_t addr, uint32_t reg, const std::string& n = "",
                     const std::string& t = "", const std::string& s = "")
        : register_num(reg), name(n), type_descriptor(t), signature(s) {
        type = RESTART_LOCAL;
        address = addr;
        sort_order = 0;
    }
};

struct PrologueEndItem : DebugItem {
    PrologueEndItem(uint32_t addr) {
        type = PROLOGUE_END;
        address = addr;
        sort_order = 0;
    }
};

struct EpilogueBeginItem : DebugItem {
    EpilogueBeginItem(uint32_t addr) {
        type = EPILOGUE_BEGIN;
        address = addr;
        sort_order = 0;
    }
};

struct SetSourceFileItem : DebugItem {
    std::string source_file;

    SetSourceFileItem(uint32_t addr, const std::string& file) : source_file(file) {
        type = SET_SOURCE_FILE;
        address = addr;
        sort_order = 0;
    }
};

// Extend DexCode with debug information (now that DebugItem is defined)
// We need to redefine the instructions and debug_items outside the struct due to C++ limitations

// Simple annotation representation
struct DexAnnotation {
    std::string type;
    uint8_t visibility;  // VISIBILITY_BUILD, VISIBILITY_RUNTIME, or VISIBILITY_SYSTEM
    std::vector<std::pair<std::string, std::string>> elements;
};

struct DexMethod {
    uint32_t method_idx;
    uint32_t access_flags;
    std::unique_ptr<DexCode> code;
    std::string name;
    std::string signature;
    std::string class_name;
    
    // Method annotations
    std::vector<DexAnnotation> annotations;
};

struct DexField {
    uint32_t field_idx;
    uint32_t access_flags;
    std::string name;
    std::string type;
    std::string class_name;
    std::string initial_value;  // For static final fields

    // Field annotations
    std::vector<DexAnnotation> annotations;
};

// DEX annotation structures (packed)
#pragma pack(push, 1)

struct DexAnnotationsDirectoryItem {
    uint32_t class_annotations_off;      // Offset to annotation_set_item for class annotations
    uint32_t fields_size;                // Count of field annotations
    uint32_t annotated_methods_size;     // Count of method annotations  
    uint32_t annotated_parameters_size;  // Count of parameter annotations
    // followed by fields_size field_annotation items
    // followed by annotated_methods_size method_annotation items
    // followed by annotated_parameters_size parameter_annotation items
};

struct DexFieldAnnotation {
    uint32_t field_idx;                  // Index of field being annotated
    uint32_t annotations_off;            // Offset to annotation_set_item
};

struct DexMethodAnnotation {
    uint32_t method_idx;                 // Index of method being annotated  
    uint32_t annotations_off;            // Offset to annotation_set_item
};

struct DexParameterAnnotation {
    uint32_t method_idx;                 // Index of method whose parameters are annotated
    uint32_t annotations_off;            // Offset to annotation_set_ref_list
};

struct DexAnnotationSetItem {
    uint32_t size;                       // Number of entries in this set
    // followed by size annotation_off_item entries
};

struct DexAnnotationOffItem {
    uint32_t annotation_off;             // Offset to annotation_item
};

struct DexAnnotationItem {
    uint8_t visibility;                  // Visibility of annotation (VISIBILITY_*)
    // followed by encoded_annotation
};

#pragma pack(pop)

// Annotation visibility constants
enum AnnotationVisibility : uint8_t {
    VISIBILITY_BUILD = 0x00,    // Build-time only
    VISIBILITY_RUNTIME = 0x01,  // Runtime visible  
    VISIBILITY_SYSTEM = 0x02    // System-level visibility
};

struct DexClass {
    uint32_t class_idx;
    uint32_t access_flags;
    std::string class_name;
    std::string superclass_name;
    std::vector<std::string> interfaces;
    std::string source_file;
    
    std::vector<DexField> static_fields;
    std::vector<DexField> instance_fields;
    std::vector<DexMethod> direct_methods;
    std::vector<DexMethod> virtual_methods;
    
    // Annotations
    std::vector<DexAnnotation> annotations;
};

// Now we can complete DexCode with debug_items (after DebugItem is defined)
// This is a global variable to add to existing DexCode instances
// Actually, let's use a cleaner approach - we'll add the debug_items through a helper method