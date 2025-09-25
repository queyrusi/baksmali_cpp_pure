#include "dalvik_opcodes.hpp"
#include "dex_file.hpp"
#include "../formatter/baksmali_writer.hpp"
#include <sstream>
#include <iomanip>
#include <iostream>

// Local helper function for string escaping to match Python baksmali behavior
static std::string escape_string_for_smali(const std::string& str) {
    std::string result;
    result.reserve(str.length() * 2);

    for (size_t i = 0; i < str.size(); ++i) {
        char c = str[i];

        if (c == '\r') {
            result += "\\r";
            if (i + 1 < str.size() && str[i + 1] == '\n') {
                result += "\\n";
                ++i;
            }
            continue;
        }
        if (c == '\n') {
            result += "\\n";
            continue;
        }

        if (c == '\\' && i + 1 < str.size() && str[i + 1] == 'u' && i + 5 < str.size()) {
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

const std::unordered_map<uint8_t, std::string> DalvikInstructionParser::opcode_names_ = {
    {OP_NOP, "nop"},
    {OP_MOVE, "move"},
    {OP_MOVE_FROM16, "move/from16"},
    {OP_MOVE_16, "move/16"},
    {OP_MOVE_WIDE, "move-wide"},
    {OP_MOVE_WIDE_FROM16, "move-wide/from16"},
    {OP_MOVE_WIDE_16, "move-wide/16"},
    {OP_MOVE_OBJECT, "move-object"},
    {OP_MOVE_OBJECT_FROM16, "move-object/from16"},
    {OP_MOVE_OBJECT_16, "move-object/16"},
    {OP_MOVE_RESULT, "move-result"},
    {OP_MOVE_RESULT_WIDE, "move-result-wide"},
    {OP_MOVE_RESULT_OBJECT, "move-result-object"},
    {OP_MOVE_EXCEPTION, "move-exception"},
    {OP_RETURN_VOID, "return-void"},
    {OP_RETURN, "return"},
    {OP_RETURN_WIDE, "return-wide"},
    {OP_RETURN_OBJECT, "return-object"},
    {OP_CONST_4, "const/4"},
    {OP_CONST_16, "const/16"},
    {OP_CONST, "const"},
    {OP_CONST_HIGH16, "const/high16"},
    {OP_CONST_WIDE_16, "const-wide/16"},
    {OP_CONST_WIDE_32, "const-wide/32"},
    {OP_CONST_WIDE, "const-wide"},
    {OP_CONST_WIDE_HIGH16, "const-wide/high16"},
    {OP_CONST_STRING, "const-string"},
    {OP_CONST_STRING_JUMBO, "const-string/jumbo"},
    {OP_CONST_CLASS, "const-class"},
    {OP_MONITOR_ENTER, "monitor-enter"},
    {OP_MONITOR_EXIT, "monitor-exit"},
    {OP_CHECK_CAST, "check-cast"},
    {OP_INSTANCE_OF, "instance-of"},
    {OP_ARRAY_LENGTH, "array-length"},
    {OP_NEW_INSTANCE, "new-instance"},
    {OP_NEW_ARRAY, "new-array"},
    {OP_FILLED_NEW_ARRAY, "filled-new-array"},
    {OP_FILLED_NEW_ARRAY_RANGE, "filled-new-array/range"},
    {OP_FILL_ARRAY_DATA, "fill-array-data"},
    {OP_THROW, "throw"},
    {OP_GOTO, "goto"},
    {OP_GOTO_16, "goto/16"},
    {OP_GOTO_32, "goto/32"},
    {OP_PACKED_SWITCH, "packed-switch"},
    {OP_SPARSE_SWITCH, "sparse-switch"},
    {OP_CMPL_FLOAT, "cmpl-float"},
    {OP_CMPG_FLOAT, "cmpg-float"},
    {OP_CMPL_DOUBLE, "cmpl-double"},
    {OP_CMPG_DOUBLE, "cmpg-double"},
    {OP_CMP_LONG, "cmp-long"},
    {OP_IF_EQ, "if-eq"},
    {OP_IF_NE, "if-ne"},
    {OP_IF_LT, "if-lt"},
    {OP_IF_GE, "if-ge"},
    {OP_IF_GT, "if-gt"},
    {OP_IF_LE, "if-le"},
    {OP_IF_EQZ, "if-eqz"},
    {OP_IF_NEZ, "if-nez"},
    {OP_IF_LTZ, "if-ltz"},
    {OP_IF_GEZ, "if-gez"},
    {OP_IF_GTZ, "if-gtz"},
    {OP_IF_LEZ, "if-lez"},
    {OP_AGET, "aget"},
    {OP_AGET_WIDE, "aget-wide"},
    {OP_AGET_OBJECT, "aget-object"},
    {OP_AGET_BOOLEAN, "aget-boolean"},
    {OP_AGET_BYTE, "aget-byte"},
    {OP_AGET_CHAR, "aget-char"},
    {OP_AGET_SHORT, "aget-short"},
    {OP_APUT, "aput"},
    {OP_APUT_WIDE, "aput-wide"},
    {OP_APUT_OBJECT, "aput-object"},
    {OP_APUT_BOOLEAN, "aput-boolean"},
    {OP_APUT_BYTE, "aput-byte"},
    {OP_APUT_CHAR, "aput-char"},
    {OP_APUT_SHORT, "aput-short"},
    {OP_IGET, "iget"},
    {OP_IGET_WIDE, "iget-wide"},
    {OP_IGET_OBJECT, "iget-object"},
    {OP_IGET_BOOLEAN, "iget-boolean"},
    {OP_IGET_BYTE, "iget-byte"},
    {OP_IGET_CHAR, "iget-char"},
    {OP_IGET_SHORT, "iget-short"},
    {OP_IPUT, "iput"},
    {OP_IPUT_WIDE, "iput-wide"},
    {OP_IPUT_OBJECT, "iput-object"},
    {OP_IPUT_BOOLEAN, "iput-boolean"},
    {OP_IPUT_BYTE, "iput-byte"},
    {OP_IPUT_CHAR, "iput-char"},
    {OP_IPUT_SHORT, "iput-short"},
    {OP_SGET, "sget"},
    {OP_SGET_WIDE, "sget-wide"},
    {OP_SGET_OBJECT, "sget-object"},
    {OP_SGET_BOOLEAN, "sget-boolean"},
    {OP_SGET_BYTE, "sget-byte"},
    {OP_SGET_CHAR, "sget-char"},
    {OP_SGET_SHORT, "sget-short"},
    {OP_SPUT, "sput"},
    {OP_SPUT_WIDE, "sput-wide"},
    {OP_SPUT_OBJECT, "sput-object"},
    {OP_SPUT_BOOLEAN, "sput-boolean"},
    {OP_SPUT_BYTE, "sput-byte"},
    {OP_SPUT_CHAR, "sput-char"},
    {OP_SPUT_SHORT, "sput-short"},
    {OP_INVOKE_VIRTUAL, "invoke-virtual"},
    {OP_INVOKE_SUPER, "invoke-super"},
    {OP_INVOKE_DIRECT, "invoke-direct"},
    {OP_INVOKE_STATIC, "invoke-static"},
    {OP_INVOKE_INTERFACE, "invoke-interface"},
    {OP_INVOKE_VIRTUAL_RANGE, "invoke-virtual/range"},
    {OP_INVOKE_SUPER_RANGE, "invoke-super/range"},
    {OP_INVOKE_DIRECT_RANGE, "invoke-direct/range"},
    {OP_INVOKE_STATIC_RANGE, "invoke-static/range"},
    {OP_INVOKE_INTERFACE_RANGE, "invoke-interface/range"},
    
    // Arithmetic operations
    {OP_NEG_INT, "neg-int"}, {OP_NOT_INT, "not-int"}, {OP_NEG_LONG, "neg-long"}, {OP_NOT_LONG, "not-long"},
    {OP_NEG_FLOAT, "neg-float"}, {OP_NEG_DOUBLE, "neg-double"},
    {OP_INT_TO_LONG, "int-to-long"}, {OP_INT_TO_FLOAT, "int-to-float"}, {OP_INT_TO_DOUBLE, "int-to-double"},
    {OP_LONG_TO_INT, "long-to-int"}, {OP_LONG_TO_FLOAT, "long-to-float"}, {OP_LONG_TO_DOUBLE, "long-to-double"},
    {OP_FLOAT_TO_INT, "float-to-int"}, {OP_FLOAT_TO_LONG, "float-to-long"}, {OP_FLOAT_TO_DOUBLE, "float-to-double"},
    {OP_DOUBLE_TO_INT, "double-to-int"}, {OP_DOUBLE_TO_LONG, "double-to-long"}, {OP_DOUBLE_TO_FLOAT, "double-to-float"},
    {OP_INT_TO_BYTE, "int-to-byte"}, {OP_INT_TO_CHAR, "int-to-char"}, {OP_INT_TO_SHORT, "int-to-short"},
    
    // Binary operations
    {OP_ADD_INT, "add-int"}, {OP_SUB_INT, "sub-int"}, {OP_MUL_INT, "mul-int"}, {OP_DIV_INT, "div-int"},
    {OP_REM_INT, "rem-int"}, {OP_AND_INT, "and-int"}, {OP_OR_INT, "or-int"}, {OP_XOR_INT, "xor-int"},
    {OP_SHL_INT, "shl-int"}, {OP_SHR_INT, "shr-int"}, {OP_USHR_INT, "ushr-int"},
    {OP_ADD_LONG, "add-long"}, {OP_SUB_LONG, "sub-long"}, {OP_MUL_LONG, "mul-long"}, {OP_DIV_LONG, "div-long"},
    {OP_REM_LONG, "rem-long"}, {OP_AND_LONG, "and-long"}, {OP_OR_LONG, "or-long"}, {OP_XOR_LONG, "xor-long"},
    {OP_SHL_LONG, "shl-long"}, {OP_SHR_LONG, "shr-long"}, {OP_USHR_LONG, "ushr-long"},
    {OP_ADD_FLOAT, "add-float"}, {OP_SUB_FLOAT, "sub-float"}, {OP_MUL_FLOAT, "mul-float"}, {OP_DIV_FLOAT, "div-float"},
    {OP_REM_FLOAT, "rem-float"}, {OP_ADD_DOUBLE, "add-double"}, {OP_SUB_DOUBLE, "sub-double"}, {OP_MUL_DOUBLE, "mul-double"},
    {OP_DIV_DOUBLE, "div-double"}, {OP_REM_DOUBLE, "rem-double"},
    
    // Binary 2addr operations
    {OP_ADD_INT_2ADDR, "add-int/2addr"}, {OP_SUB_INT_2ADDR, "sub-int/2addr"}, {OP_MUL_INT_2ADDR, "mul-int/2addr"},
    {OP_DIV_INT_2ADDR, "div-int/2addr"}, {OP_REM_INT_2ADDR, "rem-int/2addr"}, {OP_AND_INT_2ADDR, "and-int/2addr"},
    {OP_OR_INT_2ADDR, "or-int/2addr"}, {OP_XOR_INT_2ADDR, "xor-int/2addr"}, {OP_SHL_INT_2ADDR, "shl-int/2addr"},
    {OP_SHR_INT_2ADDR, "shr-int/2addr"}, {OP_USHR_INT_2ADDR, "ushr-int/2addr"},
    {OP_ADD_LONG_2ADDR, "add-long/2addr"}, {OP_SUB_LONG_2ADDR, "sub-long/2addr"}, {OP_MUL_LONG_2ADDR, "mul-long/2addr"},
    {OP_DIV_LONG_2ADDR, "div-long/2addr"}, {OP_REM_LONG_2ADDR, "rem-long/2addr"}, {OP_AND_LONG_2ADDR, "and-long/2addr"},
    {OP_OR_LONG_2ADDR, "or-long/2addr"}, {OP_XOR_LONG_2ADDR, "xor-long/2addr"}, {OP_SHL_LONG_2ADDR, "shl-long/2addr"},
    {OP_SHR_LONG_2ADDR, "shr-long/2addr"}, {OP_USHR_LONG_2ADDR, "ushr-long/2addr"},
    {OP_ADD_FLOAT_2ADDR, "add-float/2addr"}, {OP_SUB_FLOAT_2ADDR, "sub-float/2addr"}, {OP_MUL_FLOAT_2ADDR, "mul-float/2addr"},
    {OP_DIV_FLOAT_2ADDR, "div-float/2addr"}, {OP_REM_FLOAT_2ADDR, "rem-float/2addr"},
    {OP_ADD_DOUBLE_2ADDR, "add-double/2addr"}, {OP_SUB_DOUBLE_2ADDR, "sub-double/2addr"}, {OP_MUL_DOUBLE_2ADDR, "mul-double/2addr"},
    {OP_DIV_DOUBLE_2ADDR, "div-double/2addr"}, {OP_REM_DOUBLE_2ADDR, "rem-double/2addr"},
    
    // Literal operations
    {OP_ADD_INT_LIT16, "add-int/lit16"}, {OP_RSUB_INT, "rsub-int"}, {OP_MUL_INT_LIT16, "mul-int/lit16"},
    {OP_DIV_INT_LIT16, "div-int/lit16"}, {OP_REM_INT_LIT16, "rem-int/lit16"}, {OP_AND_INT_LIT16, "and-int/lit16"},
    {OP_OR_INT_LIT16, "or-int/lit16"}, {OP_XOR_INT_LIT16, "xor-int/lit16"},
    {OP_ADD_INT_LIT8, "add-int/lit8"}, {OP_RSUB_INT_LIT8, "rsub-int/lit8"}, {OP_MUL_INT_LIT8, "mul-int/lit8"},
    {OP_DIV_INT_LIT8, "div-int/lit8"}, {OP_REM_INT_LIT8, "rem-int/lit8"}, {OP_AND_INT_LIT8, "and-int/lit8"},
    {OP_OR_INT_LIT8, "or-int/lit8"}, {OP_XOR_INT_LIT8, "xor-int/lit8"}, {OP_SHL_INT_LIT8, "shl-int/lit8"},
    {OP_SHR_INT_LIT8, "shr-int/lit8"}, {OP_USHR_INT_LIT8, "ushr-int/lit8"},
};

const std::unordered_map<uint8_t, int> DalvikInstructionParser::instruction_widths_ = {
    {OP_NOP, 1}, {OP_MOVE, 1}, {OP_MOVE_FROM16, 2}, {OP_MOVE_16, 3},
    {OP_MOVE_WIDE, 1}, {OP_MOVE_WIDE_FROM16, 2}, {OP_MOVE_WIDE_16, 3},
    {OP_MOVE_OBJECT, 1}, {OP_MOVE_OBJECT_FROM16, 2}, {OP_MOVE_OBJECT_16, 3},
    {OP_MOVE_RESULT, 1}, {OP_MOVE_RESULT_WIDE, 1}, {OP_MOVE_RESULT_OBJECT, 1},
    {OP_MOVE_EXCEPTION, 1}, {OP_RETURN_VOID, 1}, {OP_RETURN, 1},
    {OP_RETURN_WIDE, 1}, {OP_RETURN_OBJECT, 1}, {OP_CONST_4, 1},
    {OP_CONST_16, 2}, {OP_CONST, 3}, {OP_CONST_HIGH16, 2},
    {OP_CONST_WIDE_16, 2}, {OP_CONST_WIDE_32, 3}, {OP_CONST_WIDE, 5},
    {OP_CONST_WIDE_HIGH16, 2}, {OP_CONST_STRING, 2}, {OP_CONST_STRING_JUMBO, 3},
    {OP_CONST_CLASS, 2}, {OP_MONITOR_ENTER, 1}, {OP_MONITOR_EXIT, 1},
    {OP_CHECK_CAST, 2}, {OP_INSTANCE_OF, 2}, {OP_ARRAY_LENGTH, 1},
    {OP_NEW_INSTANCE, 2}, {OP_NEW_ARRAY, 2}, {OP_FILLED_NEW_ARRAY, 3},
    {OP_FILLED_NEW_ARRAY_RANGE, 3}, {OP_FILL_ARRAY_DATA, 3}, {OP_THROW, 1},
    {OP_GOTO, 1}, {OP_GOTO_16, 2}, {OP_GOTO_32, 3}, {OP_PACKED_SWITCH, 3},
    {OP_SPARSE_SWITCH, 3}, {OP_CMPL_FLOAT, 2}, {OP_CMPG_FLOAT, 2},
    {OP_CMPL_DOUBLE, 2}, {OP_CMPG_DOUBLE, 2}, {OP_CMP_LONG, 2},
    {OP_IF_EQ, 2}, {OP_IF_NE, 2}, {OP_IF_LT, 2}, {OP_IF_GE, 2},
    {OP_IF_GT, 2}, {OP_IF_LE, 2}, {OP_IF_EQZ, 2}, {OP_IF_NEZ, 2},
    {OP_IF_LTZ, 2}, {OP_IF_GEZ, 2}, {OP_IF_GTZ, 2}, {OP_IF_LEZ, 2},
    {OP_AGET, 2}, {OP_AGET_WIDE, 2}, {OP_AGET_OBJECT, 2}, {OP_AGET_BOOLEAN, 2},
    {OP_AGET_BYTE, 2}, {OP_AGET_CHAR, 2}, {OP_AGET_SHORT, 2},
    {OP_APUT, 2}, {OP_APUT_WIDE, 2}, {OP_APUT_OBJECT, 2}, {OP_APUT_BOOLEAN, 2},
    {OP_APUT_BYTE, 2}, {OP_APUT_CHAR, 2}, {OP_APUT_SHORT, 2},
    {OP_IGET, 2}, {OP_IGET_WIDE, 2}, {OP_IGET_OBJECT, 2}, {OP_IGET_BOOLEAN, 2},
    {OP_IGET_BYTE, 2}, {OP_IGET_CHAR, 2}, {OP_IGET_SHORT, 2},
    {OP_IPUT, 2}, {OP_IPUT_WIDE, 2}, {OP_IPUT_OBJECT, 2}, {OP_IPUT_BOOLEAN, 2},
    {OP_IPUT_BYTE, 2}, {OP_IPUT_CHAR, 2}, {OP_IPUT_SHORT, 2},
    {OP_SGET, 2}, {OP_SGET_WIDE, 2}, {OP_SGET_OBJECT, 2}, {OP_SGET_BOOLEAN, 2},
    {OP_SGET_BYTE, 2}, {OP_SGET_CHAR, 2}, {OP_SGET_SHORT, 2},
    {OP_SPUT, 2}, {OP_SPUT_WIDE, 2}, {OP_SPUT_OBJECT, 2}, {OP_SPUT_BOOLEAN, 2},
    {OP_SPUT_BYTE, 2}, {OP_SPUT_CHAR, 2}, {OP_SPUT_SHORT, 2},
    {OP_INVOKE_VIRTUAL, 3}, {OP_INVOKE_SUPER, 3}, {OP_INVOKE_DIRECT, 3},
    {OP_INVOKE_STATIC, 3}, {OP_INVOKE_INTERFACE, 3},
    {OP_INVOKE_VIRTUAL_RANGE, 3}, {OP_INVOKE_SUPER_RANGE, 3},
    {OP_INVOKE_DIRECT_RANGE, 3}, {OP_INVOKE_STATIC_RANGE, 3},
    {OP_INVOKE_INTERFACE_RANGE, 3},
    
    // Arithmetic operations (all unary operations are width 1)
    {OP_NEG_INT, 1}, {OP_NOT_INT, 1}, {OP_NEG_LONG, 1}, {OP_NOT_LONG, 1},
    {OP_NEG_FLOAT, 1}, {OP_NEG_DOUBLE, 1},
    {OP_INT_TO_LONG, 1}, {OP_INT_TO_FLOAT, 1}, {OP_INT_TO_DOUBLE, 1},
    {OP_LONG_TO_INT, 1}, {OP_LONG_TO_FLOAT, 1}, {OP_LONG_TO_DOUBLE, 1},
    {OP_FLOAT_TO_INT, 1}, {OP_FLOAT_TO_LONG, 1}, {OP_FLOAT_TO_DOUBLE, 1},
    {OP_DOUBLE_TO_INT, 1}, {OP_DOUBLE_TO_LONG, 1}, {OP_DOUBLE_TO_FLOAT, 1},
    {OP_INT_TO_BYTE, 1}, {OP_INT_TO_CHAR, 1}, {OP_INT_TO_SHORT, 1},
    
    // Binary operations (all binary operations are width 2)
    {OP_ADD_INT, 2}, {OP_SUB_INT, 2}, {OP_MUL_INT, 2}, {OP_DIV_INT, 2},
    {OP_REM_INT, 2}, {OP_AND_INT, 2}, {OP_OR_INT, 2}, {OP_XOR_INT, 2},
    {OP_SHL_INT, 2}, {OP_SHR_INT, 2}, {OP_USHR_INT, 2},
    {OP_ADD_LONG, 2}, {OP_SUB_LONG, 2}, {OP_MUL_LONG, 2}, {OP_DIV_LONG, 2},
    {OP_REM_LONG, 2}, {OP_AND_LONG, 2}, {OP_OR_LONG, 2}, {OP_XOR_LONG, 2},
    {OP_SHL_LONG, 2}, {OP_SHR_LONG, 2}, {OP_USHR_LONG, 2},
    {OP_ADD_FLOAT, 2}, {OP_SUB_FLOAT, 2}, {OP_MUL_FLOAT, 2}, {OP_DIV_FLOAT, 2},
    {OP_REM_FLOAT, 2}, {OP_ADD_DOUBLE, 2}, {OP_SUB_DOUBLE, 2}, {OP_MUL_DOUBLE, 2},
    {OP_DIV_DOUBLE, 2}, {OP_REM_DOUBLE, 2},
    
    // Binary 2addr operations (all width 1)
    {OP_ADD_INT_2ADDR, 1}, {OP_SUB_INT_2ADDR, 1}, {OP_MUL_INT_2ADDR, 1},
    {OP_DIV_INT_2ADDR, 1}, {OP_REM_INT_2ADDR, 1}, {OP_AND_INT_2ADDR, 1},
    {OP_OR_INT_2ADDR, 1}, {OP_XOR_INT_2ADDR, 1}, {OP_SHL_INT_2ADDR, 1},
    {OP_SHR_INT_2ADDR, 1}, {OP_USHR_INT_2ADDR, 1},
    {OP_ADD_LONG_2ADDR, 1}, {OP_SUB_LONG_2ADDR, 1}, {OP_MUL_LONG_2ADDR, 1},
    {OP_DIV_LONG_2ADDR, 1}, {OP_REM_LONG_2ADDR, 1}, {OP_AND_LONG_2ADDR, 1},
    {OP_OR_LONG_2ADDR, 1}, {OP_XOR_LONG_2ADDR, 1}, {OP_SHL_LONG_2ADDR, 1},
    {OP_SHR_LONG_2ADDR, 1}, {OP_USHR_LONG_2ADDR, 1},
    {OP_ADD_FLOAT_2ADDR, 1}, {OP_SUB_FLOAT_2ADDR, 1}, {OP_MUL_FLOAT_2ADDR, 1},
    {OP_DIV_FLOAT_2ADDR, 1}, {OP_REM_FLOAT_2ADDR, 1},
    {OP_ADD_DOUBLE_2ADDR, 1}, {OP_SUB_DOUBLE_2ADDR, 1}, {OP_MUL_DOUBLE_2ADDR, 1},
    {OP_DIV_DOUBLE_2ADDR, 1}, {OP_REM_DOUBLE_2ADDR, 1},
    
    // Literal operations
    {OP_ADD_INT_LIT16, 2}, {OP_RSUB_INT, 2}, {OP_MUL_INT_LIT16, 2},
    {OP_DIV_INT_LIT16, 2}, {OP_REM_INT_LIT16, 2}, {OP_AND_INT_LIT16, 2},
    {OP_OR_INT_LIT16, 2}, {OP_XOR_INT_LIT16, 2},
    {OP_ADD_INT_LIT8, 2}, {OP_RSUB_INT_LIT8, 2}, {OP_MUL_INT_LIT8, 2},
    {OP_DIV_INT_LIT8, 2}, {OP_REM_INT_LIT8, 2}, {OP_AND_INT_LIT8, 2},
    {OP_OR_INT_LIT8, 2}, {OP_XOR_INT_LIT8, 2}, {OP_SHL_INT_LIT8, 2},
    {OP_SHR_INT_LIT8, 2}, {OP_USHR_INT_LIT8, 2},
};

std::string DalvikInstructionParser::get_opcode_name(uint8_t opcode) {
    auto it = opcode_names_.find(opcode);
    if (it != opcode_names_.end()) {
        return it->second;
    }
    std::ostringstream oss;
    oss << "unknown-" << std::hex << (int)opcode;
    return oss.str();
}

int DalvikInstructionParser::get_instruction_width(uint8_t opcode) {
    auto it = instruction_widths_.find(opcode);
    if (it != instruction_widths_.end()) {
        return it->second;
    }
    return 1; // Default width
}

std::string DalvikInstructionParser::format_instruction(const uint16_t* insn, uint32_t address, const DexFile* dex_file) {
    uint8_t opcode = insn[0] & 0xFF;
    std::ostringstream oss;
    
    oss << get_opcode_name(opcode);
    
    // Basic operand extraction (simplified for common cases)
    switch (opcode) {
        case OP_CONST_STRING: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            uint16_t string_idx = insn[1];
            std::string str = dex_file->get_string(string_idx);

            // Debug output removed for production

            // Escape single quotes to match Python baksmali behavior
            oss << " v" << (int)vA << ", \"" << escape_string_for_smali(str) << "\"";
            break;
        }
        
        case OP_NEW_INSTANCE: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            uint16_t type_idx = insn[1];
            oss << " v" << (int)vA << ", " << dex_file->get_type_name(type_idx);
            break;
        }
        
        case OP_CHECK_CAST: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            uint16_t type_idx = insn[1];
            oss << " v" << (int)vA << ", " << dex_file->get_type_name(type_idx);
            break;
        }
        
        case OP_INVOKE_DIRECT:
        case OP_INVOKE_VIRTUAL:
        case OP_INVOKE_SUPER:
        case OP_INVOKE_STATIC:
        case OP_INVOKE_INTERFACE: {
            // Format 35c: [A|G|op BBBB F|E|D|C]
            // A = arg count (4 bits), G = arg5 (4 bits), op = opcode (8 bits)
            // B = method index (16 bits)
            // C-F = arg1-4 (4 bits each)
            uint8_t count = (insn[0] >> 12) & 0x0F;  // A field - argument count
            uint8_t vG = (insn[0] >> 8) & 0x0F;      // G field - 5th argument register
            uint16_t method_idx = insn[1];           // B field - method index
            uint16_t args = insn[2];                 // F|E|D|C fields
            
            oss << " {";
            for (int i = 0; i < count; ++i) {
                if (i > 0) oss << ", ";
                uint8_t reg;
                switch (i) {
                    case 0: reg = args & 0xF; break;           // C
                    case 1: reg = (args >> 4) & 0xF; break;    // D
                    case 2: reg = (args >> 8) & 0xF; break;    // E
                    case 3: reg = (args >> 12) & 0xF; break;   // F
                    case 4: reg = vG; break;                    // G
                    default: reg = 0; break;
                }
                oss << "v" << (int)reg;
            }
            oss << "}, ";
            
            // Get method reference from method_ids table
            oss << dex_file->get_method_reference(method_idx);
            break;
        }
        
        case OP_MOVE:
        case OP_MOVE_OBJECT: {
            uint8_t vA = (insn[0] >> 8) & 0xF;
            uint8_t vB = (insn[0] >> 12) & 0xF;
            oss << " v" << (int)vA << ", v" << (int)vB;
            break;
        }
        
        case OP_MOVE_RESULT:
        case OP_MOVE_RESULT_WIDE:
        case OP_MOVE_RESULT_OBJECT:
        case OP_MOVE_EXCEPTION: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            oss << " v" << (int)vA;
            break;
        }

        case OP_THROW: {
            // Format 11x: [AA|op] vAA
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            oss << " v" << (int)vA;
            break;
        }
        
        case OP_NOP:
            // Format 10x: No operands
            break;

        case OP_FILL_ARRAY_DATA: {
            // Format 31t: [AA|op] BBBB vAA, +BBBB
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            int16_t offset = (int16_t)insn[1]; // Target offset
            oss << " v" << (int)vA << ", :array_" << std::hex << (address + offset);
            break;
        }

        case OP_RETURN_VOID:
            // No operands
            break;
            
        case OP_RETURN:
        case OP_RETURN_WIDE:
        case OP_RETURN_OBJECT: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            oss << " v" << (int)vA;
            break;
        }
            
        case OP_CONST_4: {
            uint8_t vA = (insn[0] >> 8) & 0xF;
            int8_t literal = (int8_t)((insn[0] >> 12) & 0xF);
            if (literal & 0x8) literal |= 0xF0; // Sign extend
            oss << " v" << (int)vA << ", 0x" << std::hex << (int)literal;
            break;
        }
        
        case OP_CONST_16: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            int16_t literal = (int16_t)insn[1];
            oss << " v" << (int)vA << ", 0x" << std::hex << literal;
            break;
        }
        
        case OP_CONST: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            int32_t literal = (int32_t)((uint32_t)insn[1] | ((uint32_t)insn[2] << 16));
            oss << " v" << (int)vA << ", 0x" << std::hex << literal;
            break;
        }

        case OP_CONST_HIGH16: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            int32_t literal = ((int32_t)insn[1]) << 16;
            oss << " v" << (int)vA << ", 0x" << std::hex << literal;
            break;
        }

        case OP_IGET:
        case OP_IGET_WIDE:
        case OP_IGET_OBJECT:
        case OP_IGET_BOOLEAN:
        case OP_IGET_BYTE:
        case OP_IGET_CHAR:
        case OP_IGET_SHORT: {
            uint8_t vA = (insn[0] >> 8) & 0xF;
            uint8_t vB = (insn[0] >> 12) & 0xF;
            uint16_t field_idx = insn[1];
            oss << " v" << (int)vA << ", v" << (int)vB << ", " << dex_file->get_field_reference(field_idx);
            break;
        }
        
        case OP_IPUT:
        case OP_IPUT_WIDE:
        case OP_IPUT_OBJECT:
        case OP_IPUT_BOOLEAN:
        case OP_IPUT_BYTE:
        case OP_IPUT_CHAR:
        case OP_IPUT_SHORT: {
            uint8_t vA = (insn[0] >> 8) & 0xF;
            uint8_t vB = (insn[0] >> 12) & 0xF;
            uint16_t field_idx = insn[1];
            oss << " v" << (int)vA << ", v" << (int)vB << ", " << dex_file->get_field_reference(field_idx);
            break;
        }
        
        case OP_SGET:
        case OP_SGET_WIDE:
        case OP_SGET_OBJECT:
        case OP_SGET_BOOLEAN:
        case OP_SGET_BYTE:
        case OP_SGET_CHAR:
        case OP_SGET_SHORT: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            uint16_t field_idx = insn[1];
            oss << " v" << (int)vA << ", " << dex_file->get_field_reference(field_idx);
            break;
        }
        
        case OP_SPUT:
        case OP_SPUT_WIDE:
        case OP_SPUT_OBJECT:
        case OP_SPUT_BOOLEAN:
        case OP_SPUT_BYTE:
        case OP_SPUT_CHAR:
        case OP_SPUT_SHORT: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            uint16_t field_idx = insn[1];
            oss << " v" << (int)vA << ", " << dex_file->get_field_reference(field_idx);
            break;
        }
        
        case OP_ADD_INT:
        case OP_SUB_INT:
        case OP_MUL_INT:
        case OP_DIV_INT:
        case OP_REM_INT:
        case OP_AND_INT:
        case OP_OR_INT:
        case OP_XOR_INT: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            uint8_t vB = insn[1] & 0xFF;
            uint8_t vC = (insn[1] >> 8) & 0xFF;
            oss << " v" << (int)vA << ", v" << (int)vB << ", v" << (int)vC;
            break;
        }
        
        case OP_ADD_INT_2ADDR:
        case OP_SUB_INT_2ADDR:
        case OP_MUL_INT_2ADDR:
        case OP_DIV_INT_2ADDR:
        case OP_REM_INT_2ADDR:
        case OP_AND_INT_2ADDR:
        case OP_OR_INT_2ADDR:
        case OP_XOR_INT_2ADDR: {
            uint8_t vA = (insn[0] >> 8) & 0xF;
            uint8_t vB = (insn[0] >> 12) & 0xF;
            oss << " v" << (int)vA << ", v" << (int)vB;
            break;
        }
        
        case OP_GOTO: {
            int8_t offset = (int8_t)((insn[0] >> 8) & 0xFF);
            uint32_t target_addr = (address / 2) + offset;
            oss << " :cond_" << std::hex << target_addr;
            break;
        }
        
        case OP_GOTO_16: {
            int16_t offset = (int16_t)insn[1];
            uint32_t target_addr = (address / 2) + offset;
            oss << " :cond_" << std::hex << target_addr;
            break;
        }
        
        case OP_GOTO_32: {
            int32_t offset = (int32_t)((uint32_t)insn[1] | ((uint32_t)insn[2] << 16));
            uint32_t target_addr = (address / 2) + offset;
            oss << " :cond_" << std::hex << target_addr;
            break;
        }
        
        case OP_IF_EQ:
        case OP_IF_NE:
        case OP_IF_LT:
        case OP_IF_GE:
        case OP_IF_GT:
        case OP_IF_LE: {
            uint8_t vA = (insn[0] >> 8) & 0xF;
            uint8_t vB = (insn[0] >> 12) & 0xF;
            int16_t offset = (int16_t)insn[1];
            // Branch target is calculated as (current address + offset) in 16-bit units, then converted to hex
            uint32_t target_addr = (address / 2) + offset;
            oss << " v" << (int)vA << ", v" << (int)vB << ", :cond_" << std::hex << target_addr;
            break;
        }
        
        case OP_IF_EQZ:
        case OP_IF_NEZ:
        case OP_IF_LTZ:
        case OP_IF_GEZ:
        case OP_IF_GTZ:
        case OP_IF_LEZ: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            int16_t offset = (int16_t)insn[1];
            // Branch target is calculated as (current address + offset) in 16-bit units, then converted to hex
            uint32_t target_addr = (address / 2) + offset;
            oss << " v" << (int)vA << ", :cond_" << std::hex << target_addr;
            break;
        }
        
        case OP_AGET: {
            // Format 23x: [AA|op BBBB CCCC]
            uint8_t vA = (insn[0] >> 8) & 0xFF;   // destination register
            uint8_t vB = insn[1] & 0xFF;          // array register
            uint8_t vC = (insn[1] >> 8) & 0xFF;   // index register
            oss << " v" << (int)vA << ", v" << (int)vB << ", v" << (int)vC;
            break;
        }
        
        case OP_APUT: {
            // Format 23x: [AA|op BBBB CCCC] 
            uint8_t vA = (insn[0] >> 8) & 0xFF;   // source register
            uint8_t vB = insn[1] & 0xFF;          // array register
            uint8_t vC = (insn[1] >> 8) & 0xFF;   // index register
            oss << " v" << (int)vA << ", v" << (int)vB << ", v" << (int)vC;
            break;
        }
        
        case OP_NEW_ARRAY: {
            uint8_t vA = (insn[0] >> 8) & 0xF;
            uint8_t vB = (insn[0] >> 12) & 0xF;
            uint16_t type_idx = insn[1];
            oss << " v" << (int)vA << ", v" << (int)vB << ", " << dex_file->get_type_name(type_idx);
            break;
        }
        
        case OP_PACKED_SWITCH: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            int32_t offset = (int32_t)((uint32_t)insn[1] | ((uint32_t)insn[2] << 16));
            uint32_t target_addr = (address / 2) + offset;
            oss << " v" << (int)vA << ", :pswitch_data_" << std::hex << target_addr;
            break;
        }
        
        case OP_SPARSE_SWITCH: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            int32_t offset = (int32_t)((uint32_t)insn[1] | ((uint32_t)insn[2] << 16));
            uint32_t target_addr = (address / 2) + offset;
            oss << " v" << (int)vA << ", :sswitch_data_" << std::hex << target_addr;
            break;
        }
        
        case OP_INVOKE_VIRTUAL_RANGE:
        case OP_INVOKE_SUPER_RANGE:
        case OP_INVOKE_DIRECT_RANGE:
        case OP_INVOKE_STATIC_RANGE:
        case OP_INVOKE_INTERFACE_RANGE: {
            // Format 3rc: [AA|op BBBB CCCC]
            // AA = argument count, BBBB = method index, CCCC = first argument register
            uint8_t count = (insn[0] >> 8) & 0xFF;
            uint16_t method_idx = insn[1];
            uint16_t first_reg = insn[2];
            
            oss << " {";
            for (int i = 0; i < count; ++i) {
                if (i > 0) oss << ", ";
                oss << "v" << (first_reg + i);
            }
            oss << "}, " << dex_file->get_method_reference(method_idx);
            break;
        }

        case OP_CONST_CLASS: {
            // Format 21c: [AA|op] BBBB vAA, type@BBBB
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            uint16_t type_idx = insn[1];
            oss << " v" << (int)vA << ", Ljava/lang/Class;"; // Simplified type reference
            break;
        }

        case OP_ARRAY_LENGTH: {
            // Format 12x: [B|A|op] vA, vB
            uint8_t vA = (insn[0] >> 8) & 0xF;
            uint8_t vB = (insn[0] >> 12) & 0xF;
            oss << " v" << (int)vA << ", v" << (int)vB;
            break;
        }

        case OP_ADD_INT_LIT8:
        case OP_RSUB_INT_LIT8:
        case OP_MUL_INT_LIT8:
        case OP_DIV_INT_LIT8:
        case OP_REM_INT_LIT8:
        case OP_AND_INT_LIT8:
        case OP_OR_INT_LIT8:
        case OP_XOR_INT_LIT8:
        case OP_SHL_INT_LIT8:
        case OP_SHR_INT_LIT8:
        case OP_USHR_INT_LIT8: {
            // Format 22b: [AA|op] CC|BB vAA, vBB, #+CC
            uint8_t vAA = (insn[0] >> 8) & 0xFF;
            uint8_t vBB = insn[1] & 0xFF;
            int8_t literal = (int8_t)(insn[1] >> 8);
            oss << " v" << (int)vAA << ", v" << (int)vBB << ", 0x" << std::hex << (int)literal;
            break;
        }

        case OP_MONITOR_ENTER:
        case OP_MONITOR_EXIT: {
            // Format 11x: [AA|op] vAA
            uint8_t vAA = (insn[0] >> 8) & 0xFF;
            oss << " v" << (int)vAA;
            break;
        }

        case OP_INSTANCE_OF: {
            // Format 22c: [B|A|op] CCCC vA, vB, type@CCCC
            uint8_t vA = (insn[0] >> 8) & 0xF;
            uint8_t vB = (insn[0] >> 12) & 0xF;
            uint16_t type_idx = insn[1];
            oss << " v" << (int)vA << ", v" << (int)vB << ", " << dex_file->get_type_name(type_idx);
            break;
        }

        case OP_INT_TO_BYTE:
        case OP_INT_TO_CHAR:
        case OP_INT_TO_SHORT: {
            // Format 12x: [B|A|op] vA, vB
            uint8_t vA = (insn[0] >> 8) & 0xF;
            uint8_t vB = (insn[0] >> 12) & 0xF;
            oss << " v" << (int)vA << ", v" << (int)vB;
            break;
        }

        case OP_AGET_OBJECT: {
            // Format 23x: [AA|op] CCBB vAA, vBB, vCC
            uint8_t vAA = (insn[0] >> 8) & 0xFF;
            uint8_t vBB = insn[1] & 0xFF;
            uint8_t vCC = (insn[1] >> 8) & 0xFF;
            oss << " v" << (int)vAA << ", v" << (int)vBB << ", v" << (int)vCC;
            break;
        }

        case OP_APUT_OBJECT: {
            // Format 23x: [AA|op] CCBB vAA, vBB, vCC
            uint8_t vAA = (insn[0] >> 8) & 0xFF;
            uint8_t vBB = insn[1] & 0xFF;
            uint8_t vCC = (insn[1] >> 8) & 0xFF;
            oss << " v" << (int)vAA << ", v" << (int)vBB << ", v" << (int)vCC;
            break;
        }

        default:
            // For unimplemented instructions, show as unknown with opcode
            oss << " ; unknown opcode 0x" << std::hex << (int)opcode;
            break;
    }
    
    return oss.str();
}

std::string DalvikInstructionParser::format_instruction_with_method(const uint16_t* insn, uint32_t address, const DexFile* dex_file, const DexMethod* method) {
    uint8_t opcode = insn[0] & 0xFF;
    std::ostringstream oss;
    
    oss << get_opcode_name(opcode);
    
    // Format with method context for parameter registers
    switch (opcode) {
        case OP_CONST_STRING: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            uint16_t string_idx = insn[1];
            std::string str = dex_file->get_string(string_idx);

            // Debug output removed for production

            // Escape single quotes to match Python baksmali behavior
            oss << " " << format_register(vA, method) << ", \"" << escape_string_for_smali(str) << "\"";
            break;
        }
        
        case OP_NEW_INSTANCE: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            uint16_t type_idx = insn[1];
            oss << " " << format_register(vA, method) << ", " << dex_file->get_type_name(type_idx);
            break;
        }
        
        case OP_CHECK_CAST: {
            uint8_t vA = (insn[0] >> 8) & 0xFF;
            uint16_t type_idx = insn[1];
            oss << " " << format_register(vA, method) << ", " << dex_file->get_type_name(type_idx);
            break;
        }
        
        case OP_INVOKE_DIRECT:
        case OP_INVOKE_VIRTUAL:
        case OP_INVOKE_SUPER:
        case OP_INVOKE_STATIC:
        case OP_INVOKE_INTERFACE: {
            // Format 35c: [A|G|op BBBB F|E|D|C]
            uint8_t count = (insn[0] >> 12) & 0x0F;
            uint8_t vG = (insn[0] >> 8) & 0x0F;
            uint16_t method_idx = insn[1];
            uint16_t args = insn[2];
            
            oss << " {";
            for (int i = 0; i < count; ++i) {
                if (i > 0) oss << ", ";
                uint8_t reg;
                switch (i) {
                    case 0: reg = args & 0xF; break;
                    case 1: reg = (args >> 4) & 0xF; break;
                    case 2: reg = (args >> 8) & 0xF; break;
                    case 3: reg = (args >> 12) & 0xF; break;
                    case 4: reg = vG; break;
                    default: reg = 0; break;
                }
                oss << format_register(reg, method);
            }
            oss << "}, " << dex_file->get_method_reference(method_idx);
            break;
        }

        case OP_INVOKE_VIRTUAL_RANGE:
        case OP_INVOKE_SUPER_RANGE:
        case OP_INVOKE_DIRECT_RANGE:
        case OP_INVOKE_STATIC_RANGE:
        case OP_INVOKE_INTERFACE_RANGE: {
            // Format 3rc: [AA|op BBBB CCCC]
            // AA = argument count, BBBB = method index, CCCC = first argument register
            uint8_t count = (insn[0] >> 8) & 0xFF;
            uint16_t method_idx = insn[1];
            uint16_t first_reg = insn[2];

            oss << " {";
            for (int i = 0; i < count; ++i) {
                if (i > 0) oss << ", ";
                oss << format_register(first_reg + i, method);
            }
            oss << "}, ";
            if (dex_file) {
                oss << dex_file->get_method_reference(method_idx);
            } else {
                oss << "Method@" << method_idx;
            }
            break;
        }

        case OP_CONST_4: {
            uint8_t vA = (insn[0] >> 8) & 0xF;
            int8_t vB = (insn[0] >> 12) & 0xF;
            if (vB & 0x8) vB |= 0xF0; // Sign extend
            oss << " " << format_register(vA, method) << ", 0x" << std::hex << (int)vB;
            break;
        }
        
        case OP_MOVE:
        case OP_MOVE_OBJECT: {
            uint8_t vA = (insn[0] >> 8) & 0xF;
            uint8_t vB = (insn[0] >> 12) & 0xF;
            oss << " " << format_register(vA, method) << ", " << format_register(vB, method);
            break;
        }
        
        case OP_RETURN_VOID: {
            // No operands
            break;
        }
        
        default:
            // For other opcodes, fall back to the basic formatting but with method context
            return format_instruction(insn, address, dex_file);
    }
    
    return oss.str();
}

std::string DalvikInstructionParser::format_register(uint8_t reg, const DexMethod* method) {
    if (method && is_parameter_register(reg, method)) {
        // Calculate parameter register number
        uint8_t param_count = method->code ? method->code->ins_size : 0;
        uint8_t total_regs = method->code ? method->code->registers_size : 0;
        
        // Parameter registers start at (total_regs - param_count)
        uint8_t param_start = total_regs - param_count;
        
        if (reg >= param_start) {
            uint8_t param_num = reg - param_start;
            return "p" + std::to_string(param_num);
        }
    }
    
    return "v" + std::to_string(reg);
}

bool DalvikInstructionParser::is_parameter_register(uint8_t reg, const DexMethod* method) {
    if (!method || !method->code) {
        return false;
    }
    
    uint8_t param_count = method->code->ins_size;
    uint8_t total_regs = method->code->registers_size;
    
    // Parameter registers are the last ins_size registers
    uint8_t param_start = total_regs - param_count;
    
    return reg >= param_start;
}

std::string DalvikInstructionParser::reformat_registers_for_method(const std::string& instruction, uint16_t registers_size, uint16_t ins_size) {
    if (ins_size == 0 || registers_size == 0) {
        return instruction;
    }
    
    std::string result = instruction;
    uint16_t param_start = registers_size - ins_size;
    
    // Replace register references with parameter registers
    // We need to be careful to replace in the right order (higher numbers first)
    // to avoid replacing v1 when we mean v10
    for (int reg = 15; reg >= 0; --reg) {
        if (reg >= param_start && reg < registers_size) {
            uint16_t param_num = reg - param_start;
            std::string old_reg = "v" + std::to_string(reg);
            std::string new_reg = "p" + std::to_string(param_num);
            
            size_t pos = 0;
            while ((pos = result.find(old_reg, pos)) != std::string::npos) {
                // Make sure we're replacing a complete register reference, not part of another number
                bool is_complete = true;
                if (pos > 0 && (std::isalnum(result[pos - 1]) || result[pos - 1] == '_')) {
                    is_complete = false;
                }
                if (pos + old_reg.length() < result.length() && 
                    (std::isalnum(result[pos + old_reg.length()]) || result[pos + old_reg.length()] == '_')) {
                    is_complete = false;
                }
                
                if (is_complete) {
                    result.replace(pos, old_reg.length(), new_reg);
                    pos += new_reg.length();
                } else {
                    pos += old_reg.length();
                }
            }
        }
    }
    
    return result;
}
