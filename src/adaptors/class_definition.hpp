#pragma once

#include "../dex/dex_structures.hpp"
#include "../baksmali_options.hpp"
#include <ostream>

class ClassDefinition {
public:
    ClassDefinition(const DexClass& class_def, const BaksmaliOptions& options);
    
    void write_to(std::ostream& output);
    
private:
    const DexClass& class_def_;
    const BaksmaliOptions& options_;
    
    void write_class_header(std::ostream& output);
    void write_annotations(std::ostream& output);
    void write_static_fields(std::ostream& output);
    void write_instance_fields(std::ostream& output);
    void write_direct_methods(std::ostream& output);
    void write_virtual_methods(std::ostream& output);
    void write_field_annotations(std::ostream& output, const DexField& field);
    void write_method_annotations(std::ostream& output, const DexMethod& method);
    void write_method_code(std::ostream& output, const DexMethod& method);
    void write_debug_items(std::ostream& output, const std::vector<std::unique_ptr<DebugItem>>& debug_items);
    void write_local_info(std::ostream& output, const std::string& name,
                          const std::string& type, const std::string& signature);
    void write_local_info_to_stream(std::ostream& output, const std::string& name,
                                    const std::string& type, const std::string& signature);
};