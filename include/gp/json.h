// Minimal STRICT JSON parser for portal responses (GlobalProtect uses JSON
// in newer portal versions alongside XML). Security/robustness properties:
//  - size cap and depth cap enforced up front / during descent;
//  - no trailing content after the top-level value;
//  - numbers follow the JSON grammar exactly (no leading zeros, no NaN/Inf);
//  - \uXXXX escapes decoded to UTF-8, including surrogate pairs.
#pragma once

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace gp::json {

class Value {
   public:
    enum class Kind { Null, Bool, Number, String, Array, Object };

    Kind kind = Kind::Null;
    bool b = false;
    double num = 0.0;
    std::string str;
    std::vector<Value> arr;
    // Insertion order preserved; duplicate keys: last one wins on find().
    std::vector<std::pair<std::string, Value>> obj;

    const Value* find(const std::string& key) const;
    const char* as_string() const { return kind == Kind::String ? str.c_str() : nullptr; }
    double as_number() const { return kind == Kind::Number ? num : 0.0; }
    bool as_bool() const { return kind == Kind::Bool && b; }
    bool is_null() const { return kind == Kind::Null; }
};

// Parse `doc` into *out. Fails (returns false, sets *err) on any grammar
// error, trailing content, depth > 64, or doc.size() > max_bytes.
bool parse_json(const std::string& doc, size_t max_bytes, Value* out, std::string* err = nullptr);

}  // namespace gp::json