// Minimal STRICT XML parser for machine-generated portal documents
// (GlobalProtect prelogin/session responses). Security properties:
//  - DOCTYPE declarations are REJECTED outright (no external/internal
//    entities => no XXE, no billion-laughs);
//  - only the five predefined character references plus numeric refs are
//    decoded; any other entity name is a parse error;
//  - depth cap and total-size cap (DoS protection);
//  - NUL bytes and unbalanced/mismatched tags are errors.
// This is NOT a general-purpose XML library: no DTDs, no namespaces beyond
// passing prefixes through, no validation.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace gp::xml {

struct Attr {
    std::string name;
    std::string value;
};

struct Element {
    std::string name;
    std::vector<Attr> attrs;
    std::vector<Element> children;
    std::string text;  // direct text content (entities decoded), untrimmed

    const Element* child(const std::string& name) const;
    std::vector<const Element*> children_named(const std::string& name) const;
    // nullptr if the attribute is absent.
    const char* attr(const std::string& name) const;
    // text with leading/trailing whitespace stripped.
    std::string text_trim() const;
};

// Parse `doc` into *root. Fails (returns false, sets *err) on any structural
// error, DOCTYPE, unknown entity, depth > 32, or doc.size() > max_bytes.
bool parse_xml(const std::string& doc, size_t max_bytes, Element* root, std::string* err = nullptr);

}  // namespace gp::xml