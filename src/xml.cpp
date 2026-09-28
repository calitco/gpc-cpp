// Strict XML parser implementation. See include/gp/xml.h for the security
// model (no DOCTYPE, no undeclared entities, depth/size caps).
#include "gp/xml.h"

#include <cctype>
#include <cstdlib>

namespace gp::xml {

namespace {

constexpr int kMaxDepth = 32;

bool is_name_start(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) || c == '_' || c == ':';
}

bool is_name_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == ':' || c == '.' ||
           c == '-';
}

// Decode one UTF-8 code point into `out`. Returns false for surrogates or
// out-of-range values.
bool encode_utf8(unsigned cp, std::string* out) {
    if (cp >= 0xD800 && cp <= 0xDFFF)
        return false;
    if (cp > 0x10FFFF)
        return false;
    if (cp < 0x80) {
        out->push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out->push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out->push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out->push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    return true;
}

struct Parser {
    const std::string& doc;
    size_t i = 0;
    int depth = 0;
    std::string err;

    explicit Parser(const std::string& d) : doc(d) {}

    bool fail(const std::string& msg) {
        if (err.empty())
            err = msg + " at offset " + std::to_string(i);
        return false;
    }

    void skip_ws() {
        while (i < doc.size() &&
               (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\r' || doc[i] == '\n')) {
            ++i;
        }
    }

    bool parse_name(std::string* out) {
        if (i >= doc.size() || !is_name_start(doc[i]))
            return fail("expected name");
        size_t start = i;
        while (i < doc.size() && is_name_char(doc[i]))
            ++i;
        *out = doc.substr(start, i - start);
        return true;
    }

    // Decode entities in [start, end) into out. Only the five predefined
    // references and numeric refs are allowed.
    bool decode_entities(size_t start, size_t end, std::string* out) {
        size_t p = start;
        while (p < end) {
            if (doc[p] != '&') {
                out->push_back(doc[p]);
                ++p;
                continue;
            }
            size_t semi = doc.find(';', p);
            if (semi == std::string::npos || semi > end)
                return fail("unterminated entity");
            std::string ref = doc.substr(p + 1, semi - p - 1);
            char decoded = '\0';
            unsigned cp = 0;
            bool ok = false;
            if (ref == "amp") {
                decoded = '&';
                ok = true;
            } else if (ref == "lt") {
                decoded = '<';
                ok = true;
            } else if (ref == "gt") {
                decoded = '>';
                ok = true;
            } else if (ref == "quot") {
                decoded = '"';
                ok = true;
            } else if (ref == "apos") {
                decoded = '\'';
                ok = true;
            } else if (!ref.empty() && ref[0] == '#') {
                const char* digits = ref.c_str() + 1;
                int base = 10;
                if (ref.size() >= 2 && (ref[1] == 'x' || ref[1] == 'X')) {
                    ++digits;
                    base = 16;
                }
                char* endp = nullptr;
                if (digits == ref.c_str() + ref.size())
                    return fail("empty numeric entity");
                unsigned long v = std::strtoul(digits, &endp, base);
                // Everything from `digits` to the end of the reference must be digits.
                if (endp != ref.c_str() + ref.size())
                    return fail("bad numeric entity");
                cp = static_cast<unsigned>(v);
                ok = encode_utf8(cp, out);
                if (!ok)
                    return fail("invalid code point in entity");
                p = semi + 1;
                continue;
            } else {
                return fail("undeclared entity &" + ref + "; (DOCTYPE/entities not allowed)");
            }
            if (ok && decoded)
                out->push_back(decoded);
            p = semi + 1;
        }
        return true;
    }

    bool skip_comment() {
        size_t end = doc.find("-->", i + 4);
        if (end == std::string::npos)
            return fail("unterminated comment");
        i = end + 3;
        return true;
    }

    bool skip_pi() {  // <?xml ...?> and any other processing instruction
        size_t end = doc.find("?>", i);
        if (end == std::string::npos)
            return fail("unterminated PI");
        i = end + 2;
        return true;
    }

    bool skip_cdata(std::string* out) {
        // i points at "<![CDATA["
        size_t start = i + 9;
        size_t end = doc.find("]]>", start);
        if (end == std::string::npos)
            return fail("unterminated CDATA");
        out->append(doc, start, end - start);
        i = end + 3;
        return true;
    }

    bool parse_attrs(Element* el) {
        for (;;) {
            skip_ws();
            if (i >= doc.size())
                return fail("unexpected EOF in tag");
            if (doc[i] == '>' || (doc[i] == '/' && i + 1 < doc.size() && doc[i + 1] == '>')) {
                return true;
            }
            std::string name;
            if (!parse_name(&name))
                return false;
            skip_ws();
            if (i >= doc.size() || doc[i] != '=')
                return fail("expected = in attribute");
            ++i;
            skip_ws();
            if (i >= doc.size() || (doc[i] != '"' && doc[i] != '\'')) {
                return fail("unquoted attribute value");
            }
            char quote = doc[i++];
            size_t end = doc.find(quote, i);
            if (end == std::string::npos)
                return fail("unterminated attribute value");
            std::string value;
            if (!decode_entities(i, end, &value))
                return false;
            for (const auto& a : el->attrs) {
                if (a.name == name)
                    return fail("duplicate attribute " + name);
            }
            el->attrs.push_back({name, value});
            i = end + 1;
        }
    }

    bool parse_children(Element* el) {
        ++depth;
        bool ok = true;
        while (ok) {
            if (i >= doc.size())
                return fail("unexpected EOF in element " + el->name);
            if (doc[i] == '<') {
                if (doc.compare(i, 2, "</") == 0) {
                    i += 2;
                    std::string close_name;
                    if (!parse_name(&close_name))
                        return false;
                    skip_ws();
                    if (i >= doc.size() || doc[i] != '>')
                        return fail("malformed closing tag");
                    ++i;
                    if (close_name != el->name) {
                        return fail("mismatched closing tag </" + close_name + "> for <" +
                                    el->name + ">");
                    }
                    --depth;
                    return true;
                }
                if (doc.compare(i, 4, "<!--") == 0) {
                    ok = skip_comment();
                    continue;
                }
                if (doc.compare(i, 2, "<?") == 0) {
                    ok = skip_pi();
                    continue;
                }
                if (doc.compare(i, 2, "<!") == 0) {
                    if (doc.compare(i, 9, "<![CDATA[") == 0) {
                        ok = skip_cdata(&el->text);
                        continue;
                    }
                    return fail("DOCTYPE/declarations are not allowed (XXE protection)");
                }
                if (depth >= kMaxDepth)
                    return fail("element depth limit exceeded");
                Element child;
                ++i;  // consume '<'
                if (!parse_name(&child.name))
                    return false;
                if (!parse_attrs(&child))
                    return false;
                bool self_closing = doc[i] == '/';
                if (self_closing)
                    ++i;
                if (i >= doc.size() || doc[i] != '>')
                    return fail("malformed opening tag");
                ++i;
                if (!self_closing) {
                    if (!parse_children(&child))
                        return false;
                }
                el->children.push_back(std::move(child));
            } else {
                size_t start = i;
                while (i < doc.size() && doc[i] != '<')
                    ++i;
                std::string text;
                if (!decode_entities(start, i, &text))
                    return false;
                el->text += text;
            }
        }
        --depth;
        return ok;
    }

    bool parse_element(Element* el) {
        // i points just past '<' of the opening tag.
        if (!parse_name(&el->name))
            return false;
        if (!parse_attrs(el))
            return false;
        bool self_closing = doc[i] == '/';
        if (self_closing)
            ++i;
        if (i >= doc.size() || doc[i] != '>')
            return fail("malformed opening tag");
        ++i;
        if (self_closing)
            return true;
        return parse_children(el);
    }

    bool run(Element* root) {
        // Strip UTF-8 BOM.
        if (doc.size() >= 3 && static_cast<unsigned char>(doc[0]) == 0xEF &&
            static_cast<unsigned char>(doc[1]) == 0xBB &&
            static_cast<unsigned char>(doc[2]) == 0xBF) {
            i = 3;
        }
        for (size_t p = 0; p < doc.size(); ++p) {
            if (doc[p] == '\0')
                return fail("NUL byte in document");
        }
        skip_ws();
        // Optional XML declaration.
        if (i + 1 < doc.size() && doc[i] == '<' && doc[i + 1] == '?') {
            if (!skip_pi())
                return false;
            skip_ws();
        }
        if (i + 1 < doc.size() && doc[i] == '<' && doc[i + 1] == '!') {
            return fail("DOCTYPE/declarations are not allowed (XXE protection)");
        }
        if (i >= doc.size() || doc[i] != '<')
            return fail("expected root element");
        ++i;
        if (!parse_element(root))
            return false;
        skip_ws();
        if (i != doc.size())
            return fail("trailing content after root element");
        return true;
    }
};

}  // namespace

bool parse_xml(const std::string& doc, size_t max_bytes, Element* root, std::string* err) {
    if (doc.size() > max_bytes) {
        if (err)
            *err = "document exceeds size cap";
        return false;
    }
    Parser p(doc);
    bool ok = p.run(root);
    if (!ok && err)
        *err = p.err;
    return ok;
}

const Element* Element::child(const std::string& name) const {
    for (const auto& c : children) {
        if (c.name == name)
            return &c;
    }
    return nullptr;
}

std::vector<const Element*> Element::children_named(const std::string& name) const {
    std::vector<const Element*> out;
    for (const auto& c : children) {
        if (c.name == name)
            out.push_back(&c);
    }
    return out;
}

const char* Element::attr(const std::string& name) const {
    for (const auto& a : attrs) {
        if (a.name == name)
            return a.value.c_str();
    }
    return nullptr;
}

std::string Element::text_trim() const {
    size_t b = text.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
        return "";
    size_t e = text.find_last_not_of(" \t\r\n");
    return text.substr(b, e - b + 1);
}

}  // namespace gp::xml
