// Strict JSON parser implementation. See include/gp/json.h for the grammar
// strictness and caps.
#include "gp/json.h"

#include <cctype>
#include <cstdlib>

namespace gp::json {

namespace {

constexpr int kMaxDepth = 64;

void append_utf8(unsigned cp, std::string* out) {
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
               (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\n' || doc[i] == '\r')) {
            ++i;
        }
    }

    bool consume(char c) {
        if (i < doc.size() && doc[i] == c) {
            ++i;
            return true;
        }
        return false;
    }

    bool parse_value(Value* out) {
        skip_ws();
        if (i >= doc.size())
            return fail("unexpected EOF");
        char c = doc[i];
        if (c == '{')
            return parse_object(out);
        if (c == '[')
            return parse_array(out);
        if (c == '"') {
            out->kind = Value::Kind::String;
            return parse_string(&out->str);
        }
        if (doc.compare(i, 4, "true") == 0) {
            i += 4;
            out->kind = Value::Kind::Bool;
            out->b = true;
            return true;
        }
        if (doc.compare(i, 5, "false") == 0) {
            i += 5;
            out->kind = Value::Kind::Bool;
            out->b = false;
            return true;
        }
        if (doc.compare(i, 4, "null") == 0) {
            i += 4;
            out->kind = Value::Kind::Null;
            return true;
        }
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
            return parse_number(out);
        }
        return fail("unexpected character");
    }

    bool parse_number(Value* out) {
        size_t start = i;
        consume('-');
        if (i >= doc.size())
            return fail("bad number");
        if (doc[i] == '0') {
            ++i;
        } else if (std::isdigit(static_cast<unsigned char>(doc[i]))) {
            while (i < doc.size() && std::isdigit(static_cast<unsigned char>(doc[i])))
                ++i;
        } else {
            return fail("bad number");
        }
        if (i < doc.size() && doc[i] == '.') {
            ++i;
            if (i >= doc.size() || !std::isdigit(static_cast<unsigned char>(doc[i]))) {
                return fail("bad fraction");
            }
            while (i < doc.size() && std::isdigit(static_cast<unsigned char>(doc[i])))
                ++i;
        }
        if (i < doc.size() && (doc[i] == 'e' || doc[i] == 'E')) {
            ++i;
            if (i < doc.size() && (doc[i] == '+' || doc[i] == '-'))
                ++i;
            if (i >= doc.size() || !std::isdigit(static_cast<unsigned char>(doc[i]))) {
                return fail("bad exponent");
            }
            while (i < doc.size() && std::isdigit(static_cast<unsigned char>(doc[i])))
                ++i;
        }
        std::string s = doc.substr(start, i - start);
        char* endp = nullptr;
        double v = std::strtod(s.c_str(), &endp);
        if (endp != s.c_str() + s.size())
            return fail("bad number");
        out->kind = Value::Kind::Number;
        out->num = v;
        return true;
    }

    bool parse_hex4(unsigned* cp) {
        if (i + 4 > doc.size())
            return fail("bad \\u escape");
        unsigned v = 0;
        for (int k = 0; k < 4; ++k) {
            char c = doc[i++];
            v <<= 4;
            if (c >= '0' && c <= '9')
                v |= static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f')
                v |= static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                v |= static_cast<unsigned>(c - 'A' + 10);
            else
                return fail("bad \\u escape");
        }
        *cp = v;
        return true;
    }

    bool parse_string(std::string* out) {
        // i is at the opening quote.
        ++i;
        for (;;) {
            if (i >= doc.size())
                return fail("unterminated string");
            char c = doc[i++];
            if (c == '"')
                return true;
            if (c != '\\') {
                if (static_cast<unsigned char>(c) < 0x20) {
                    return fail("unescaped control character in string");
                }
                out->push_back(c);
                continue;
            }
            if (i >= doc.size())
                return fail("bad escape");
            char e = doc[i++];
            switch (e) {
                case '"':
                    out->push_back('"');
                    break;
                case '\\':
                    out->push_back('\\');
                    break;
                case '/':
                    out->push_back('/');
                    break;
                case 'b':
                    out->push_back('\b');
                    break;
                case 'f':
                    out->push_back('\f');
                    break;
                case 'n':
                    out->push_back('\n');
                    break;
                case 'r':
                    out->push_back('\r');
                    break;
                case 't':
                    out->push_back('\t');
                    break;
                case 'u': {
                    unsigned cp = 0;
                    if (!parse_hex4(&cp))
                        return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (doc.compare(i, 2, "\\u") != 0)
                            return fail("unpaired surrogate");
                        i += 2;
                        unsigned lo = 0;
                        if (!parse_hex4(&lo))
                            return false;
                        if (lo < 0xDC00 || lo > 0xDFFF)
                            return fail("bad low surrogate");
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        return fail("unpaired surrogate");
                    }
                    append_utf8(cp, out);
                    break;
                }
                default:
                    return fail("bad escape");
            }
        }
    }

    bool parse_array(Value* out) {
        if (++depth > kMaxDepth)
            return fail("depth limit exceeded");
        out->kind = Value::Kind::Array;
        ++i;  // '['
        skip_ws();
        if (consume(']')) {
            --depth;
            return true;
        }
        for (;;) {
            out->arr.emplace_back();
            if (!parse_value(&out->arr.back()))
                return false;
            skip_ws();
            if (consume(','))
                continue;
            if (consume(']')) {
                --depth;
                return true;
            }
            return fail("expected , or ]");
        }
    }

    bool parse_object(Value* out) {
        if (++depth > kMaxDepth)
            return fail("depth limit exceeded");
        out->kind = Value::Kind::Object;
        ++i;  // '{'
        skip_ws();
        if (consume('}')) {
            --depth;
            return true;
        }
        for (;;) {
            skip_ws();
            if (i >= doc.size() || doc[i] != '"')
                return fail("expected object key");
            std::string key;
            if (!parse_string(&key))
                return false;
            skip_ws();
            if (!consume(':'))
                return fail("expected :");
            out->obj.emplace_back(std::move(key), Value{});
            if (!parse_value(&out->obj.back().second))
                return false;
            skip_ws();
            if (consume(','))
                continue;
            if (consume('}')) {
                --depth;
                return true;
            }
            return fail("expected , or }");
        }
    }

    bool run(Value* out) {
        for (size_t p = 0; p < doc.size(); ++p) {
            if (doc[p] == '\0')
                return fail("NUL byte in document");
        }
        if (!parse_value(out))
            return false;
        skip_ws();
        if (i != doc.size())
            return fail("trailing content after JSON value");
        return true;
    }
};

}  // namespace

bool parse_json(const std::string& doc, size_t max_bytes, Value* out, std::string* err) {
    if (doc.size() > max_bytes) {
        if (err)
            *err = "document exceeds size cap";
        return false;
    }
    Parser p(doc);
    bool ok = p.run(out);
    if (!ok && err)
        *err = p.err;
    return ok;
}

const Value* Value::find(const std::string& key) const {
    for (auto it = obj.rbegin(); it != obj.rend(); ++it) {  // last duplicate wins
        if (it->first == key)
            return &it->second;
    }
    return nullptr;
}

}  // namespace gp::json
