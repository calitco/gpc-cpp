// Tests for gp::json — strict grammar, escapes, caps.
#include "gp/json.h"
#include "test_framework.h"

using gp::json::Value;

namespace {

bool parse(const std::string& doc, Value* out, size_t cap = 1 << 20, std::string* err = nullptr) {
    return gp::json::parse_json(doc, cap, out, err);
}

}  // namespace

TEST(json, parses_all_scalar_kinds) {
    Value v;
    CHECK(parse("null", &v));
    CHECK(v.is_null());
    CHECK(parse("true", &v));
    CHECK(v.as_bool());
    CHECK(parse("false", &v));
    CHECK(!v.as_bool());
    CHECK(parse("-12.5e+3", &v));
    CHECK(v.as_number() == -12500.0);
    CHECK(parse("\"a\\n\\t\\u0041\"", &v));
    CHECK_EQ(std::string(v.as_string()), std::string("a\n\tA"));
}

TEST(json, parses_nested_structures_and_find) {
    Value v;
    const std::string doc =
        "{\"otp\": true, \"servers\": [{\"id\": 1, \"url\": \"https://a\"}, "
        "{\"id\": 2}], \"n\": [1, 2, [3]]}";
    CHECK(parse(doc, &v));
    CHECK(v.kind == Value::Kind::Object);
    const Value* otp = v.find("otp");
    REQUIRE(otp != nullptr);
    CHECK(otp->as_bool());
    const Value* servers = v.find("servers");
    REQUIRE(servers != nullptr && servers->kind == Value::Kind::Array);
    CHECK_EQ(servers->arr.size(), (size_t)2);
    CHECK_EQ(std::string(servers->arr[0].find("url")->as_string()), std::string("https://a"));
    const Value* n = v.find("n");
    REQUIRE(n != nullptr);
    CHECK_EQ(n->arr.size(), (size_t)3);
    CHECK_EQ(n->arr[2].arr[0].as_number(), 3.0);
}

TEST(json, decodes_surrogate_pairs_to_utf8) {
    Value v;
    // U+1F600 GRINNING FACE = \uD83D\uDE00 -> F0 9F 98 80
    CHECK(parse("\"\\uD83D\\uDE00\"", &v));
    const std::string s = v.as_string();
    CHECK_EQ(s.size(), (size_t)4);
    CHECK(static_cast<unsigned char>(s[0]) == 0xF0);
    CHECK(static_cast<unsigned char>(s[1]) == 0x9F);
    CHECK(static_cast<unsigned char>(s[2]) == 0x98);
    CHECK(static_cast<unsigned char>(s[3]) == 0x80);
}

TEST(json, rejects_grammar_violations) {
    Value v;
    std::string err;
    CHECK(!parse("NaN", &v, 1 << 20, &err));
    CHECK(!parse("Infinity", &v, 1 << 20, &err));
    CHECK(!parse("01", &v, 1 << 20, &err));           // leading zero
    CHECK(!parse("+1", &v, 1 << 20, &err));           // no plus sign
    CHECK(!parse("1.", &v, 1 << 20, &err));           // bare fraction
    CHECK(!parse("{\"a\":1}", &v, 4, &err));          // size cap
    CHECK(!parse("{\"a\":1}x", &v, 1 << 20, &err));   // trailing content
    CHECK(!parse("\"a\rb\"", &v, 1 << 20, &err));     // unescaped control char
    CHECK(!parse("\"\\uD800\"", &v, 1 << 20, &err));  // lone high surrogate
}

TEST(json, enforces_depth_cap) {
    Value v;
    std::string deep = std::string(70, '[') + std::string(70, ']');
    CHECK(!parse(deep, &v));
}

TEST(json, duplicate_keys_last_wins) {
    Value v;
    CHECK(parse("{\"k\": 1, \"k\": 2}", &v));
    const Value* k = v.find("k");
    REQUIRE(k != nullptr);
    CHECK_EQ(k->as_number(), 2.0);
}

int main() {
    return gp::test::Registry::instance().run_all();
}