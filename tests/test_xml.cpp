// Tests for gp::xml — strict parsing, XXE rejection, caps.
#include "gp/xml.h"
#include "test_framework.h"

using gp::xml::Element;

namespace {

bool parse(const std::string& doc, Element* root, std::string* err = nullptr) {
    return gp::xml::parse_xml(doc, 1 << 20, root, err);
}

}  // namespace

TEST(xml, parses_nested_document_with_attrs_entities_cdata_comment) {
    const std::string doc =
        "<?xml version=\"1.0\"?>\n"
        "<prelogin-response>\n"
        "  <!-- generated -->\n"
        "  <server id=\"1\" url=\"https://gp.example.com/ssl-vpn\">\n"
        "    <name>GW &amp; Co</name>\n"
        "  </server>\n"
        "  <cookie name=\"GP-SESSION\"/>\n"
        "  <raw><![CDATA[<not xml>&stuff;</not xml>]]></raw>\n"
        "</prelogin-response>";
    Element root;
    std::string err;
    CHECK(parse(doc, &root, &err));
    CHECK_EQ(root.name, std::string("prelogin-response"));
    const Element* server = root.child("server");
    REQUIRE(server != nullptr);
    CHECK(std::string(server->attr("id")) == "1");
    CHECK(std::string(server->attr("url")) == "https://gp.example.com/ssl-vpn");
    const Element* name = server->child("name");
    REQUIRE(name != nullptr);
    CHECK_EQ(name->text_trim(), std::string("GW & Co"));  // entity decoded
    const Element* cookie = root.child("cookie");
    REQUIRE(cookie != nullptr);
    CHECK(cookie->children.empty());  // self-closing
    CHECK(std::string(cookie->attr("name")) == "GP-SESSION");
    const Element* raw = root.child("raw");
    REQUIRE(raw != nullptr);
    CHECK_EQ(raw->text, std::string("<not xml>&stuff;</not xml>"));  // CDATA verbatim
}

TEST(xml, rejects_doctype_and_unknown_entities) {
    Element root;
    std::string err;
    CHECK(
        !parse("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
               "<r>&xxe;</r>",
               &root, &err));
    CHECK(err.find("DOCTYPE") != std::string::npos);

    CHECK(!parse("<r>&bogus;</r>", &root, &err));
    CHECK(err.find("undeclared entity") != std::string::npos);
}

TEST(xml, rejects_mismatched_tags_trailing_content_and_nul) {
    Element root;
    CHECK(!parse("<a><b></a></b>", &root, nullptr));
    CHECK(!parse("<a></a>trailing", &root, nullptr));
    std::string with_nul = "<a>x\0y</a>";
    CHECK(!parse(with_nul, &root, nullptr));
}

TEST(xml, enforces_depth_and_size_caps) {
    Element root;
    std::string deep;
    for (int i = 0; i < 40; ++i)
        deep += "<n>";
    for (int i = 0; i < 40; ++i)
        deep += "</n>";
    CHECK(!parse(deep, &root, nullptr));

    std::string big = "<a>" + std::string(2048, 'x') + "</a>";
    CHECK(!gp::xml::parse_xml(big, 100, &root, nullptr));
}

TEST(xml, decodes_numeric_entities_and_surrogate_rejection) {
    Element root;
    CHECK(parse("<r>&#65;&#x42;&#233;</r>", &root, nullptr));
    // parse_xml fills *root with the document element itself (no wrapper).
    CHECK_EQ(root.text_trim(), std::string("AB\xc3\xa9"));  // é in UTF-8
    CHECK(!parse("<r>&#xD800;</r>", &root, nullptr));       // lone surrogate rejected
}

int main() {
    return gp::test::Registry::instance().run_all();
}