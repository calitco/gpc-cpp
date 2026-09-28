// Escaping utilities. The AuthServer renders portal-provided values (URLs,
// titles) into HTML; every such value MUST pass through these functions
// (fixes the XSS vector in H-2). Also provides strict URL validation used to
// reject CRLF-injection / control-character redirect targets.
#pragma once

#include <string>
#include <vector>

namespace gp::html {

// Escape for inclusion inside an HTML text node or double-quoted attribute.
std::string escape_text(const std::string& s);

// Validate a redirect target URL. Returns true only if:
//  - scheme is http or https
//  - no control characters (blocks CRLF header injection)
//  - non-empty host
//  - if allowlist is non-empty, host (case-insensitive, port ignored) is in it
bool valid_redirect_target(const std::string& url, const std::vector<std::string>& allowlist);

}  // namespace gp::html
