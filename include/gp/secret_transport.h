// Secret-handling utilities — fixes finding H-3 (secrets in argv, raw
// payloads in world-readable logs).
//
// Rules implemented here:
//  - secrets travel over stdin (or a 0600 file), NEVER via argv;
//  - every helper that touches a secret verifies the resulting state
//    (argv scan, file mode) and fails closed on mismatch;
//  - logs go through Redactor; raw payloads are never logged.
#pragma once

#include <string>
#include <vector>

namespace gp::secrets {

// Defensive check: refuse to build an argv that contains any registered
// secret (guards against future regressions where a "convenience" flag
// starts smuggling the password back into arguments).
bool argv_contains_secret(const std::vector<std::string>& args,
                          const std::vector<std::string>& secrets);

// Spawn `program args...` with each secret written to the child's stdin
// (newline-separated), then closed. Returns false on spawn/exec failure.
// The caller must document the stdin protocol in the child (e.g. a
// --read-secrets-on-stdin flag, as the GUI launcher already does for its
// API key).
bool spawn_with_stdin_secrets(const std::string& program, const std::vector<std::string>& args,
                              const std::vector<std::string>& secrets, std::string* err = nullptr);

// Write `data` to `path` created 0600 (O_EXCL unless overwrite). The mode is
// re-verified after writing; any mismatch fails the call.
bool write_secret_file(const std::string& path, const std::string& data, bool overwrite = false,
                       std::string* err = nullptr);

// Open (create/truncate) a log file with mode 0600 regardless of umask.
// Returns fd or -1. The old code used default-umask creation for
// gpcallback.log → world-readable; this cannot happen anymore.
int open_log_file_0600(const std::string& path);

// Value redaction for log lines. Values shorter than 4 chars are ignored to
// avoid over-redacting single characters/digits.
class Redactor {
   public:
    void add_value(const std::string& value);
    // Replace every occurrence of every registered value with "[REDACTED]".
    std::string redact(const std::string& line) const;
    bool empty() const { return values_.empty(); }

   private:
    std::vector<std::string> values_;
};

}  // namespace gp::secrets
