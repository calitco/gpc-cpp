#include "gp/secret_transport.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <sstream>

namespace gp::secrets {

bool argv_contains_secret(const std::vector<std::string>& args,
                          const std::vector<std::string>& secrets) {
    for (const auto& arg : args) {
        for (const auto& s : secrets) {
            if (!s.empty() && arg.find(s) != std::string::npos)
                return true;
        }
    }
    return false;
}

bool spawn_with_stdin_secrets(const std::string& program, const std::vector<std::string>& args,
                              const std::vector<std::string>& secrets, std::string* err) {
    // Fail closed: never exec if a secret leaked into argv.
    if (argv_contains_secret(args, secrets)) {
        if (err)
            *err = "refusing to spawn: secret material present in argv";
        return false;
    }

    int pipefd[2];
    if (::pipe(pipefd) != 0) {
        if (err)
            *err = "pipe() failed";
        return false;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        if (err)
            *err = "fork() failed";
        return false;
    }
    if (pid == 0) {
        // Child: stdin <- secrets, then EOF.
        ::close(pipefd[1]);
        ::dup2(pipefd[0], STDIN_FILENO);
        ::close(pipefd[0]);

        std::vector<char*> cargs;
        cargs.push_back(const_cast<char*>(program.c_str()));
        for (const auto& a : args)
            cargs.push_back(const_cast<char*>(a.c_str()));
        cargs.push_back(nullptr);
        ::execvp(program.c_str(), cargs.data());
        _exit(127);  // exec failed
    }

    // Parent: hand over the secrets, close stdin for the child.
    ::close(pipefd[0]);
    bool ok = true;
    std::ostringstream oss;
    for (const auto& s : secrets) {
        oss << s << "\n";
    }
    const std::string blob = oss.str();
    const unsigned char* p = reinterpret_cast<const unsigned char*>(blob.data());
    std::size_t off = 0;
    while (off < blob.size()) {
        ssize_t n = ::write(pipefd[1], p + off, blob.size() - off);
        if (n <= 0) {
            ok = false;
            break;
        }
        off += static_cast<std::size_t>(n);
    }
    ::close(pipefd[1]);

    int status = 0;
    ::waitpid(pid, &status, 0);
    if (!ok) {
        if (err)
            *err = "failed writing secrets to child stdin";
        return false;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (err)
            *err = "child exited with status " +
                   std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return false;
    }
    return true;
}

bool write_secret_file(const std::string& path, const std::string& data, bool overwrite,
                       std::string* err) {
    int flags = O_WRONLY | O_CREAT | (overwrite ? 0 : O_EXCL);
    int fd = ::open(path.c_str(), flags, 0600);
    if (fd < 0) {
        if (err)
            *err = "cannot open secret file: " + path;
        return false;
    }
    // fchmod defeats a permissive umask even on an existing file.
    if (::fchmod(fd, 0600) != 0) {
        ::close(fd);
        if (err)
            *err = "fchmod failed";
        return false;
    }
    const unsigned char* p = reinterpret_cast<const unsigned char*>(data.data());
    std::size_t off = 0;
    bool ok = true;
    while (off < data.size()) {
        ssize_t n = ::write(fd, p + off, data.size() - off);
        if (n <= 0) {
            ok = false;
            break;
        }
        off += static_cast<std::size_t>(n);
    }
    ::close(fd);
    if (!ok) {
        if (err)
            *err = "short write to secret file";
        return false;
    }
    // Verify the on-disk mode actually ended up owner-only.
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0 || (st.st_mode & 077) != 0) {
        if (err)
            *err = "secret file is not 0600 after write";
        return false;
    }
    return true;
}

int open_log_file_0600(const std::string& path) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    // Enforce regardless of umask.
    if (::fchmod(fd, 0600) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

void Redactor::add_value(const std::string& value) {
    if (value.size() < 4)
        return;  // avoid over-redaction of tiny strings
    values_.push_back(value);
}

std::string Redactor::redact(const std::string& line) const {
    std::string out = line;
    for (const auto& v : values_) {
        std::size_t pos = 0;
        while ((pos = out.find(v, pos)) != std::string::npos) {
            out.replace(pos, v.size(), "[REDACTED]");
            pos += std::string("[REDACTED]").size();
        }
    }
    return out;
}

}  // namespace gp::secrets
