// Posture check execution implementation. See include/gp/posture.h for the
// security properties (no shell, deadline kill, output caps).
#include "gp/posture.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>

namespace gp::posture {

namespace {

long long now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// Drain a non-blocking pipe fd into out, honoring the cap (data beyond the
// cap is read and discarded so a chatty child never blocks on a full pipe).
void drain(int fd, std::string& out, size_t cap) {
    char buf[8192];
    for (;;) {
        ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            return;  // treat other errors as EOF
        }
        if (n == 0)
            return;
        size_t space = out.size() < cap ? cap - out.size() : 0;
        if (static_cast<size_t>(n) <= space) {
            out.append(buf, static_cast<size_t>(n));
        } else {
            out.append(buf, space);  // keep the first `space` bytes, drop the rest
        }
    }
}

}  // namespace

CheckResult run_check(const CheckConfig& cfg) {
    CheckResult res;
    if (cfg.program.empty() || cfg.timeout_ms <= 0) {
        res.spawn_failed = true;
        return res;
    }

    int out_pipe[2];
    int err_pipe[2];
    int exec_pipe[2];
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0 || pipe(exec_pipe) != 0) {
        res.spawn_failed = true;
        for (int fd :
             {out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1], exec_pipe[0], exec_pipe[1]}) {
            if (fd >= 0)
                ::close(fd);
        }
        return res;
    }
    fcntl(out_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(err_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(exec_pipe[0], F_SETFL, O_NONBLOCK);
    // Closed automatically across a successful execvp; the failure path writes
    // to it before _exit, so the parent can tell exec failure from exit codes.
    fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC);

    pid_t pid = fork();
    if (pid < 0) {
        ::close(out_pipe[0]);
        ::close(out_pipe[1]);
        ::close(err_pipe[0]);
        ::close(err_pipe[1]);
        ::close(exec_pipe[0]);
        ::close(exec_pipe[1]);
        res.spawn_failed = true;
        return res;
    }

    if (pid == 0) {
        // Child: redirect, exec. Never a shell. Signal exec success via
        // exec_pipe so the parent can distinguish exec failure from exit codes.
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        ::close(out_pipe[0]);
        ::close(out_pipe[1]);
        ::close(err_pipe[0]);
        ::close(err_pipe[1]);
        std::vector<const char*> argv;
        argv.push_back(cfg.program.c_str());
        for (const auto& a : cfg.args)
            argv.push_back(a.c_str());
        argv.push_back(nullptr);
        execvp(cfg.program.c_str(), const_cast<char* const*>(argv.data()));
        // exec failed: signal the parent via exec_pipe (before _exit), report on
        // the (captured) stderr, and exit 127.
        char sig = 'E';
        ssize_t wn = write(exec_pipe[1], &sig, 1);
        (void)wn;
        const char msg[] = "gp::posture: exec failed\n";
        write(STDERR_FILENO, msg, sizeof msg - 1);
        _exit(127);
    }

    // Parent.
    ::close(out_pipe[1]);
    ::close(err_pipe[1]);
    ::close(exec_pipe[1]);

    const long long deadline = now_ms() + cfg.timeout_ms;
    bool out_eof = false;
    bool err_eof = false;
    bool reaped = false;
    int status = 0;

    while (!(reaped && out_eof && err_eof)) {
        if (now_ms() >= deadline) {
            ::kill(pid, SIGKILL);
            res.timed_out = true;
            break;
        }
        struct pollfd pfs[2];
        int nfds = 0;
        if (!out_eof)
            pfs[nfds++] = {out_pipe[0], POLLIN, 0};
        if (!err_eof)
            pfs[nfds++] = {err_pipe[0], POLLIN, 0};
        if (nfds == 0)
            break;

        long long remaining = deadline - now_ms();
        int pr = poll(pfs, static_cast<nfds_t>(nfds),
                      remaining > 1000 ? 1000 : static_cast<int>(remaining));
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (int k = 0; k < nfds; ++k) {
            if (!(pfs[k].revents & (POLLIN | POLLHUP)))
                continue;
            int fd = pfs[k].fd;
            bool* eof_flag = (fd == out_pipe[0]) ? &out_eof : &err_eof;
            std::string* sink = (fd == out_pipe[0]) ? &res.stdout_text : &res.stderr_text;
            if (*eof_flag)
                continue;
            drain(fd, *sink, cfg.max_output_bytes);
            // Accurate EOF probe: after draining everything available, a pipe whose
            // writer closed returns 0 immediately; a live writer yields EAGAIN.
            char probe;
            ssize_t n = ::read(fd, &probe, 1);
            if (n == 0) {
                *eof_flag = true;
            } else if (n > 0 && sink->size() < cfg.max_output_bytes) {
                sink->push_back(probe);
            }
        }
        int st = 0;
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid) {
            reaped = true;
            status = st;
        } else if (r < 0 && errno != EINTR) {
            break;
        }
    }

    ::close(out_pipe[0]);
    ::close(err_pipe[0]);
    if (!reaped) {
        ::kill(pid, SIGKILL);
        int st = 0;
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
        }
        status = st;
        reaped = true;
    }

    // Exec-failure signal: the child writes here only on the execvp failure
    // path, so any byte means "the program never ran".
    char sig = 0;
    ssize_t sn = ::read(exec_pipe[0], &sig, 1);
    ::close(exec_pipe[0]);
    bool exec_failed = (sn > 0) && !res.timed_out;

    if (reaped && WIFEXITED(status)) {
        res.exit_code = WEXITSTATUS(status);
        res.ok = !res.timed_out && !exec_failed;
        if (exec_failed)
            res.spawn_failed = true;
    } else if (reaped && WIFSIGNALED(status)) {
        res.exit_code = 128 + WTERMSIG(status);
        res.ok = false;
    } else {
        res.spawn_failed = true;
    }
    return res;
}

std::map<std::string, std::string> parse_key_value(const std::string& text) {
    std::map<std::string, std::string> out;
    size_t start = 0;
    while (start <= text.size()) {
        size_t eol = text.find('\n', start);
        std::string line =
            text.substr(start, eol == std::string::npos ? std::string::npos : eol - start);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        size_t eq = line.find('=');
        if (eq != std::string::npos) {
            std::string key = line.substr(0, eq);
            size_t b = key.find_first_not_of(" \t");
            size_t e = key.find_last_not_of(" \t");
            if (b != std::string::npos && b <= e) {
                out[key.substr(b, e - b + 1)] = line.substr(eq + 1);
            }
        }
        if (eol == std::string::npos)
            break;
        start = eol + 1;
    }
    return out;
}

}  // namespace gp::posture