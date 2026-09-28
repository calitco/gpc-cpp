// GUI launch implementation. See include/gp/gui.h for the protocol and the
// H-3 property (URL via stdin, never argv).
#include "gp/gui.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>

namespace gp::gui {

namespace {

long long now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

void drain(int fd, std::string& out, size_t cap) {
    char buf[8192];
    for (;;) {
        ssize_t n = ::read(fd, buf, sizeof buf);
        if (n <= 0)
            return;
        size_t space = out.size() < cap ? cap - out.size() : 0;
        if (static_cast<size_t>(n) <= space)
            out.append(buf, static_cast<size_t>(n));
        else
            out.append(buf, space);
    }
}

}  // namespace

GuiResult launch(const GuiConfig& cfg, const std::string& url) {
    GuiResult res;
    if (cfg.program.empty() || cfg.timeout_ms <= 0 || url.find('\n') != std::string::npos) {
        res.spawn_failed = true;
        return res;
    }

    int in_pipe[2];    // parent -> child stdin (carries the URL)
    int out_pipe[2];   // child stdout -> parent (capped)
    int exec_pipe[2];  // child signals exec failure
    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0 || pipe(exec_pipe) != 0) {
        res.spawn_failed = true;
        for (int fd :
             {in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1], exec_pipe[0], exec_pipe[1]}) {
            if (fd >= 0)
                ::close(fd);
        }
        return res;
    }
    fcntl(out_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(exec_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC);

    pid_t pid = fork();
    if (pid < 0) {
        res.spawn_failed = true;
        for (int fd :
             {in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1], exec_pipe[0], exec_pipe[1]}) {
            ::close(fd);
        }
        return res;
    }

    if (pid == 0) {
        // Child: URL arrives on stdin. argv contains only the static program args.
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        // stderr intentionally inherited (GUI logs are not secret material).
        ::close(in_pipe[0]);
        ::close(in_pipe[1]);
        ::close(out_pipe[0]);
        ::close(out_pipe[1]);
        std::vector<const char*> argv;
        argv.push_back(cfg.program.c_str());
        for (const auto& a : cfg.args)
            argv.push_back(a.c_str());
        argv.push_back(nullptr);
        execvp(cfg.program.c_str(), const_cast<char* const*>(argv.data()));
        char sig = 'E';
        ssize_t wn = write(exec_pipe[1], &sig, 1);
        (void)wn;
        _exit(127);
    }

    // Parent: deliver the URL on stdin, then close it (EOF).
    ::close(in_pipe[0]);
    ::close(out_pipe[1]);
    ::close(exec_pipe[1]);
    std::string payload = url + "\n";
    size_t off = 0;
    while (off < payload.size()) {
        ssize_t n = ::write(in_pipe[1], payload.data() + off, payload.size() - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        off += static_cast<size_t>(n);
    }
    ::close(in_pipe[1]);

    const long long deadline = now_ms() + cfg.timeout_ms;
    bool out_eof = false;
    bool reaped = false;
    int status = 0;

    while (!(reaped && out_eof)) {
        if (now_ms() >= deadline) {
            ::kill(pid, SIGKILL);
            res.timed_out = true;
            break;
        }
        struct pollfd pfs[1] = {{out_pipe[0], POLLIN, 0}};
        long long remaining = deadline - now_ms();
        int pr = poll(pfs, 1, remaining > 1000 ? 1000 : static_cast<int>(remaining));
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pr > 0 && pfs[0].revents & (POLLIN | POLLHUP)) {
            drain(out_pipe[0], res.stdout_text, cfg.max_stdout_bytes);
            char probe;
            ssize_t n = ::read(out_pipe[0], &probe, 1);
            if (n == 0)
                out_eof = true;
            else if (n > 0 && res.stdout_text.size() < cfg.max_stdout_bytes) {
                res.stdout_text.push_back(probe);
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
    char sig = 0;
    ssize_t sn = ::read(exec_pipe[0], &sig, 1);
    ::close(exec_pipe[0]);
    bool exec_failed = (sn > 0) && !res.timed_out;

    if (!reaped) {
        int st = 0;
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
        }
        status = st;
        reaped = true;
    }

    if (reaped && WIFEXITED(status)) {
        res.exit_code = WEXITSTATUS(status);
        res.completed = !res.timed_out && !exec_failed;
        if (exec_failed)
            res.spawn_failed = true;
    } else if (reaped && WIFSIGNALED(status)) {
        res.exit_code = 128 + WTERMSIG(status);
        res.completed = false;
    } else {
        res.spawn_failed = true;
    }
    return res;
}

}  // namespace gp::gui