#include "signalhandler.h"
#include <cstdio>
#include <cstring>
#include <sys/signalfd.h>

namespace utils {

SignalHandler::SignalHandler(std::initializer_list<int> signals)
{
    if (sigemptyset(&mask_) != 0)
        throw SignalError("sigemptyset failed");

    for (int s : signals) {
        if (sigaddset(&mask_, s) != 0)
            throw SignalError("sigaddset failed");
    }

    // Block signals on all current threads
    if (pthread_sigmask(SIG_BLOCK, &mask_, &old_mask_) != 0)
        throw SignalError("pthread_sigmask failed");

    // SFD_CLOEXEC: automatically close this file descriptor if this
    //  process replaces itself with another program via exec()
    // SFD_NONBLOCK: non-blocking read
    signal_fd_ = signalfd(-1, &mask_, SFD_CLOEXEC | SFD_NONBLOCK);
    if (signal_fd_ == -1)
        throw SignalError("signalfd failed");
}

SignalHandler::~SignalHandler()
{
    if (signal_fd_ >= 0) {
        close(signal_fd_);
    }
    pthread_sigmask(SIG_UNBLOCK, &old_mask_, nullptr);
}

std::optional<signalfd_siginfo> SignalHandler::consume() const
{
    signalfd_siginfo fdsi{};
    ssize_t s = read(signal_fd_, &fdsi, sizeof(fdsi));
    if (s == -1) {
        if (errno == EAGAIN) {
            return std::nullopt;
        }
        throw SignalError("read from signalfd failed");
    }

    if (s != sizeof(fdsi))
        throw SignalError("size of read data does not match signalfd_siginfo");
    return fdsi; // Signal consumed
}

void SignalHandler::enableSegfaultHandler()
{
    struct sigaction sa{};
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = &SignalHandler::segFaultHandler;

    sigaction(SIGSEGV, &sa, nullptr);
}

void SignalHandler::segFaultHandler(int sig, siginfo_t* info, void*)
{
    constexpr std::string_view msg = "Segmentation fault!\n";
    ssize_t ret = write(STDERR_FILENO, msg.data(), msg.size());
    (void)ret;

    if (info) {
        char buf[64];
        int len = snprintf(buf, sizeof(buf), "Fault at: %p\n", info->si_addr);
        ret = write(STDERR_FILENO, buf, static_cast<size_t>(len));
    }

    // Restore default and crash properly for core dump/debugger
    signal(sig, SIG_DFL);
    kill(getpid(), sig);
}

} // namespace utils
