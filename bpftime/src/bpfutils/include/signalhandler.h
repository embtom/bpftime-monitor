#ifndef SIGNALHANDLER_H
#define SIGNALHANDLER_H

#include <cerrno>
#include <csignal>
#include <initializer_list>
#include <optional>
#include <pthread.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/signalfd.h>
#include <system_error>
#include <unistd.h>

namespace utils {

class SignalError : public std::system_error {
  public:
    explicit SignalError(const std::string& what, int errnum = errno) :
     std::system_error(errnum, std::generic_category(), what)
    {
    }
};

class SignalHandler {
  public:
    explicit SignalHandler(std::initializer_list<int> signals);
    ~SignalHandler();

    int fd() const
    {
        return signal_fd_;
    }

    std::optional<signalfd_siginfo> consume() const;

    static void enableSegfaultHandler();

  private:
    int signal_fd_{-1};
    sigset_t mask_{};
    sigset_t old_mask_{};
    static void segFaultHandler(int sig, siginfo_t* info, void* ctx);
};

} // namespace utils

#endif // SIGNALHANDLER_H
