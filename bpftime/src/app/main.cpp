#include <bpf/libbpf.h>
#include <clock_adjtime.skel.h>
#include <cxxopts.hpp>
#include <fdset.h>
#include <iostream>
#include <poll.h>
#include <ringbuf.h>
#include <signalhandler.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <timex_event.h>

struct CliArgs {
    spdlog::level::level_enum log_level;
};

static CliArgs parse_arguments(int argc, char* argv[])
{
    cxxopts::Options options(
        "sockact-udsctl", "Simple UDS client for communicating with sockact service");

    options.add_options()(
        "l,log-level",
        "Log level (trace, debug, info, warn, error, critical, off)",
        cxxopts::value<std::string>()->default_value("info"));

    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            std::exit(EXIT_SUCCESS);
        }

    } catch (const cxxopts::exceptions::exception& ex) {
        std::cerr << "Error parsing options: " << ex.what() << "\n\n"
                  << options.help() << std::endl;
        std::exit(EXIT_FAILURE);
    }

    const std::string level_str = result["log-level"].as<std::string>();
    spdlog::level::level_enum log_level;

    try {
        log_level = spdlog::level::from_str(level_str);
    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Warning: Invalid log level '" << level_str << "' (" << ex.what()
                  << "), falling back to 'info'\n";
        log_level = spdlog::level::info;
    }

    CliArgs args;
    args.log_level = log_level;
    return args;
}

inline std::string StatusToString(const TimexStatus& st)
{
    std::string out;
    auto& s = st.B;

    if (s.pll_updates_enabled)
        out += "PLL|";
    if (s.pps_freq_discipline_enabled)
        out += "PPSFREQ|";
    if (s.pps_time_discipline_enabled)
        out += "PPSTIME|";
    if (s.frequency_lock_mode_enabled)
        out += "FLL|";
    if (s.inserting_leap_second)
        out += "INS|";
    if (s.deleting_leap_second)
        out += "DEL|";
    if (s.clock_unsynchronized)
        out += "UNSYNC|";
    if (s.holding_frequency)
        out += "FREQHOLD|";
    if (s.pps_signal_present)
        out += "PPSSIGNAL|";
    if (s.pps_signal_jitter_exceeded)
        out += "PPSJITTER|";
    if (s.pps_signal_wander_exceeded)
        out += "PPSWANDER|";
    if (s.pps_signal_calibration_error)
        out += "PPSERROR|";
    if (s.clock_hardware_fault)
        out += "CLOCKERR|";
    if (s.ns_resolution)
        out += "NANO|";
    if (s.fll_mode)
        out += "MODE|";
    if (s.clock_source)
        out += "CLK|";

    if (!out.empty())
        out.pop_back();

    return out.empty() ? "NONE" : out;
}

int main(int argc, char* argv[])
{
    utils::SignalHandler signal_handler({SIGINT, SIGTERM});

    const auto args = parse_arguments(argc, argv);

    std::shared_ptr<spdlog::logger> logger;

    try {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        logger = std::make_shared<spdlog::logger>("uds-daemon", console_sink);

        spdlog::set_default_logger(logger);
        spdlog::set_level(args.log_level);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Failed to initialize logger: %s\n", e.what());
        return EXIT_FAILURE;
    }

    using BpfSkelPtr = std::unique_ptr<clock_adjtime_bpf, decltype(&clock_adjtime_bpf__destroy)>;

    BpfSkelPtr bpfskel(clock_adjtime_bpf__open_and_load(), &clock_adjtime_bpf__destroy);

    if (!bpfskel) {
        spdlog::error("Failed to open and load eBPF skeleton");
        return EXIT_FAILURE;
    }

    if (clock_adjtime_bpf__attach(bpfskel.get())) {
        spdlog::error("Failed to attach eBPF skeleton");
        return EXIT_FAILURE;
    }

    bpfutils::RingBuffer<TimexEvent> rb(
        bpf_map__fd(bpfskel->maps.clock_events), [](const TimexEvent& e) {
            spdlog::info(
                "modes={:#x} freq={} tick={} esterror={} status={:#06x} [{}]",
                e.modes,
                e.freq,
                e.tick,
                e.esterror,
                e.status.R,
                StatusToString(e.status));
        });

    bpfutils::RingBuffer<long> rb_status(
        bpf_map__fd(bpfskel->maps.status_events),
        [](const long& status) { spdlog::info("clock_adjtime() returned={}", status); });

    utils::FdSet fdset;
    fdset.AddFd(rb.fd(), [&rb](int) { rb.consume(); });
    fdset.AddFd(rb_status.fd(), [&rb_status](int) { rb_status.consume(); });

    fdset.AddFd(signal_handler.fd(), [&signal_handler, &fdset](int) {
        if (auto sig = signal_handler.consume(); sig.has_value()) {
            spdlog::info("Received signal {}", sig->ssi_signo);
            fdset.UnBlock();
        }
    });

    spdlog::info("Entering event loop, waiting for events...");

    while (fdset.Select() != utils::FdSetRet::UNBLOCK) {
        // Event loop continues until signal handler unblocks fdset
    }

    spdlog::info("Unblocked by signal");
    spdlog::info("End of bpftime");
}
