
#ifndef TIMEX_EVENT_H_
#define TIMEX_EVENT_H_

// include/uapi/linux/timex.h

#ifdef __cplusplus
#include <cstdint>
#endif

struct TimexStatusBits {
    uint32_t pll_updates_enabled : 1;         // 0 STA_PLL
    uint32_t pps_freq_discipline_enabled : 1; // 1 STA_PPSFREQ
    uint32_t pps_time_discipline_enabled : 1; // 2 STA_PPSTIME
    uint32_t frequency_lock_mode_enabled : 1; // 3 STA_FLL

    uint32_t inserting_leap_second : 1; // 4 STA_INS
    uint32_t deleting_leap_second : 1;  // 5 STA_DEL
    uint32_t clock_unsynchronized : 1;  // 6 STA_UNSYNC
    uint32_t holding_frequency : 1;     // 7 STA_FREQHOLD

    uint32_t pps_signal_present : 1;           // 8  STA_PPSSIGNAL
    uint32_t pps_signal_jitter_exceeded : 1;   // 9  STA_PPSJITTER
    uint32_t pps_signal_wander_exceeded : 1;   // 10 STA_PPSWANDER
    uint32_t pps_signal_calibration_error : 1; // 11 STA_PPSERROR

    uint32_t clock_hardware_fault : 1; // 12 STA_CLOCKERR
    uint32_t ns_resolution : 1;        // 13 STA_NANO
    uint32_t fll_mode : 1;             // 14 STA_MODE
    uint32_t clock_source : 1;         // 15 STA_CLK

    uint32_t reserved : 16;
};

union TimexStatus {
    uint32_t R;
    struct TimexStatusBits B;
};

struct TimexEvent {
    uint64_t freq;
    uint64_t tick;
    union TimexStatus status;
    int32_t modes;
    int64_t esterror;
};

#endif
