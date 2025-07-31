#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <net/tcp.h>

#define BW_SCALE_2      24
#define BW_UNIT (1 << BW_SCALE_2)

#define BBR_SCALE 8 /* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)

#define SPLINE_SCALE    10
#define SCALE_BW_RTT    4
#define BW_SCALE        12
#define MIN_RTT_US      50000   /* 50 ms */
#define MIN_BW          14480    /* Minimum bandwidth in bytes/sec */

#define SCC_MIN_RTT_WIN_SEC 10
#define SCC_MIN_SEGMENT_SIZE    1448
#define SCC_MIN_SND_CWND    10

enum spline_cc_mode {
    MODE_START_PROBE,
    MODE_PROBE_BW,
    MODE_PROBE_RTT,
    MODE_DRAIN_PROBE
};

struct scc {
    u32 curr_cwnd;      /* Current congestion window (bytes) */
    u32 last_min_rtt;       /* Minimum RTT (us) */
    u32 last_ack;       /* Last acknowledged bytes */
    u32 curr_ack;       /* Newly delivered bytes */
    u32 fairness_rat;
    u32 last_rtt;
    u32 curr_rtt;
    u32 gain;
    u32 cwnd_gain;

    u64 cycle_mstamp;        /* time of this cycle phase start */
    u32 bw;
    u32 lt_bw;
    u32 last_min_rtt_stamp; /* Timestamp for min RTT update */
    u32 lt_last_stamp;       /* LT intvl start: tp->delivered_mstamp */
    u32 lt_last_lost;        /* LT intvl start: tp->lost */
    u32 lt_last_wstamp_ns;
    u32 lt_last_delivered;
    u32 pacing_gain;
    u32 delivered;
