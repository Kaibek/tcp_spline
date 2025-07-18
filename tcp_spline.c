#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <net/tcp.h>

#define SPLINE_SCALE    10
#define SCALE_BW_RTT    4
#define BW_SCALE        12
#define MIN_RTT_US      50000   /* 50 ms */
#define MIN_BW          14480    /* Minimum bandwidth in bytes/sec */
#define BW_SCALE_2      24

#define SCC_MIN_RTT_WIN_SEC 10
#define SCC_MIN_ALLOWED_CWND_SEGNETS 4
#define SCC_MIN_SEGMENT_SIZE    1448
#define SCC_MIN_SND_CWND    (SCC_MIN_SEGMENT_SIZE * SCC_MIN_ALLOWED_CWND_SEGNETS)

/* Congestion control modes */
enum spline_cc_mode {
    MODE_START_PROBE,
    MODE_PROBE_BW,
    MODE_PROBE_RTT,
    MODE_DRAIN_PROBE
};

/* Private data for spline congestion control */
struct scc {
    u32 curr_cwnd;      /* Current congestion window (bytes) */
    u32 throughput;     /* Throughput from in_flight */
    u64 bw;         /* Bandwidth estimate from ACKs */
    u32 last_max_cwnd;      /* Maximum window in bytes */
    u32 last_min_rtt_stamp; /* Timestamp for min RTT update */
    u32 last_min_rtt;       /* Minimum RTT (us) */
    u32 last_ack;       /* Last acknowledged bytes */
    u16 prev_ca_state:3;    /* Previous TCP_CA state */
    u32 last_acked_sacked;  /* ACKed+SACKed bytes */
    u32 mss;            /* Maximum Segment Size */
    u32 prior_cwnd;     /* Prior congestion window */
    u32 min_cwnd;       /* Minimum window */
    u32 curr_rtt;       /* Current RTT (us) */
    u32 cwnd_gain;      /* Congestion window gain */
    u32 max_could_cwnd;     /* Max cwnd balancing bw and fairness */
    u32 curr_ack;       /* Newly delivered bytes */
    u32 fairness_rat;       /* Fairness ratio */
    u32  current_mode:3;       /* Current mode (START_PROBE, etc.) */
    u8  epp_min_rtt;        /* Epoch counter for min RTT */
    u8  epp;            /* Epoch cycle counter */
    u16 EPOCH_ROUND;
    u8 unfair_flag;
    u32 bytes_in_flight;    /* Bytes in flight */
    u32 last_cwnd;
};

static void update_bytes_in_flight(struct sock *sk);
static void update_last_acked_sacked_cwnd_mss(struct sock *sk, const struct rate_sample *rs);

static void fairness_check(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    if(scc->curr_rtt > (scc->last_min_rtt * 3 >> 1) &&
        scc->curr_ack < scc->last_ack)
    {
        scc->unfair_flag++;
    }
}

static bool ack_check(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    return ((u64)scc->curr_ack << SCALE_BW_RTT) < (((u64)scc->last_ack << SCALE_BW_RTT)
        && scc->last_ack > SCC_MIN_SND_CWND);
}

//Проверка на стабильность RTT
static bool rtt_check(struct sock *sk)
{
   struct scc *scc = inet_csk_ca(sk);
   return ((scc->last_min_rtt + 1000) < scc->curr_rtt && 
    (scc->last_min_rtt + MIN_RTT_US + 1000) > scc->curr_rtt);
}

static void stable_rtt(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    if (rtt_check(sk) && 
        !ack_check(sk)) {
            scc->curr_cwnd = max(scc->curr_cwnd, SCC_MIN_SND_CWND);
    }
    printk(KERN_DEBUG"stable_rtt: curr_cwnd=%u\n", scc->curr_cwnd);
}

static void fairness_rtt(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    if (!rtt_check(sk) < scc->curr_rtt && 
        scc->unfair_flag >= 20) {

        u32 cwnd;
        if(scc->bytes_in_flight)
            cwnd = (scc->bytes_in_flight * 10) >> 4;
        else
            cwnd = (scc->curr_cwnd * 10) >> 4;
        scc->curr_cwnd = max(cwnd, SCC_MIN_SND_CWND);
    }
    printk(KERN_DEBUG"fairness_rtt: curr_cwnd=%u\n", scc->curr_cwnd);
}

static void overload_rtt(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    if (!rtt_check(sk) && (scc->bytes_in_flight << 1 > scc->curr_cwnd)) {
            scc->curr_cwnd = (u32)(((u64)scc->curr_cwnd * 14) >> SCALE_BW_RTT);
        scc->curr_cwnd = max(scc->curr_cwnd, SCC_MIN_SND_CWND);
    }
    else if(((scc->bytes_in_flight << 1) < scc->curr_cwnd) && 
        scc->unfair_flag < 20) {
        scc->curr_cwnd = scc->last_acked_sacked + (u32)(((u64)scc->curr_cwnd * 12) >> SCALE_BW_RTT);
        scc->curr_cwnd = max(scc->curr_cwnd, SCC_MIN_SND_CWND);
    }
    printk(KERN_DEBUG"overload_rtt: curr_cwnd=%u\n", scc->curr_cwnd);
}

static void probe_rtt(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    stable_rtt(sk);
    fairness_rtt(sk);
    overload_rtt(sk);
    printk(KERN_DEBUG"probe_rtt: curr_cwnd=%u\n", scc->curr_cwnd);
}

static void update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
    struct scc *scc = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    bool new_min_rtt = after(tcp_jiffies32, scc->last_min_rtt_stamp + SCC_MIN_RTT_WIN_SEC * HZ);

    if (tp->srtt_us)
        scc->curr_rtt = tp->srtt_us >> 3;
    else
        scc->curr_rtt = MIN_RTT_US;

    if (scc->curr_rtt < scc->last_min_rtt || scc->last_min_rtt == 0) {
        pr_debug("update_min_rtt: updating last_min_rtt from %u to %u\n",
             scc->last_min_rtt, scc->curr_rtt);
        scc->last_min_rtt = scc->curr_rtt;
    }

    if (rs && rs->rtt_us > 0 && (rs->rtt_us < scc->last_min_rtt ||
         (new_min_rtt && !rs->is_ack_delayed))) {
        scc->last_min_rtt = rs->rtt_us;
        scc->last_min_rtt_stamp = tcp_jiffies32;
    }

    if (scc->last_min_rtt == 0) {
        scc->last_min_rtt = MIN_RTT_US;
        pr_debug("update_min_rtt: last_min_rtt was 0, set to %u\n", scc->last_min_rtt);
    }

    if (scc->last_min_rtt > scc->curr_rtt) {
        scc->last_min_rtt = scc->curr_rtt;
        scc->epp_min_rtt++;
    }

    scc->epp++;
}

static void update_bandwidth_throughput(struct sock *sk, const struct rate_sample *rs)
{
    struct scc *scc = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    u64 gamma, beta;

    if (scc->last_min_rtt == 0) {
        scc->last_min_rtt = MIN_RTT_US;
    }

    printk(KERN_DEBUG "update_bandwidth_throughput: before calc: last_min_rtt=%u, bytes_in_flight=%u, curr_cwnd=%u, curr_ack=%u, last_acked_sacked=%u\n",
         scc->last_min_rtt, scc->bytes_in_flight, scc->curr_cwnd, scc->curr_ack,
         scc->last_acked_sacked);

    u64 tmp_tp = (u64)scc->bytes_in_flight * USEC_PER_SEC;
    scc->throughput = div_u64(tmp_tp, scc->last_min_rtt);

    if (scc->curr_ack) {
        u64 tmp_bw = ((u64)scc->curr_ack << BW_SCALE_2) * USEC_PER_SEC;
        scc->bw = div_u64(tmp_bw, scc->last_min_rtt);
    } else {
        u64 tmp_bw = ((u64)(scc->last_acked_sacked << 3) << BW_SCALE_2) * USEC_PER_SEC;
        scc->bw = div_u64(tmp_bw, scc->last_min_rtt);
    }

    gamma = scc->bw;
    beta = scc->throughput;

    if (!beta)
        beta = (u32)(scc->bw >> 2) >> BW_SCALE_2;
    scc->fairness_rat = gamma / (beta + MIN_BW);

    if(scc->fairness_rat < 65536U)
        scc->fairness_rat = 65536U;

    if((scc->bw >> BW_SCALE_2) < scc->curr_cwnd)
        scc->curr_cwnd = scc->bw >> BW_SCALE_2;

    printk(KERN_DEBUG "bw_tp: scc->fairness_rat=%u, scc->bw=%llu, scc->throughput=%llu\n",
           scc->fairness_rat, scc->bw, scc->throughput);

    scc->bw = scc->bw >> BW_SCALE_2;
    scc->throughput = scc->throughput;
    scc->bw = max(scc->bw, (u64)MIN_BW);
}

static bool is_loss(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    return ((scc->curr_ack * 17 >> 4) < scc->last_ack && scc->prev_ca_state == TCP_CA_Loss);
}

// v2
static void spline_max_cwnd(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    u64 tmp;

    if (!(scc->throughput << 2))
        scc->throughput = 1;

    tmp = (u64)scc->fairness_rat * ((scc->bw << BW_SCALE_2) / (scc->throughput));
    scc->max_could_cwnd = (scc->curr_cwnd * tmp) >> (BW_SCALE_2 + BW_SCALE_2);

    printk(KERN_DEBUG "max_cwnd: scc->max_could_cwnd=%u, scc->epp_min_rtt=%u\n",
           scc->max_could_cwnd, scc->epp_min_rtt);
}

static bool check_unstable_cwnd(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    return ((scc->curr_cwnd > (scc->bw * 3 >> 2) || scc->bw < scc->throughput));
}

static void drain_probe(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    if (is_loss(sk) || scc->throughput > scc->bw)
        scc->curr_cwnd = scc->curr_cwnd * 12 >> SCALE_BW_RTT;

    scc->curr_cwnd = max(scc->curr_cwnd, scc->min_cwnd);
     printk(KERN_DEBUG "drain_probe: scc->curr_cwnd=%u\n",
           scc->curr_cwnd);
}

static void start_probe(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    u64 new_cwnd = SCC_MIN_SEGMENT_SIZE + scc->curr_cwnd + scc->last_acked_sacked;
    scc->curr_cwnd = new_cwnd;

    scc->curr_cwnd = max(scc->curr_cwnd, scc->max_could_cwnd);

    printk(KERN_DEBUG "start_probe: curr_cwnd=%u\n", scc->curr_cwnd);
}

static void check_drain_probe(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    if ((scc->last_min_rtt * 20 >> 4) > scc->curr_rtt && is_loss(sk))
        scc->current_mode = MODE_DRAIN_PROBE;
}

static void check_epoch_probes_rtt_bw(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    if (scc->epp_min_rtt) {
        scc->epp_min_rtt = 0;
        scc->current_mode = MODE_PROBE_BW;
    } else {
        if(!rtt_check(sk) && scc->unfair_flag >= 30)
            scc->current_mode = MODE_PROBE_RTT;
        else
            scc->current_mode = MODE_PROBE_BW;
    }
}

static void check_probes(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    printk(KERN_DEBUG "check_probes: epp=%u\n", scc->epp);
    if (scc->epp == scc->EPOCH_ROUND) {
        scc->epp = 0;
        scc->EPOCH_ROUND = 10;
        check_epoch_probes_rtt_bw(sk);
        check_drain_probe(sk);
    }
    printk(KERN_DEBUG "check_probes: current_mode=%u\n", scc->current_mode);
}

static u32 spline_cwnd_gain(struct sock *sk, u32 cwnd)
{
    struct scc *scc = inet_csk_ca(sk);
    u64 rtt = scc->last_min_rtt ? scc->last_min_rtt : MIN_RTT_US;
    u64 denom = (scc->bw * USEC_PER_SEC) / rtt;

    if (denom == 0)
        denom = MIN_BW;

    return (u32)(div_u64((u64)cwnd << BW_SCALE_2, denom));
}

// v2
static u32 spline_cwnd_next_gain(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u64 gain;
    u32 rtt;
    fairness_check(sk);
    spline_max_cwnd(sk);

    rtt = scc->last_min_rtt;
    rtt =  scc->last_min_rtt ? scc->last_min_rtt : MIN_RTT_US;
    printk(KERN_DEBUG "cwnd_next_gain: before curr_cwnd=%u, max_could_cwnd=%u, cwnd_gain=%u, unfair_flag=%u, last_cwnd=%u, curr_rtt=%u\n",
         scc->curr_cwnd, scc->max_could_cwnd, scc->cwnd_gain, scc->unfair_flag, scc->last_cwnd, scc->curr_rtt);

    if(ack_check(sk) && (!rtt_check(sk) || scc->unfair_flag >= 10) || scc->unfair_flag >= 60)
    {
        scc->cwnd_gain = spline_cwnd_gain(sk, scc->last_ack);
        if(scc->cwnd_gain < 65536U)
            scc->cwnd_gain = 65536U;

        rtt = (rtt + scc->curr_rtt) >> 1;
        gain = (u64)scc->cwnd_gain * scc->bw * USEC_PER_SEC;
        printk(KERN_DEBUG "cwnd_next_gain_inslide: before curr_cwnd=%u\n", scc->curr_cwnd);
        scc->curr_cwnd = (u32)(div_u64(gain, rtt) >> BW_SCALE_2) + (scc->curr_ack >> 2) + scc->max_could_cwnd;
    } else {
        scc->cwnd_gain = spline_cwnd_gain(sk, scc->curr_ack);
        if(scc->cwnd_gain < 65536U)
            scc->cwnd_gain = 65536U;
        printk(KERN_DEBUG "cwnd_next_gain_no_inslide: before curr_cwnd=%u\n", scc->curr_cwnd);
        gain = (u64)scc->cwnd_gain * scc->bw * scc->max_could_cwnd * USEC_PER_SEC;
        scc->curr_cwnd = (u32)(div_u64(gain, rtt) >> BW_SCALE_2) + scc->curr_ack;
        if(scc->fairness_rat < 65536U)
            scc->fairness_rat = 65536U;
        scc->curr_cwnd = (u32)(((u64)scc->fairness_rat * scc->curr_cwnd) >> BW_SCALE_2);
    }
    printk(KERN_DEBUG "cwnd_next_gain: after curr_cwnd=%u, scc->loss_flag=%u\n", scc->curr_cwnd, scc->max_could_cwnd);
    return scc->curr_cwnd;
}

static void spline_save_cwnd(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);

    if (scc->prev_ca_state < TCP_CA_Recovery && scc->current_mode != MODE_PROBE_RTT)
        scc->prior_cwnd = tcp_snd_cwnd(tp);
    else
        scc->prior_cwnd = max(scc->prior_cwnd, SCC_MIN_SND_CWND);
}

static void spline_check_main(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    scc->curr_cwnd = scc->curr_cwnd ? scc->curr_cwnd : SCC_MIN_SEGMENT_SIZE;
    scc->mss = scc->mss ? scc->mss : SCC_MIN_SEGMENT_SIZE;
}

static void update_probes(struct sock *sk, const struct rate_sample *rs)
{
    struct scc *scc = inet_csk_ca(sk);

    check_probes(sk);
    switch (scc->current_mode) {
    case MODE_START_PROBE:
        start_probe(sk);
        break;
    case MODE_PROBE_BW:
        spline_cwnd_next_gain(sk, rs);
        break;
    case MODE_PROBE_RTT:
        spline_cwnd_next_gain(sk, rs);
        probe_rtt(sk);
        break;
    case MODE_DRAIN_PROBE:
        drain_probe(sk);
        break;
    default:
        spline_cwnd_next_gain(sk, rs);
    }
}

static void update_bytes_in_flight(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u64 inflight = (u64)tcp_packets_in_flight(tp) * scc->mss;

    scc->bytes_in_flight = (inflight > 0xFFFFFFFFU) ? 0xFFFFFFFFU : (u32)inflight;
}

static void update_last_acked_sacked_cwnd_mss(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);

    if (scc->mss == 0)
        scc->mss = SCC_MIN_SEGMENT_SIZE;

    scc->last_ack = scc->curr_ack;

    if (!rs) {
        scc->curr_ack = 0;
        scc->last_acked_sacked = 0;
    } else {
        if (rs->delivered < 0 || rs->delivered > 0x7FFFFFFF) {
            printk(KERN_DEBUG "update_last_acked_sacked_cwnd_mss: invalid delivered=%d, resetting to 0\n",
                 rs->delivered);
            scc->curr_ack = 0;
            scc->last_acked_sacked = 0;
        } else {
            scc->curr_ack = (u64)rs->delivered * scc->mss;
            scc->last_acked_sacked = (u64)rs->acked_sacked * scc->mss;
        }
    }

    scc->min_cwnd = SCC_MIN_SND_CWND;
    if (scc->mss == 0)
        scc->mss = SCC_MIN_SEGMENT_SIZE;

    spline_check_main(sk);
    scc->curr_cwnd = (u64)tcp_snd_cwnd(tp) * scc->mss;

    if (scc->curr_cwnd > scc->last_max_cwnd)
        scc->last_max_cwnd = scc->curr_cwnd;
}

static void spline_update(struct sock *sk, const struct rate_sample *rs)
{
    update_min_rtt(sk, rs);
    update_bytes_in_flight(sk);
    update_last_acked_sacked_cwnd_mss(sk, rs);
    fairness_check(sk);
    update_bandwidth_throughput(sk, rs);
    update_probes(sk, rs);
}

static void spline_cwnd_send(struct sock *sk, const struct rate_sample *rs)
{
    struct scc *scc = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    u32 cwnd_segments;

    spline_update(sk, rs);

    if (scc->mss == 0)
        scc->mss = SCC_MIN_SEGMENT_SIZE;
    cwnd_segments = scc->curr_cwnd / scc->mss;
    if (cwnd_segments < (SCC_MIN_SND_CWND / scc->mss + 1))
        cwnd_segments = (SCC_MIN_SND_CWND + scc->mss - 1) / scc->mss;

    printk(KERN_DEBUG "spline_cwnd_send: curr_cwnd=%u, mss=%u, cwnd_segments=%u\n",
         scc->curr_cwnd, scc->mss, cwnd_segments);
    scc->last_cwnd = scc->curr_cwnd;
    tcp_snd_cwnd_set(tp, min(cwnd_segments, tp->snd_cwnd_clamp));
}

static void spline_cong_control(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);

    scc->mss = tp->mss_cache;
    scc->curr_cwnd = tcp_snd_cwnd(tp) * tp->mss_cache;
    tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
    scc->min_cwnd = SCC_MIN_SND_CWND;
    scc->prev_ca_state = TCP_CA_Open;
    if(!scc->current_mode)
        scc->current_mode = MODE_START_PROBE;
    scc->last_min_rtt_stamp = tcp_jiffies32;

    spline_cwnd_send(sk, rs);
}

static u32 spline_undo_cwnd(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    scc->curr_cwnd = tcp_snd_cwnd(tcp_sk(sk)) * SCC_MIN_SEGMENT_SIZE;
    return tcp_snd_cwnd(tcp_sk(sk));
}

static void spline_set_state(struct sock *sk, u8 new_state)
{
    struct scc *scc = inet_csk_ca(sk);

    if (new_state == TCP_CA_Loss)
        scc->prev_ca_state = TCP_CA_Loss;
    else
        scc->prev_ca_state = TCP_CA_Open;

    pr_debug("spline_set_state: sk=%p, new_state=%u\n", sk, new_state);
}

static void spline_init(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    scc->last_max_cwnd = 0;
    scc->last_min_rtt = 0;
    scc->bw = 0;
    scc->throughput = 0;
    scc->curr_rtt = 0;
    scc->curr_ack = 0;
    scc->last_ack = 0;
    scc->fairness_rat = 0;
    scc->prior_cwnd = 0;
    scc->epp = 0;
    scc->epp_min_rtt = 0;
    scc->bytes_in_flight = 0;
    scc->max_could_cwnd = 0;
    scc->cwnd_gain = 0;
    scc->curr_cwnd = SCC_MIN_SND_CWND;
    scc->mss = SCC_MIN_SEGMENT_SIZE;
    scc->current_mode = MODE_START_PROBE;
    scc->EPOCH_ROUND = 100;
}

static u32 spline_ssthresh(struct sock *sk)
{
    spline_save_cwnd(sk);
    return tcp_sk(sk)->snd_ssthresh;
}

static u32 spline_sndbuf_expand(struct sock *sk)
{
    return 3;
}

static void spline_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
    struct scc *scc = inet_csk_ca(sk);

    if (event == CA_EVENT_CWND_RESTART || event == CA_EVENT_TX_START) {
        scc->prev_ca_state = TCP_CA_Open;
        scc->curr_cwnd = SCC_MIN_SND_CWND;

        if (scc->mss == 0)
            scc->mss = SCC_MIN_SEGMENT_SIZE;
    }
}

static struct tcp_congestion_ops spline_cc_ops __read_mostly = {
    .init       = spline_init,
    .ssthresh   = spline_ssthresh,
    .cong_control   = spline_cong_control,
    .sndbuf_expand  = spline_sndbuf_expand,
    .cwnd_event = spline_cwnd_event,
    .undo_cwnd  = spline_undo_cwnd,
    .set_state  = spline_set_state,
    .owner      = THIS_MODULE,
    .name       = "spline_cc",
};

static int __init spline_cc_register(void)
{
    int ret;

    BUILD_BUG_ON(sizeof(struct scc) > ICSK_CA_PRIV_SIZE);

    ret = tcp_register_congestion_control(&spline_cc_ops);
    if (ret < 0) {
        pr_err("spline_cc: registration failed with error %d\n", ret);
        return ret;
    }

    pr_info("spline_cc: successfully registered\n");
    return 0;
}

static void __exit spline_cc_unregister(void)
{
    tcp_unregister_congestion_control(&spline_cc_ops);
}

module_init(spline_cc_register);
module_exit(spline_cc_unregister);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bekzhan Kalimollayev");
MODULE_DESCRIPTION("Spline Congestion Control for Linux Kernel");
