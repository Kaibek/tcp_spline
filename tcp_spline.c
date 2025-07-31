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
#define MIN_RTT_US      100000   /* 50 ms */
#define MIN_BW          14480    /* Minimum bandwidth in bytes/sec */

#define SCC_MIN_RTT_WIN_SEC 10
#define SCC_MIN_SEGMENT_SIZE 1448
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

    u16 rtt_epoch;
    u16 unfair_flag;
    u16 stable_flag;
    u32 rtt_cnt;

    u16 epp:7,            /* Epoch cycle counter */
        EPOCH_ROUND:7;
    u32 lt_use_bw:1,
        current_mode:3,       /* Current mode (START_PROBE, etc.) */
        prev_ca_state:3,    /* Previous TCP_CA state */
        lt_is_sampling:1,
        lt_rtt_cnt:7,
        round_start:1,
        has_seen_rtt:1,
        hight_round:6,
        loss_cnt:8;
};

#define CYCLE_LEN   8
static const int bbr_bw_rtts = CYCLE_LEN + 2;
static const u32 bbr_lt_bw_diff = 4000 / 8;
static const u64 thresh_tg = 2013567;
static const u32 bbr_lt_bw_ratio = BBR_UNIT >> 3;
static const int bbr_pacing_margin_percent = 1;
static const u32 bbr_lt_bw_max_rtts = 48;
static const u32 bbr_lt_intvl_min_rtts = 4;
static const u32 bbr_lt_loss_thresh = 3;
static const int bbr_high_gain  = BBR_UNIT * 2800 / 1000;
static const int cwnd_rtt_gain  = BBR_UNIT * 1300 / 1000;
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885;
static const int scc_drain_gain = 5646946;
static const int scc_high_gain  = 45646946;

static u32 bytes_in_flight(struct sock *sk);
static void update_last_acked_sacked(struct sock *sk, const struct rate_sample *rs);

static bool check_hight_rtt(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    return ((scc->last_rtt + 1000) < scc->curr_rtt &&
        (scc->last_rtt + scc->rtt_epoch -
            ((scc->rtt_epoch * 3) >> 2)) > scc->curr_rtt);
}

static bool ack_check(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    return ((scc->curr_ack < scc->last_ack + 7000U &&
        scc->last_ack > SCC_MIN_SND_CWND) &&
    scc->curr_ack > scc->last_ack);
}

static bool rtt_check(struct sock *sk)
{
   struct scc *scc = inet_csk_ca(sk);
   return ((scc->last_min_rtt + 1000) < scc->curr_rtt &&
    (scc->last_min_rtt + scc->rtt_epoch -
        ((scc->rtt_epoch * 3) >> 3)) > scc->curr_rtt);
}

static u32 bytes_in_flight(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u32 segment_size, bytes_in_flight;
    segment_size = tp->mss_cache ? tp->mss_cache : SCC_MIN_SEGMENT_SIZE;

    u64 inflight = (u64)tcp_packets_in_flight(tp) * segment_size;

    bytes_in_flight = (inflight > 0xFFFFFFFFU) ? 0xFFFFFFFFU : (u32)inflight;

    return bytes_in_flight;
}

static void hight_rtt_round(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    u32 inflight = bytes_in_flight(sk);
    if(!check_hight_rtt(sk))
        scc->hight_round++;

    if(scc->hight_round == 50 && ack_check(sk) &&
        inflight > scc->curr_cwnd * SCC_MIN_SEGMENT_SIZE)
    {
        scc->hight_round = 0;
        if(scc->rtt_epoch <= 60000)
            scc->rtt_epoch += 4000;
        else
            scc->rtt_epoch = 64000;
    }
    else if(scc->hight_round == 50)
        scc->hight_round = 0;
}

static void fairness_check(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    if(scc->unfair_flag == 1 << 16)
        scc->unfair_flag = 1 << 16;

    else if(!rtt_check(sk) &&
        !ack_check(sk) && !check_hight_rtt(sk))
        scc->unfair_flag++;
}

static void stable_check(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    if(scc->stable_flag == 1 << 16)
        scc->stable_flag = 1 << 16;

    else if(rtt_check(sk) &&
        ack_check(sk) && check_hight_rtt(sk))
        scc->stable_flag++;
}

static void loss_rate(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u32 lost, delivered;
    lost = tp->lost - scc->lt_last_lost;
    delivered = tp->delivered - scc->lt_last_delivered;
    if((lost << BBR_SCALE) > (delivered >> bbr_lt_loss_thresh)) {
        scc->loss_cnt++;
    }
    if(scc->loss_cnt > (1 << 8) - 2)
        scc->loss_cnt = 1 << 7;
}

static u64 scc_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
{
    unsigned int mss = tcp_sk(sk)->mss_cache;

    rate *= mss;
    rate *= gain;
    rate >>= BBR_SCALE;
    rate *= USEC_PER_SEC / 100 * (100 - bbr_pacing_margin_percent);
    return rate >> BW_SCALE_2;
}

static u64 bbr_bw_to_pacing_rate(struct sock *sk, u64 bw, int gain)
{
    u64 rate = bw;

    rate = scc_rate_bytes_per_sec(sk, rate, gain);
    rate = min_t(u64, rate, READ_ONCE(sk->sk_max_pacing_rate));
    return rate;
}

static void bbr_init_pacing_rate_from_rtt(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u64 bw;
    u32 rtt_us;

    if (tp->srtt_us) {      /* any RTT sample yet? */
        rtt_us = max(tp->srtt_us >> 3, 1U);
        scc->has_seen_rtt = 1;
    } else {             /* no RTT sample yet */
        rtt_us = USEC_PER_MSEC;  /* use nominal default RTT */
    }
    bw = (u64)tcp_snd_cwnd(tp) * BW_UNIT;
    do_div(bw, rtt_us);
    WRITE_ONCE(sk->sk_pacing_rate,
           bbr_bw_to_pacing_rate(sk, bw, scc->pacing_gain));
}

/* Pace using current bw estimate and a gain factor. */
static void bbr_set_pacing_rate(struct sock *sk, u32 bw, int gain)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    unsigned long rate = bbr_bw_to_pacing_rate(sk, bw, gain);

    if (unlikely(!scc->has_seen_rtt && tp->srtt_us))
        bbr_init_pacing_rate_from_rtt(sk);
    if (rate > READ_ONCE(sk->sk_pacing_rate))
        WRITE_ONCE(sk->sk_pacing_rate, rate);
}

static void scc_reset_lt_bw_sampling_interval(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);

    scc->lt_last_stamp = div_u64(tp->delivered_mstamp, USEC_PER_MSEC);
    scc->lt_last_delivered = tp->delivered;
    scc->lt_last_lost = tp->lost;
    scc->lt_rtt_cnt = 0;
}

static void scc_reset_lt_bw_sampling(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    scc->lt_bw = 0;
    scc->lt_use_bw = 0;
    scc->lt_is_sampling = false;
    scc->lt_rtt_cnt = 0;
    scc_reset_lt_bw_sampling_interval(sk);
}

static u64 bandwidth(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    u64 tmp_bw, bw;
    tmp_bw = (scc->curr_ack << BW_SCALE_2) * 10000;
    bw = div_u64(tmp_bw, scc->last_min_rtt);
    bw = max(bw, MIN_BW);
    return bw;
}

static u32 inflight_throughput(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    u64 tmp_tp, tp;
    u32 inflight = bytes_in_flight(sk);
    inflight = inflight ? inflight : 448; 
    tmp_tp = (u64)inflight * 10000;
    tp = div_u64(tmp_tp, scc->last_min_rtt);

    return (u32)tp;
}

static u32 fairness_rat(u64 gamma, u32 beta)
{
    u32 fairness_rat;
    if (!beta)
    beta = (u32)(gamma >> 2) >> BW_SCALE_2;
    fairness_rat = gamma / (beta + MIN_BW);

    if(fairness_rat < 6646946U)
        fairness_rat = 6646946U;
    if(fairness_rat > 21989530U)
        fairness_rat = 21989530U;

    return fairness_rat;
}

static u32 update_bandwidth(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    u32 beta;
    u64 bw, throughput;
    bw = bandwidth(sk);
    throughput = inflight_throughput(sk);

    scc->fairness_rat = fairness_rat(bw, throughput);
    bw = bw >> BW_SCALE_2;

    return max((u32)bw, MIN_BW);
}

static void scc_lt_bw_interval_done(struct sock *sk, u32 bw)
{
    struct scc *scc = inet_csk_ca(sk);
    u32 diff;

    if (scc->lt_bw) {  /* do we have bw from a previous interval? */
        /* Is new bw close to the lt_bw from the previous interval? */
        diff = abs(bw - scc->lt_bw);
        if ((diff * BBR_UNIT <= bbr_lt_bw_ratio * scc->lt_bw) ||
            (scc_rate_bytes_per_sec(sk, diff, BBR_UNIT) <=
             bbr_lt_bw_diff)) {
            /* All criteria are met; estimate we're policed. */
            scc->lt_bw = (bw + scc->lt_bw) >> 1;  /* avg 2 intvls */
            scc->lt_use_bw = 1;
            scc->pacing_gain = BBR_UNIT;
            return;
        }
    }
    scc->lt_bw = bw;
    scc_reset_lt_bw_sampling_interval(sk);
}

static void scc_lt_bw_sampling(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u32 lost, delivered, t;
    u64 bw;

    if (scc->lt_use_bw) {   /* already using long-term rate, lt_bw? */
        if (scc->current_mode == MODE_PROBE_BW && scc->round_start &&
            ++scc->lt_rtt_cnt >= bbr_lt_bw_max_rtts) {
            scc_reset_lt_bw_sampling(sk);    /* stop using lt_bw */
        }
        return;
    }

    if (!scc->lt_is_sampling) {
        if (!rs->losses)
            return;
        scc_reset_lt_bw_sampling_interval(sk);
        scc->lt_is_sampling = true;
    }

    if (rs->is_app_limited) {
        scc_reset_lt_bw_sampling(sk);
        return;
    }

    if (scc->round_start)
        scc->lt_rtt_cnt++;  /* count round trips in this interval */
    if (scc->lt_rtt_cnt < bbr_lt_intvl_min_rtts)
        return;     /* sampling interval needs to be longer */
    if (scc->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
        scc_reset_lt_bw_sampling(sk);  /* interval is too long */
        return;
    }
    if (!rs->losses)
        return;

    /* Calculate packets lost and delivered in sampling interval. */
    lost = tp->lost - scc->lt_last_lost;
    delivered = tp->delivered - scc->lt_last_delivered;
    /* Is loss rate (lost/delivered) >= lt_loss_thresh? If not, wait. */
    if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)
        return;

    /* Find average delivery rate in this sampling interval. */
    t = div_u64(tp->delivered_mstamp, USEC_PER_MSEC) - scc->lt_last_stamp;
    if ((s32)t < 1)
        return;     /* interval is less than one ms, so wait */
    /* Check if can multiply without overflow */
    if (t >= ~0U / USEC_PER_MSEC) {
        scc_reset_lt_bw_sampling(sk);  /* interval too long; reset */
        return;
    }
    t *= USEC_PER_MSEC;
    bw = (u64)delivered * BW_UNIT;
    do_div(bw, t);
    scc_lt_bw_interval_done(sk, bw);
}

static u32 scc_bdp(struct sock *sk, u64 bw, int gain)
{
    struct scc *scc = inet_csk_ca(sk);
    u32 bdp;
    u64 w = bw;

    if (unlikely(scc->last_min_rtt == ~0U))
        return TCP_INIT_CWND;

    w = bw * scc->last_min_rtt;
    bdp = (((w * gain) >> BW_SCALE_2) + BW_UNIT - 1) / BW_UNIT;

    return bdp;
}

static u32 scc_inflight(struct sock *sk, u32 bw, int gain)
{
    u32 inflight;

    inflight = scc_bdp(sk, bw, gain);

    return inflight;
}

static u32 scc_max_bw(const struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    u32 bw_max;
    if(scc->loss_cnt < 50)
        bw_max = max(scc->bw, (u32)bandwidth(sk));
    else
        bw_max = scc->bw;
    return bw_max;
}

static u32 scc_bw(const struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    return scc->lt_use_bw ? scc->lt_bw : scc_max_bw(sk);
}

static u32 scc_packets_in_net_at_edt(struct sock *sk, u32 inflight_now)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u64 now_ns, edt_ns, interval_us;
    u32 interval_delivered, inflight_at_edt;

    now_ns = tp->tcp_clock_cache;
    edt_ns = max(tp->tcp_wstamp_ns, now_ns);
    interval_us = div_u64(edt_ns - now_ns, NSEC_PER_USEC);
    interval_delivered = (u64)scc_bw(sk) * interval_us >> BW_SCALE_2;
    inflight_at_edt = inflight_now;
    if (interval_delivered >= inflight_at_edt)
        return 0;
    return inflight_at_edt - interval_delivered;
}

static bool scc_is_next_cycle_phase(struct sock *sk,
                    const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    bool is_full_length =
            tcp_stamp_us_delta(tp->tcp_wstamp_ns, scc->cycle_mstamp) > 1;
    scc->cycle_mstamp = tp->tcp_wstamp_ns;
    u64 bw = (u64)scc_bw(sk);
    u32 inflight = scc_packets_in_net_at_edt(sk, rs->prior_in_flight);

    if (scc->pacing_gain == BBR_UNIT)
        return is_full_length;

    if (scc->pacing_gain > BBR_UNIT)
        return is_full_length &&
            (rs->losses ||  /* perhaps pacing_gain*BDP won't fit */
             inflight >= scc_inflight(sk, bw, scc->pacing_gain));

    return is_full_length ||
        inflight <= scc_inflight(sk, bw, scc->gain);
}

static void scc_update_bw(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u64 bw;

    scc->round_start = 0;
    if (rs->delivered < 0 || rs->interval_us <= 0)
        return; /* Not a valid observation */

    /* See if we've reached the next RTT */
    if (!before(rs->prior_delivered,
        scc->delivered)) {
        scc->delivered = tp->delivered * SCC_MIN_SEGMENT_SIZE;
        scc->rtt_cnt++;
        scc->round_start = 1;
    }
    scc_lt_bw_sampling(sk, rs);

    bw = div64_long((u64)rs->delivered * BW_UNIT, rs->interval_us);

    if (!rs->is_app_limited || bw >= scc_max_bw(sk)) {
        /* Incorporate new sample into our max bw filter. */
    scc->bw = bw;
    }
}

static void update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
    struct scc *scc = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    bool new_min_rtt = after(tcp_jiffies32, scc->last_min_rtt_stamp + SCC_MIN_RTT_WIN_SEC * HZ);

    scc->last_rtt = scc->curr_rtt;
    if (tp->srtt_us) {
        scc->curr_rtt = tp->srtt_us >> 3;
        if(!scc->last_rtt)
            scc->last_rtt = scc->curr_rtt;
    } else
        scc->curr_rtt = MIN_RTT_US;

    if (scc->curr_rtt < scc->last_min_rtt || scc->last_min_rtt == 0) {
        scc->last_min_rtt = scc->curr_rtt;
    } if (rs && rs->rtt_us > 0 && (rs->rtt_us < scc->last_min_rtt ||
         (new_min_rtt && !rs->is_ack_delayed))) {
        scc->last_min_rtt = rs->rtt_us;
        scc->last_min_rtt_stamp = tcp_jiffies32;
    } if (scc->last_min_rtt == 0) {
        scc->last_min_rtt = MIN_RTT_US;
    } if (scc->last_min_rtt > scc->curr_rtt) {
        scc->last_min_rtt = scc->curr_rtt;
    }
    scc->epp++;
}

static u32 spline_max_cwnd(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    u64 tmp, bw;
    u32 max_could_cwnd, throughput;
    throughput = inflight_throughput(sk);
    bw = bandwidth(sk);

    if (!(throughput << 2))
        throughput = 1;

    tmp = ((u64)scc->fairness_rat * (u64)scc->curr_cwnd) >> BW_SCALE_2;
    max_could_cwnd = tmp;
    max_could_cwnd = max_could_cwnd ? max_could_cwnd : (SCC_MIN_SND_CWND << 1);

    return max_could_cwnd;
}

static u64 percent_gain(u32 last_lost, u32 st, u32 un)
{
    u64 tg;
    st = st ? st : 1;
    un = un ? un : 1;
    tg = ((((u64)st * 3) << BW_SCALE_2) >> 2) /
    (((last_lost + un * 3)) >> 1);
    return tg;
}

static void start_probe(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    scc->curr_cwnd = SCC_MIN_SND_CWND + (scc->curr_cwnd << 1);
    scc->curr_cwnd = max(scc->curr_cwnd, SCC_MIN_SND_CWND);
}

static void check_drain_probe(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    if (!rtt_check(sk) && !ack_check(sk) && scc->lt_last_lost >
        bbr_lt_loss_thresh * 3 << 1)
        scc->current_mode = MODE_DRAIN_PROBE;
}

static void check_epoch_probes_rtt_bw(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    u64 tg = percent_gain(scc->lt_last_lost, scc->stable_flag, scc->unfair_flag);
    if(tg < thresh_tg)
        scc->current_mode = MODE_PROBE_RTT;
    else
        scc->current_mode = MODE_PROBE_BW;
    }

static void check_probes(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    if (scc->epp == scc->EPOCH_ROUND) {
        scc->epp = 0;
        scc->EPOCH_ROUND = 20;
        check_epoch_probes_rtt_bw(sk);
        check_drain_probe(sk);
    }
}

static u32 spline_cwnd_gain(struct sock *sk, u32 cwnd)
{
    struct scc *scc = inet_csk_ca(sk);
    u64 rtt = scc->last_min_rtt ? scc->last_min_rtt : MIN_RTT_US;
    u64 denom = (bandwidth(sk) * USEC_PER_SEC) / rtt;

    if (denom == 0)
        denom = MIN_BW;

    return (u32)(div_u64((u64)cwnd << BW_SCALE_2, denom));
}

static void gains_mode(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);

    switch (scc->current_mode) {
    case MODE_PROBE_BW:
        scc->pacing_gain = bbr_high_gain;
        break;
    case MODE_PROBE_RTT:
        scc->pacing_gain = bbr_drain_gain;
        break;
    case MODE_DRAIN_PROBE:
        scc->pacing_gain = bbr_drain_gain;
        scc->cwnd_gain = scc_drain_gain;
        break;
    default:
        scc->pacing_gain = bbr_high_gain;
    }
}

static u64 cwnd_gain(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    u64 cwnd_gain;
    cwnd_gain = (u64)spline_cwnd_gain(sk, scc->curr_ack);
    if(cwnd_gain < 6646946U)
        cwnd_gain = 6646946U;

    if(cwnd_gain > 45390997U)
        cwnd_gain = 45390997U;

    return cwnd_gain;
}

static u32 spline_gain(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u64 cwnd_spline_gain, gain;
    u32 rtt, bw;
    bw = (u32)bandwidth(sk);
    gains_mode(sk);
    cwnd_spline_gain = cwnd_gain(sk);

    rtt = scc->last_min_rtt;
    rtt =  scc->last_min_rtt ? scc->last_min_rtt : MIN_RTT_US;
    gain = cwnd_spline_gain * bw * USEC_PER_SEC;

    if(gain < 6646946U)
        gain = 6646946U;
    if(gain > 47390997U)
        gain = 43390997U;
    scc->gain = gain;
    scc->cwnd_gain = cwnd_spline_gain;

    return rtt;
}

static u32 cwnd_loss_phase(struct sock *sk, u64 gain, u32 rtt)
{
    struct scc *scc = inet_csk_ca(sk);

    u32 cwnd;
    rtt = (rtt + scc->curr_rtt) >> 1;

    cwnd = (u32)(div_u64(scc->gain, rtt));
    cwnd = (u32)(((u64)scc->fairness_rat * cwnd) >> BW_SCALE_2);
    return cwnd;
}

static u32 cwnd_stable_phase(u64 gain, u32 rtt)
{
    u32 cwnd;
    cwnd = (u32)(div_u64(gain, rtt)) >> BW_SCALE_2;
    return cwnd;
}

static void loss_cwnd(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    u32 ls = scc->loss_cnt;
    if (ls > 11) {
        ls = 11;
    }
    if (ls > 9) {
        scc->curr_cwnd = (u32)((u64)scc->curr_cwnd * ls * ls * ls) >> ls;
    }
}

static void spline_cwnd_next_gain(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u64 tg;
    u32 rtt, cwnd, new_cwnd;

    rtt = spline_gain(sk);
    cwnd = spline_max_cwnd(sk);
    tg = percent_gain(scc->lt_last_lost, scc->stable_flag, scc->unfair_flag);
    if(scc->unfair_flag >= 2000 || !check_hight_rtt(sk)) {
        scc->curr_cwnd = cwnd_loss_phase(sk, scc->gain, rtt);
    } else {
        rtt = scc->last_min_rtt;
        scc->curr_cwnd = cwnd_stable_phase(scc->gain, rtt);
    }
    if(tg < thresh_tg)
        scc->curr_cwnd = (scc->curr_cwnd * tg) >> BW_SCALE;
    scc->curr_cwnd = max(scc->curr_cwnd, cwnd);
    loss_cwnd(sk);
    scc->curr_cwnd += rs->acked_sacked;
}

static void spline_save_cwnd(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u32 prior_cwnd;
    if (scc->prev_ca_state < TCP_CA_Recovery && scc->current_mode != MODE_PROBE_RTT)
        prior_cwnd = tcp_snd_cwnd(tp);
    else
        prior_cwnd = max(prior_cwnd, SCC_MIN_SND_CWND);
}

static void update_probes(struct sock *sk, const struct rate_sample *rs)
{
    struct scc *scc = inet_csk_ca(sk);

    check_probes(sk);
    switch (scc->current_mode) {
    case MODE_START_PROBE:
        scc->pacing_gain = bbr_high_gain;
        start_probe(sk);
        break;
    case MODE_PROBE_BW:
        spline_cwnd_next_gain(sk, rs);
        break;
    case MODE_PROBE_RTT:
        spline_cwnd_next_gain(sk, rs);
        break;
    case MODE_DRAIN_PROBE:
        spline_cwnd_next_gain(sk, rs);
        break;
    default:
        spline_cwnd_next_gain(sk, rs);
    }
}

static void update_last_acked_sacked(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u32 segment_size;
    segment_size = tp->mss_cache ? tp->mss_cache : SCC_MIN_SEGMENT_SIZE;
    scc->last_ack = scc->curr_ack;

    if (!rs) {
        scc->curr_ack = 0;
    } else {
        if (rs->delivered < 0 || rs->delivered > 0x7FFFFFFF) {
            scc->curr_ack = 0;
        } else {
            scc->curr_ack = (u64)rs->delivered * segment_size;
        }
    }
}

static void spline_update(struct sock *sk,
    const struct rate_sample *rs)
{
    struct scc *scc = inet_csk_ca(sk);
    update_min_rtt(sk, rs);
    update_last_acked_sacked(sk, rs);
    if(scc_is_next_cycle_phase(sk, rs) ||
        scc->EPOCH_ROUND == 50)
        update_bandwidth(sk);
    scc_update_bw(sk, rs);
    fairness_check(sk);
    hight_rtt_round(sk);
    stable_check(sk);
    loss_rate(sk);
    update_probes(sk, rs);
}

static u32 next_cwnd(struct sock *sk, const struct rate_sample *rs,
 u32 target_cwnd, u32 cwnd)
{
    struct scc *scc = inet_csk_ca(sk);
    u64 tg = percent_gain(scc->lt_last_lost, scc->stable_flag, scc->unfair_flag);
    if(tg < thresh_tg && scc->EPOCH_ROUND == 20 && 
        scc->loss_cnt > 10){
        return cwnd;
    } 
    else if((scc->unfair_flag > 2000 && scc->stable_flag < 300) || 
        scc->unfair_flag > scc->stable_flag + 500) {
        return ((target_cwnd + cwnd) * 9) >> 4;
    } else {
        return max(target_cwnd, cwnd);
    }
}

static void spline_cwnd_send(struct sock *sk, const struct rate_sample *rs, u32 bw)
{
    struct scc *scc = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    u64 tg = percent_gain(scc->lt_last_lost, scc->stable_flag, scc->unfair_flag);
    u32 cwnd_segments, target_cwnd, max_cwnd;
    target_cwnd = scc_bdp(sk, bw, scc->gain);
    cwnd_segments = next_cwnd(sk, rs, target_cwnd, scc->curr_cwnd);
    cwnd_segments = max(cwnd_segments, SCC_MIN_SND_CWND);
    cwnd_segments += rs->acked_sacked;
    printk(KERN_DEBUG "next_cwnd: tg=%u, EPOCH_ROUND=%u, loss_cnt=%u, cwnd_segments=%u, curr_cwnd=%u, target_cwnd=%u\n", 
        tg, scc->EPOCH_ROUND, scc->loss_cnt, cwnd_segments, scc->curr_cwnd, target_cwnd);
    tcp_snd_cwnd_set(tp, min(cwnd_segments, tp->snd_cwnd_clamp));
}

static void spline_main(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);
    u32 bw;

    spline_update(sk, rs);
    bw = scc_bw(sk);
    bbr_set_pacing_rate(sk, bw, scc->pacing_gain);

    tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
    spline_cwnd_send(sk, rs, bw);
}

static u32 spline_undo_cwnd(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    scc_reset_lt_bw_sampling(sk);
    return tcp_snd_cwnd(tcp_sk(sk));
}

static void spline_set_state(struct sock *sk, u8 new_state)
{
    struct scc *scc = inet_csk_ca(sk);

    if (new_state == TCP_CA_Loss) {
        struct rate_sample rs = { .losses = 1 };

        scc->prev_ca_state = TCP_CA_Loss;
        scc->round_start = 1;
        scc_lt_bw_sampling(sk, &rs);
    }
}

static void spline_init(struct sock *sk)
{
    struct scc *scc = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    scc->last_min_rtt = tcp_min_rtt(tp);
    scc->curr_rtt = 0;
    scc->curr_ack = 0;
    scc->last_ack = 0;
    scc->fairness_rat = 0;
    scc->epp = 0;
    scc->curr_cwnd = SCC_MIN_SND_CWND;
    scc->current_mode = MODE_START_PROBE;
    scc->cycle_mstamp = 0;
    scc->lt_rtt_cnt = 0;
    scc->EPOCH_ROUND = 50;
    scc->rtt_epoch = 4000;
    scc->last_min_rtt_stamp = tcp_jiffies32;
    scc->lt_rtt_cnt = 0;
    scc->hight_round = 0;
    scc->unfair_flag = 0;
    scc->stable_flag = 0;
    scc->cycle_mstamp = 0;
    scc->rtt_cnt = 0;
    scc->loss_cnt = 0;
    bbr_init_pacing_rate_from_rtt(sk);
    scc->round_start = 0;
    scc_reset_lt_bw_sampling(sk);
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
    struct tcp_sock *tp = tcp_sk(sk);
    struct scc *scc = inet_csk_ca(sk);

    if (event == CA_EVENT_TX_START && tp->app_limited) {
        if (scc->current_mode ==  MODE_PROBE_BW)
            bbr_set_pacing_rate(sk, scc_bw(sk), BBR_UNIT);
    }
}

static struct tcp_congestion_ops spline_cc_ops __read_mostly = {
    .init       = spline_init,
    .ssthresh   = spline_ssthresh,
    .cong_control   = spline_main,
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
