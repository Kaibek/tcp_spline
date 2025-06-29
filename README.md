# TCP Congestion Control Algorithm Spline

## Introduction

The **Spline** algorithm is a TCP congestion control module developed for the Linux kernel, optimized for unstable network conditions such as wireless networks with high packet loss and significant delays. It combines elements of the **BBR** (Bottleneck Bandwidth and Round-trip propagation time) model with adaptive loss-oriented algorithms (Cubic/Reno) to maximize throughput and minimize latency. Key objectives include:

- Maximizing throughput.
- Minimizing latency (RTT).
- Reducing retransmissions.
- Ensuring fair resource allocation.

## Architecture and Operating Principles

Spline is a hybrid algorithm with a model-oriented approach and adaptive logic. It integrates bandwidth probing (as in BBR) with adaptation to packet loss and latency (as in Cubic/Reno), using estimated bandwidth (`bw`) and minimum RTT (`last_min_rtt`) to assess network conditions.

The algorithm dynamically switches modes based on network state, leveraging an epoch counter (`epp`) and custom stability checks. This allows adaptation to variable channel conditions, such as sudden latency spikes or packet loss (see *Response to Instability*).

## Main Operating Modes

Spline uses a state machine with four modes and adaptive transitions:

- **MODE_START_PROBE**: Doubles `curr_cwnd` for initial transmission, constrained by `max_could_cwnd` and loss detection.
- **MODE_PROBE_BW**: Aggressively increases `cwnd`, adjusting growth via `fairness_rat` for competition.
- **MODE_PROBE_RTT**: Reduces `cwnd` to minimize queuing and RTT, considering stability and load.
- **MODE_DRAIN_PROBE**: Lowers the window to estimated bandwidth during congestion to clear queues.

Mode transitions are managed by `check_probes`, based on `epp` and anomaly detection.

## Custom Implementations

Spline introduces unique metrics and mechanisms:

- **fairness_rat**: Fairness metric, calculated as `(bw / throughput) + 1`. Regulates `cwnd` aggressiveness and enhances `max_could_cwnd`. Reduces aggression when `< 3` to yield to competitors.
- **max_could_cwnd**: Dynamically computed maximum `cwnd`, balancing bandwidth and fairness:  
  `max_could_cwnd = fairness_rat * bw_ack / (bw_inflight/4) + G`  
  where \( G = curr_ack / 2 \) if `curr_ack > last_ack`, else \( SEGMENT_SIZE * 2 \). Limits `curr_cwnd` during congestion or loss.
- **bw_inflight (In-flight Bandwidth)**: Estimates bandwidth from `bytes_in_flight`:  
  `throughput = bytes_in_flight * USEC_PER_SEC * (1 << BW_SCALE) / last_min_rtt`. Reflects network load for `fairness_rat` and congestion assessment.

These are integrated into functions like `probe_bw`, `probe_rtt`, `start_probe`, and `drain_probe`.

## Response to Network Instability

Spline is designed for unstable and congested conditions:

- **Channel Congestion**: Activates `MODE_DRAIN_PROBE` if `curr_cwnd` exceeds `bw` or `curr_rtt` increases ~1.25x over `last_min_rtt`, reducing the window to `bw`.
- **ACK Instability**: Checks `last_ack < curr_ack`; limits `cwnd` growth if ACKs lag, preventing traffic spikes.
- **Bufferbloat**: Reduces `curr_cwnd` via `overload_rtt_bw` and `stable_rtt_bw` if `curr_rtt` exceeds `last_min_rtt` by >1.25x to clear queues.
- **RTT Variability**: Updates `last_min_rtt` every 10 seconds or on new minima, adapting to latency changes.

This ensures dynamic response to jitter, loss, and queues.

## Comparison with BBR

Spline shares BBR's model-oriented approach (using `bw` and `last_min_rtt`), but differs in adaptation:

- **Fairness and Loss**: Introduces `fairness_rat` and `max_could_cwnd` to yield to congested flows and reduce `cwnd` during losses, unlike BBR.
- **Instability Adaptation**: Targets wireless/unstable networks, responding to ACK delays, RTT spikes, and losses via mode transitions, while BBR is optimized for stable channels.
- **Aggressiveness**: Adjusts `cwnd` growth based on load and `fairness_rat`, unlike BBR's constant target, slowing growth in poor conditions.

Spline excels in high-loss/jitter scenarios; BBR suits stable, high-throughput channels.

## Results

- **Testing Conditions**: Almaty, Kazakhstan; 500 Mbps internet, 5 GHz Wi-Fi.
- **Platform**: Ubuntu 24.04.2 LTS (Linux 6.8.12), 4 GB RAM, Wi-Fi, using `wget`.

#### 3 GB File (ubuntu-24.04.2-live-server-amd64.iso)
- **BBR**: ~16.0 MB/s (2.99 GB in 3 min 38 s), 11.9% lost segments, 13.6% retransmissions.
- **Spline**: ~19.6 MB/s (2.99 GB in 2 min 20 s), 11.4% lost segments, 12.6% retransmissions.

#### 6 GB File (ubuntu-24.04.2-desktop-amd64.iso)
- **BBR**: ~17.1 MB/s (5.91 GB in 7 min 12 s), 10.0% lost segments, 1.5% retransmissions.
- **Spline**: ~19.8 MB/s (5.91 GB in 5 min 06 s), 8.6% lost segments, 1.1% retransmissions.

#### 6 GB File with 20% (±5%) Loss
- **Config**: `tc qdisc add dev enp0s3 root netem loss 20% 5%`
- **BBR**: ~11.3 MB/s (5.91 GB in 8 min 56 s), 8.4% lost segments, 0.5% retransmissions.
- **Spline**: ~13.2 MB/s (5.91 GB in 7 min 38 s), 10.5% lost segments, 0.6% retransmissions.

### Conclusion
- Spline achieves higher speeds (13.2–19.8 MB/s) than BBR (11.3–17.1 MB/s), reducing transfer time.
- In the first two tests, Spline shows lower loss and retransmissions with higher speeds.
- With 20% (±5%) loss, Spline trades some loss for higher throughput.
- Spline is more aggressive and efficient under high instability.

## Potential Improvements

- Optimize for low-bandwidth networks (e.g., 10 Mbps emulation).
- Test and calibrate `fairness_rat` under multi-flow competition.
- Refine ACK delay checks.

## Installation

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/Kaibek/tcp_spline.git
   cd tcp_spline
   ```

2. **Build the Module**  
   - Copy `tcp_spline.c` to the kernel source directory (e.g., `net/ipv4/`).
   - Configure the kernel: `make menuconfig` and enable custom congestion control.
   - Build: `make -C /lib/modules/$(uname -r)/build M=$(pwd) modules`.
   - Insert: `insmod tcp_spline.ko`.

3. **Activate Spline**  
   - Set as active: `sudo sysctl -w net.ipv4.tcp_congestion_control=spline`.
   - Verify: `sysctl net.ipv4.tcp_congestion_control` (should show `spline`).


## License

This project is licensed under the GPL. See `MODULE_LICENSE("GPL")` in `tcp_spline.c` for details.

## Acknowledgments

Thanks to the Linux kernel community and special gratitude to Bekzhan Kalimollayev for developing Spline.
