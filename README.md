# Spline: TCP Congestion Control Algorithm

## Project Overview

**Spline** is a custom TCP congestion control algorithm designed for the Linux kernel, inspired by BBR, and aimed at optimizing network connection performance. Unlike traditional algorithms such as TCP Reno or CUBIC, Spline employs a proactive approach by estimating available bandwidth, round-trip time (RTT), and ensuring fair resource allocation among competing flows. The algorithm is well-suited for high-speed and dynamic network environments where high throughput and minimal packet loss are critical.

## Key Features

- **Proactive Network Probing**: Dynamically adapts to network conditions by actively analyzing its state.
- **Bandwidth and RTT Optimization**: Balances high throughput with minimal latency.
- **Fairness**:
  - The `fairness_rat` coefficient prevents bandwidth monopolization by individual flows.
  - The `fairness_check()` function detects channel contention and adjusts the congestion window accordingly.
- **Modular Architecture**: Utilizes a finite state machine with four operational modes: initial probing, bandwidth probing, RTT probing, and drainage.

## How Spline Works

Spline manages congestion through a finite state machine comprising four modes:

1. **Initial Probing (MODE_START_PROBE)**:  
   Increases the congestion window to assess available bandwidth.
2. **Bandwidth Probing (MODE_PROBE_BW)**:  
   Aggressively increases the congestion window with moderate reductions as needed.
3. **RTT Probing (MODE_PROBE_RTT)**:  
   Moderately increases the congestion window, aggressively reduces it during congestion, or maintains stability when appropriate.
4. **Drainage (MODE_DRAIN_PROBE)**:  
   Reduces the congestion window upon detecting congestion or packet loss to stabilize the network.

### Mode Transitions
- Transitions occur:
  - Periodically, every 4 epochs (`EPOCH_ROUND`).
  - Triggered by events such as packet loss, significant RTT increases, or growth in bytes in flight (`inflight`).

### Congestion Window Adjustment
- **Initial Probing**: Doubles the congestion window, adding the minimum segment size.
- **Bandwidth Probing**: Aggressively increases the window with moderate reductions.
- **RTT Probing**: Moderately increases the window, aggressively reduces it during congestion, or maintains its current level as needed.
- **Drainage**: Reduces the window to the estimated bandwidth to stabilize the network.
- **spline_max_cwnd**: Determines an alternative congestion window based on the ratio of acknowledged data to bytes in flight, factoring in the fairness coefficient.
- **spline_cwnd_next_gain**: Selects between the current window (`curr_cwnd`), the maximum allowable window (`max_could_cwnd`), and the maximum window observed during the connection (`last_max_cwnd`) based on network metrics (ACK/SACK, inflight, minRTT, packet loss).

### Parameter Estimation
- **RTT**: Updates minimum and current RTT based on averaged values or new measurements.
- **Bandwidth**: Estimated from acknowledged bytes and bytes in flight, smoothed for stability.
- **Fairness**: Calculated as the ratio of bandwidth to throughput, preventing monopolization.
- **Acknowledgment History**: Algorithm behavior depends on the history of acknowledgments (`last_ack`, `curr_ack`).
- **Packet Loss**: Accounted for through acknowledgment history and the `TCP_CA_Loss` flag.

## Mininet Test Results

Tests were conducted on a channel with a bandwidth of 10 Mbps and a delay of 20 ms. The following table summarizes the performance comparison of Spline against other congestion control algorithms (CUBIC, Reno, BBR) across various configurations.

| Test | Configuration | Average Throughput (Mbps) | Jain’s Fairness Index (J) | Retransmissions (Retr) | Total Throughput (Mbps) |
|------|---------------|---------------------------|---------------------------|------------------------|-------------------------|
| 1 | Spline 4, CUBIC 5 | Spline: 1.75, CUBIC: 0.83 | Overall: 0.817, Spline: 0.992, CUBIC: 0.755 | Spline: 833, CUBIC: 463 | 11.166 |
| 2 | Spline 4, Reno 5 | Spline: 1.525, Reno: 1.149 | Overall: 0.823, Spline: 0.918, Reno: 0.833 | Spline: 213.5, Reno: 966.4 | 11.84 |
| 3 | Spline 4, Reno 4 | Spline: 1.132, Reno: 1.313 | Overall: 0.924, Spline: 0.963, Reno: 0.822 | Spline: 267.75, Reno: 1435.2 | 9.154 |
| 4 | Spline 4, CUBIC 4 | Spline: 1.435, CUBIC: 0.823 | Overall: 0.988, Spline: 0.954, CUBIC: 0.785 | Spline: 945, CUBIC: 533 | 8.94 |
| 5 | Spline 2, CUBIC 4 | Spline: 1.675, CUBIC: 0.974 | Overall: 0.891, Spline: 0.960, CUBIC: 0.809 | Spline: 563, CUBIC: 822 | 7.246 |
| 6 | Spline 2, Reno 4 | Spline: 2.26, Reno: 2.0175 | Overall: 0.981, Spline: 1.0, Reno: 0.918 | Spline: 465, Reno: 1191 | 12.59 |
| 7 | Spline 9 | Spline: 1.36 | Overall: 0.953 | Spline: 0 | 10.49 |
| 8 | Spline, CUBIC | Spline: 4.39, CUBIC: 6.38 | Overall: 0.967 | Spline: 1124, CUBIC: 2005 | 10.77 |
| 9 | Spline, Reno | Spline: 4.23, Reno: 5.66 | Overall: 0.980 | Spline: 44, Reno: 242 | 9.89 |
| 10 | Spline 4, BBR 5 | Spline: 1.43, BBR: 0.981 | Overall: 0.940, Spline: 0.964, BBR: 0.951 | Spline: 271, BBR: 18 | 10.146 |

### Key Observations
- **Throughput**: Spline outperforms CUBIC and Reno in most tests, particularly in configurations with fewer flows (e.g., Spline 2 vs. CUBIC 4: 1.675 Mbps vs. 0.974 Mbps). However, in some cases (e.g., Spline vs. CUBIC, Reno), traditional algorithms achieve higher throughput.
- **Fairness**: Spline exhibits a high Jain’s Fairness Index within its group, often approaching 1.0, indicating equitable resource distribution.
- **Retransmissions**: Spline generally has fewer retransmissions compared to Reno but may be less stable than BBR (e.g., Spline 4 vs. BBR 5: 271 vs. 18 retransmissions).
- **Overall Performance**: Spline delivers consistent performance under high contention, particularly in tests with heavy network loads.

## Compatibility
Currently compatible with Linux kernel version `6.8.12`.

## Installation

To install the Spline algorithm, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/kaibek/tcp_spline.git
   ```
2. Compile the kernel module:
   ```bash
   cd tcp_spline
   make
   ```
3. Load the module:
   ```bash
   sudo insmod tcp_spline.ko
   ```
4. Set Spline as the congestion control algorithm:
   ```bash
   sudo sysctl -w net.ipv4.tcp_congestion_control=spline_cc
   ```

## Configuration

Configurable parameters include:

- **`EPOCH_ROUND`** (default: 4): Frequency of mode transitions.
- **`MIN_RTT_US`** (default: 50 ms): Minimum RTT value.
- **`BW_SCALE`** (default: 12): Scaling factor for bandwidth estimation.

To modify these parameters:
1. Edit the module’s source code.
2. Recompile and reload the module.

## Usage

Once installed, Spline is automatically applied to all new TCP connections. To verify the current congestion control algorithm, execute:

```bash
sysctl net.ipv4.tcp_congestion_control
```

Expected output:
```
net.ipv4.tcp_congestion_control = spline_cc
```

## License

The source code is distributed under the [GNU General Public License v2.0 (GPLv2)](LICENSE).

## Contact

For questions, suggestions, or contributions, please create an issue in the repository or contact us at [kalimollaevbekzhan777@gmail.com](mailto:kalimollaevbekzhan777@gmail.com).
