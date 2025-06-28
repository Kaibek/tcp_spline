# Spline Congestion Control Algorithm

This repository contains the implementation of Spline, a TCP congestion control algorithm designed to optimize performance in unstable network conditions, such as Wi-Fi with high packet loss and jitter. Developed by Bekzhan Kalimollayev, Spline aims to balance bandwidth utilization, RTT minimization, and fairness, offering a lightweight alternative to existing algorithms like BBR.

## Overview

Spline is a state-machine-based algorithm with four modes: startup probing, bandwidth probing, RTT probing, and drain probing. It dynamically adjusts the congestion window (`curr_cwnd`) based on bandwidth estimates (`bw`), minimum RTT (`last_min_rtt`), and fairness metrics (`fairness_rat`). The code is implemented as a Linux kernel module (`tcp_spline.c`) and has been tested in real-world and simulated environments.

### Key Features
- **Adaptability**: Excels in high-loss scenarios (up to 11.4% packet loss) and jitter (up to 47.9 ms).
- **Performance**: Achieves 25.3 MB/s compared to 20.3 MB/s with BBR in real tests.
- **Fairness**: Includes a fairness ratio to avoid dominating other flows.
- **Efficiency**: Reduces retransmissions (12.6% vs. 13.6% for BBR) and kernel load.

### Testing with `iperf3`
- Install `iperf3`: `sudo apt install iperf3`.
- Run a server: `iperf3 -s` on one machine.
- Run a client with Spline: `iperf3 -c <server_ip> -t 60 -P 1` after setting `net.ipv4.tcp_congestion_control=spline`.
- Compare with BBR by switching to `bbr`.

### Capturing Traffic
- Use `tcpdump` to analyze performance:
  ```bash
  sudo tcpdump -i wlan0 host <server_ip> -w spline_test.pcap
  ```
- Analyze with Wireshark for packet loss and retransmissions.

## Test Results
The results were obtained using tcpdump with the cpap extension for use in wireshark. The results are displayed in PDF files.

### Real-World Network (Wi-Fi, Almaty)
- **Conditions**: 5 GHz Wi-Fi, RTT 172.8–210.8 ms, jitter up to 47.9 ms.
- **Task**: Download 2.99 GB file (`ubuntu-24.04.2-live-server-amd64.iso`).
- **Spline**:
  - Speed: 25.3 MB/s (202.4 Mbit/s).
  - Time: 121 seconds.
  - Packet loss: 11.4% (27,941 packets).
  - Retransmissions: 12.6% (31,055 packets).
  - Kernel drops: 359 packets (~0.14%).
- **BBR**:
  - Speed: 20.3 MB/s (162.4 Mbit/s).
  - Time: 151 seconds.
  - Packet loss: 11.9% (28,452 packets).
  - Retransmissions: 13.6% (32,664 packets).
  - Kernel drops: 751 packets (~0.31%).

### Simulated Network (Mininet)
- **Conditions**: 10 Mbit/s, 200 ms delay, 1% packet loss, 50 ms jitter.
- **Spline**: 0.761–1.07 Mbit/s, 556 retransmissions.
- **BBR**: 0.998–1.25 Mbit/s, 1447 retransmissions.
- Note: BBR performs better in controlled low-loss scenarios.

## Comparison with BBR
- **Strengths**: Spline excels in unstable networks with high loss and jitter.
- **Limitations**: May underperform in low-bandwidth, low-loss conditions compared to BBR.


## License
This project is licensed under the GPL license. See the `MODULE_LICENSE("GPL")` in `tcp_spline.c` for details.
