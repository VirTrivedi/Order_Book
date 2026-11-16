# Order_Book

A C++ parser that replays a PCAP capture of the NYSE Pillar XDP Integrated Feed, rebuilds a limit order book for every symbol, and prints rolling per-symbol price bars.

This was my first market data project (Oct 2024 – Jan 2025). Later work builds on it: [Market-Data-Processing](https://github.com/VirTrivedi/Market-Data-Processing) and [Fill-Simulator](https://github.com/VirTrivedi/Fill-Simulator).

## What it does

1. Reads packets from a `.pcap` file with libpcap and decodes the Ethernet, IPv4 and UDP headers. Non-IPv4 and non-UDP packets are skipped.
2. Splits each UDP payload into Pillar XDP messages, checking the packet length against the declared size and stopping safely on truncated messages.
3. Handles the XDP message types, including symbol index mapping, add, modify, replace, execution, delete, symbol clear, security status, imbalance, retail price improvement, cross trades and trade cancels.
4. Keeps one `OrderBook` per symbol, applying adds, modifies, replaces, executions and deletes, with prices scaled by each symbol's price scale code.
5. Every 5 seconds of run time, prints a bar per active symbol: high, low, previous close, volume and percent change.

## Build and run

Needs a C++17 compiler and libpcap.

```bash
g++ -std=c++17 -O2 order_book.cpp -o order_book -lpcap
./order_book <capture.pcap>
```

## Limitations

- Single-threaded, and it reads one capture file at a time.
- It reads the packet sequence number but does not detect gaps or request retransmissions.
- Bars are printed on wall-clock time, not on the timestamps in the capture.
