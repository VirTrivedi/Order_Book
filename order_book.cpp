#include <pcap.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)

// Ethernet Header Definition
struct mac_hdr_t {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

// XDP Message Header Definition
struct XDPMessageHeader {
    uint16_t msg_size;
    uint16_t msg_type;
};

// Enum for Ethertype
enum class ethertype_e : uint16_t {
    ipv4 = 0x0800,
    arp = 0x0806
};

// IPv4 Header Definition
struct ipv4_hdr_t {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

// UDP Header Definition
struct udp_hdr_t {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

// Define message types
constexpr uint16_t MSG_TYPE_ADD_ORDER = 100;
constexpr uint16_t MSG_TYPE_MODIFY_ORDER = 101;
constexpr uint16_t MSG_TYPE_DELETE_ORDER = 102;
constexpr uint16_t MSG_TYPE_REPLACE_ORDER = 104;
constexpr uint16_t MSG_TYPE_ORDER_EXECUTION = 103;
constexpr uint16_t MSG_TYPE_NON_DISPLAYED_TRADE = 110;
constexpr uint16_t MSG_TYPE_CROSS_TRADE = 111;
constexpr uint16_t MSG_TYPE_TRADE_CANCEL = 112;
constexpr uint16_t MSG_TYPE_CROSS_CORRECTION = 113;

// Base Message Header (common fields)
struct MessageHeader {
    uint16_t msgSize;
    uint16_t msgType;
};

// Add Order Message (Msg Type 100)
struct AddOrderMessage : MessageHeader {
    uint64_t orderID;
    uint32_t price;
    uint32_t volume;
    char side; // 'B' for Buy, 'S' for Sell
};

// Modify Order Message (Msg Type 101)
struct ModifyOrderMessage : MessageHeader {
    uint64_t orderID;
    uint32_t price;
    uint32_t volume;
};

// Delete Order Message (Msg Type 102)
struct DeleteOrderMessage : MessageHeader {
    uint64_t orderID;
};

// Replace Order Message (Msg Type 104)
struct ReplaceOrderMessage : MessageHeader {
    uint64_t oldOrderID;
    uint64_t newOrderID;
    uint32_t price;
    uint32_t volume;
};

// Order Execution Message (Msg Type 103)
struct OrderExecutionMessage : MessageHeader {
    uint64_t orderID;
    uint64_t tradeID;
    uint32_t price;
    uint32_t volume;
};

// Function to convert MAC address to human-readable string
std::string macToString(const uint8_t* mac) {
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(mac_str);
}

// Function to parse Ethernet Header
bool parseEthernetHeader(const u_char* data, mac_hdr_t& eth_header) {
    if (data == nullptr) return false;

    std::memcpy(&eth_header, data, sizeof(mac_hdr_t));
    eth_header.ethertype = ntohs(eth_header.ethertype);

    std::cout << "[Ethernet Header] Dest MAC: " << macToString(eth_header.dest_mac)
              << ", Src MAC: " << macToString(eth_header.src_mac)
              << ", Ethertype: 0x" << std::hex << eth_header.ethertype << std::dec << std::endl;

    return true;
}

// Function to parse IPv4 Header
bool parseIPv4Header(const u_char* data, ipv4_hdr_t& ipv4_header) {
    if (data == nullptr) return false;

    std::memcpy(&ipv4_header, data, sizeof(ipv4_hdr_t));
    ipv4_header.total_length = ntohs(ipv4_header.total_length);
    ipv4_header.header_checksum = ntohs(ipv4_header.header_checksum);
    ipv4_header.src_ip = ntohl(ipv4_header.src_ip);
    ipv4_header.dest_ip = ntohl(ipv4_header.dest_ip);

    std::cout << "[IPv4 Header] Src IP: " << ((ipv4_header.src_ip >> 24) & 0xFF) << "."
              << ((ipv4_header.src_ip >> 16) & 0xFF) << "."
              << ((ipv4_header.src_ip >> 8) & 0xFF) << "."
              << (ipv4_header.src_ip & 0xFF)
              << ", Dest IP: " << ((ipv4_header.dest_ip >> 24) & 0xFF) << "."
              << ((ipv4_header.dest_ip >> 16) & 0xFF) << "."
              << ((ipv4_header.dest_ip >> 8) & 0xFF) << "."
              << (ipv4_header.dest_ip & 0xFF) << std::endl;

    return true;
}

// Function to parse UDP Header
bool parseUDPHeader(const u_char* data, udp_hdr_t& udp_header) {
    if (data == nullptr) return false;

    std::memcpy(&udp_header, data, sizeof(udp_hdr_t));
    udp_header.src_port = ntohs(udp_header.src_port);
    udp_header.dest_port = ntohs(udp_header.dest_port);
    udp_header.length = ntohs(udp_header.length);

    std::cout << "[UDP Header] Src Port: " << udp_header.src_port
              << ", Dest Port: " << udp_header.dest_port
              << ", Length: " << udp_header.length << std::endl;

    return true;
}

void printHex(const u_char* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

// Dispatcher function
void handleMessage(const uint8_t* buffer, size_t size) {
    if (size < sizeof(MessageHeader)) {
        std::cerr << "Invalid message size.\n";
        return;
    }

    MessageHeader header;
    std::memcpy(&header, buffer, sizeof(header));

    switch (header.msgType) {
        case MSG_TYPE_ADD_ORDER: {
            if (size < sizeof(AddOrderMessage)) {
                std::cerr << "Invalid Add Order Message size.\n";
                return;
            }
            AddOrderMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Add Order: OrderID=" << msg.orderID << ", Price=" << msg.price
                      << ", Volume=" << msg.volume << ", Side=" << msg.side << "\n";
            break;
        }
        case MSG_TYPE_MODIFY_ORDER: {
            if (size < sizeof(ModifyOrderMessage)) {
                std::cerr << "Invalid Modify Order Message size.\n";
                return;
            }
            ModifyOrderMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Modify Order: OrderID=" << msg.orderID << ", Price=" << msg.price
                      << ", Volume=" << msg.volume << "\n";
            break;
        }
        case MSG_TYPE_DELETE_ORDER: {
            if (size < sizeof(DeleteOrderMessage)) {
                std::cerr << "Invalid Delete Order Message size.\n";
                return;
            }
            DeleteOrderMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Delete Order: OrderID=" << msg.orderID << "\n";
            break;
        }
        case MSG_TYPE_REPLACE_ORDER: {
            if (size < sizeof(ReplaceOrderMessage)) {
                std::cerr << "Invalid Replace Order Message size.\n";
                return;
            }
            ReplaceOrderMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Replace Order: OldOrderID=" << msg.oldOrderID
                      << ", NewOrderID=" << msg.newOrderID << ", Price=" << msg.price
                      << ", Volume=" << msg.volume << "\n";
            break;
        }
        case MSG_TYPE_ORDER_EXECUTION: {
            if (size < sizeof(OrderExecutionMessage)) {
                std::cerr << "Invalid Order Execution Message size.\n";
                return;
            }
            OrderExecutionMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Order Execution: OrderID=" << msg.orderID
                      << ", TradeID=" << msg.tradeID << ", Price=" << msg.price
                      << ", Volume=" << msg.volume << "\n";
            break;
        }
        default:
            std::cerr << "Unknown message type: " << header.msgType << "\n";
            break;
    }
}

// XDP Parsing Function
void parseXDPMessage(const u_char* data, uint16_t length) {
    const u_char* message_ptr = data;
    uint16_t bytes_processed = 0;

    while (bytes_processed < length) {
        if ((bytes_processed + sizeof(MessageHeader)) > length) {
            std::cerr << "[Error] Insufficient data for XDP Message Header\n";
            break;
        }

        MessageHeader header;
        std::memcpy(&header, message_ptr, sizeof(header));
        uint16_t msg_size = header.msgSize;

        if (msg_size < sizeof(MessageHeader)) {
            std::cerr << "[Error] Message size too small.\n";
            break;
        }

        if ((bytes_processed + msg_size) > length) {
            std::cerr << "[Error] Message size exceeds remaining data.\n";
            break;
        }

        std::cout << "[XDP Message] Type: " << header.msgType << ", Size: " << header.msgSize << "\n";

        // Pass the message to the dispatcher
        handleMessage(message_ptr, msg_size);

        // Move to the next message
        bytes_processed += msg_size;
        message_ptr += msg_size;
    }
}

#pragma pack(pop)

// Main Function
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    const char* file_name = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the PCAP file
    pcap_t* handle = pcap_open_offline(file_name, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return 1;
    }

    struct pcap_pkthdr* packet_header;
    const u_char* packet_data;

    // Loop through packets
    while (pcap_next_ex(handle, &packet_header, &packet_data) > 0) {
        std::cout << "Processing packet of size: " << packet_header->len << " bytes" << std::endl;

        // Parse Ethernet Header
        mac_hdr_t eth_header;
        if (!parseEthernetHeader(packet_data, eth_header)) {
            std::cerr << "Error parsing Ethernet header" << std::endl;
            continue;
        }

        // Handle only IPv4 packets
        if (eth_header.ethertype != static_cast<uint16_t>(ethertype_e::ipv4)) {
            std::cerr << "Skipping non-IPv4 packet" << std::endl;
            continue;
        }

        // Parse IPv4 Header
        ipv4_hdr_t ipv4_header;
        if (!parseIPv4Header(packet_data + sizeof(mac_hdr_t), ipv4_header)) {
            std::cerr << "Error parsing IPv4 header" << std::endl;
            continue;
        }

        // Handle only UDP packets
        if (ipv4_header.protocol != 17) { // Protocol 17 = UDP
            std::cerr << "Skipping non-UDP packet" << std::endl;
            continue;
        }

        // Calculate IPv4 Header Length (IHL * 4)
        uint8_t ipv4_header_length = (ipv4_header.version_ihl & 0x0F) * 4;

        // Parse UDP Header
        udp_hdr_t udp_header;
        if (!parseUDPHeader(packet_data + sizeof(mac_hdr_t) + ipv4_header_length, udp_header)) {
            std::cerr << "Error parsing UDP header" << std::endl;
            continue;
        }

        // Extract and parse XDP data
        const u_char* xdp_data = packet_data + sizeof(mac_hdr_t) + ipv4_header_length + sizeof(udp_hdr_t);
        uint16_t xdp_length = udp_header.length - sizeof(udp_hdr_t);
        parseXDPMessage(xdp_data, xdp_length);
    }

    pcap_close(handle);
    return 0;
}