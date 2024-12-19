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

struct PillarStreamHeader {
    uint16_t packetSize;
    uint8_t deliveryFlag;
    uint8_t numberOfMessages;
    uint32_t sequenceNumber;
    uint64_t sendTime;
};

// Pillar Message Header
struct PillarMessageHeader {
    uint16_t messageSize;
    uint16_t messageType;
};

// Define message types
constexpr uint16_t MSG_TYPE_SEQUENCE_NUMBER_RESET = 1;
constexpr uint16_t MSG_TYPE_SOURCE_TIME_REFERENCE = 2;
constexpr uint16_t MSG_TYPE_SYMBOL_INDEX_MAPPING = 3;
constexpr uint16_t MSG_TYPE_SYMBOL_CLEAR = 32;
constexpr uint16_t MSG_TYPE_SECURITY_STATUS = 34;
constexpr uint16_t MSG_TYPE_ADD_ORDER = 100;
constexpr uint16_t MSG_TYPE_MODIFY_ORDER = 101;
constexpr uint16_t MSG_TYPE_DELETE_ORDER = 102;
constexpr uint16_t MSG_TYPE_ORDER_EXECUTION = 103;
constexpr uint16_t MSG_TYPE_REPLACE_ORDER = 104;
constexpr uint16_t MSG_TYPE_IMBALANCE = 105;
constexpr uint16_t MSG_TYPE_NON_DISPLAYED_TRADE = 110;
constexpr uint16_t MSG_TYPE_CROSS_TRADE = 111;
constexpr uint16_t MSG_TYPE_TRADE_CANCEL = 112;
constexpr uint16_t MSG_TYPE_CROSS_CORRECTION = 113;

// Sequence Number Reset Message (Msg Type 1)
struct SequenceNumberResetMessage : PillarMessageHeader {
    uint64_t sourceTime;
    uint16_t productID;
    uint16_t channelID;
};

// Source Time Reference Message (Msg Type 2)
struct SourceTimeReferenceMessage : PillarMessageHeader {
    uint64_t sourceTime;
    uint32_t sourceTimeNS;
    uint16_t id;
};

// Symbol Index Mapping Message (Type 3)
struct SymbolIndexMappingMessage : PillarMessageHeader {
    uint16_t symbolIndex;
    char symbol[11];
    uint16_t marketID;
    uint8_t priceScaleCode;
    uint8_t securityType;
};

// Symbol Clear Message (Type 32)
struct SymbolClearMessage : PillarMessageHeader {
    uint16_t symbolIndex;
    uint32_t nextSourceSeqNum;
    uint64_t sourceTime;
};

// Security Status Message (Msg Type 34)
struct SecurityStatusMessage : PillarMessageHeader {
    uint16_t symbolIndex;
    uint8_t securityStatus;
    uint8_t haltCondition;
};

// Add Order Message (Msg Type 100)
struct AddOrderMessage : PillarMessageHeader {
    uint64_t orderID;
    uint32_t price;
    uint32_t volume;
    char side; // 'B' for Buy, 'S' for Sell
};

// Modify Order Message (Msg Type 101)
struct ModifyOrderMessage : PillarMessageHeader {
    uint64_t orderID;
    uint32_t price;
    uint32_t volume;
};

// Delete Order Message (Msg Type 102)
struct DeleteOrderMessage : PillarMessageHeader {
    uint64_t orderID;
};

// Order Execution Message (Msg Type 103)
struct OrderExecutionMessage : PillarMessageHeader {
    uint64_t orderID;
    uint64_t tradeID;
    uint32_t price;
    uint32_t volume;
};

// Replace Order Message (Msg Type 104)
struct ReplaceOrderMessage : PillarMessageHeader {
    uint64_t oldOrderID;
    uint64_t newOrderID;
    uint32_t price;
    uint32_t volume;
};

// Imbalance Message (Msg Type 105)
struct ImbalanceMessage : PillarMessageHeader {
    uint32_t referencePrice;
    uint32_t pairedQty;
    uint32_t imbalanceQty;
    uint8_t auctionType;
    uint32_t indicativeMatchPrice;
};

// Non-Displayed Trade Message (Msg Type 110)
struct NonDisplayedTradeMessage : PillarMessageHeader {
    uint64_t tradeID;
    uint32_t price;
    uint32_t volume;
    uint8_t printableFlag;
};

// Cross Trade Message (Msg Type 111)
struct CrossTradeMessage : PillarMessageHeader {
    uint64_t tradeID;
    uint32_t price;
    uint32_t volume;
    uint8_t crossType;
    uint8_t printableFlag;
};

// Trade Cancel Message (Msg Type 112)
struct TradeCancelMessage : PillarMessageHeader {
    uint64_t tradeID;
    uint8_t cancelReason;
    uint64_t timestamp;
};

// Cross Correction Message (Msg Type 113)
struct CrossCorrectionMessage : PillarMessageHeader {
    uint64_t originalTradeID;
    struct NewTradeDetails {
        uint32_t price;
        uint32_t volume;
    } newTradeDetails;
    uint8_t correctionReason;
};

#pragma pack(pop)

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
void handleMessage(uint16_t messageType, const uint8_t* buffer, size_t size) {
    switch (messageType) {
        case MSG_TYPE_SEQUENCE_NUMBER_RESET: {
            if (size < sizeof(SequenceNumberResetMessage)) {
                std::cerr << "Invalid Sequence Number Reset Message size.\n";
                return;
            }
            SequenceNumberResetMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Sequence Number Reset: SourceTime=" << msg.sourceTime
                      << ", ProductID=" << msg.productID
                      << ", ChannelID=" << msg.channelID << "\n";
            break;
        }
        case MSG_TYPE_SOURCE_TIME_REFERENCE: {
            if (size < sizeof(SequenceNumberResetMessage)) {
                std::cerr << "Invalid Sequence Number Reset Message size.\n";
                return;
            }
            SourceTimeReferenceMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Source Time Reference: SourceTime=" << msg.sourceTime
                      << ", SourceTimeNS=" << msg.sourceTimeNS
                      << ", ID=" << msg.id << "\n";
            break;
        }
        case MSG_TYPE_SYMBOL_INDEX_MAPPING: {
            if (size < sizeof(SequenceNumberResetMessage)) {
                std::cerr << "Invalid Sequence Number Reset Message size.\n";
                return;
            }
            SymbolIndexMappingMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Symbol Index Mapping: SymbolIndex=" << msg.symbolIndex
                      << ", Symbol=" << std::string(msg.symbol, strnlen(msg.symbol, 11))
                      << ", MarketID=" << msg.marketID
                      << ", PriceScaleCode=" << static_cast<int>(msg.priceScaleCode)
                      << ", SecurityType=" << static_cast<int>(msg.securityType) << "\n";
            break;
        }
        case MSG_TYPE_SYMBOL_CLEAR: {
            if (size < sizeof(SequenceNumberResetMessage)) {
                std::cerr << "Invalid Sequence Number Reset Message size.\n";
                return;
            }
            SymbolClearMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Symbol Clear: SymbolIndex=" << msg.symbolIndex
                      << ", NextSourceSeqNum=" << msg.nextSourceSeqNum
                      << ", SourceTime=" << msg.sourceTime << "\n";
            break;
        }
        case MSG_TYPE_SECURITY_STATUS: {
            if (size < sizeof(AddOrderMessage)) {
                std::cerr << "Invalid Add Order Message size.\n";
                return;
            }
            SecurityStatusMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Security Status: SymbolIndex=" << msg.symbolIndex
                      << ", SecurityStatus=" << static_cast<int>(msg.securityStatus)
                      << ", HaltCondition=" << static_cast<int>(msg.haltCondition) << "\n";
            break;
        }
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
        case MSG_TYPE_IMBALANCE: {
            if (size < sizeof(ReplaceOrderMessage)) {
                std::cerr << "Invalid Replace Order Message size.\n";
                return;
            }
            ImbalanceMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Imbalance Message: ReferencePrice=" << msg.referencePrice
                      << ", PairedQty=" << msg.pairedQty
                      << ", ImbalanceQty=" << msg.imbalanceQty
                      << ", AuctionType=" << static_cast<int>(msg.auctionType)
                      << ", IndicativeMatchPrice=" << msg.indicativeMatchPrice << "\n";
            break;
        }
        case MSG_TYPE_NON_DISPLAYED_TRADE: {
            if (size < sizeof(NonDisplayedTradeMessage)) {
                std::cerr << "Invalid Non-Displayed Trade Message size.\n";
                return;
            }
            NonDisplayedTradeMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Non-Displayed Trade: TradeID=" << msg.tradeID
                      << ", Price=" << msg.price
                      << ", Volume=" << msg.volume
                      << ", PrintableFlag=" << static_cast<int>(msg.printableFlag) << "\n";
            break;
        }
        case MSG_TYPE_CROSS_TRADE: {
            if (size < sizeof(CrossTradeMessage)) {
                std::cerr << "Invalid Cross Trade Message size.\n";
                return;
            }
            CrossTradeMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Cross Trade: TradeID=" << msg.tradeID
                      << ", Price=" << msg.price
                      << ", Volume=" << msg.volume
                      << ", CrossType=" << static_cast<int>(msg.crossType)
                      << ", PrintableFlag=" << static_cast<int>(msg.printableFlag) << "\n";
            break;
        }
        case MSG_TYPE_TRADE_CANCEL: {
            if (size < sizeof(TradeCancelMessage)) {
                std::cerr << "Invalid Trade Cancel Message size.\n";
                return;
            }
            TradeCancelMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Trade Cancel: TradeID=" << msg.tradeID
                      << ", CancelReason=" << static_cast<int>(msg.cancelReason)
                      << ", Timestamp=" << msg.timestamp << "\n";
            break;
        }
        case MSG_TYPE_CROSS_CORRECTION: { // Cross Correction Message
            if (size < sizeof(CrossCorrectionMessage)) {
                std::cerr << "Invalid Cross Correction Message size.\n";
                return;
            }
            CrossCorrectionMessage msg;
            std::memcpy(&msg, buffer, sizeof(msg));
            std::cout << "Cross Correction: OriginalTradeID=" << msg.originalTradeID
                      << ", New Price=" << msg.newTradeDetails.price
                      << ", New Volume=" << msg.newTradeDetails.volume
                      << ", CorrectionReason=" << static_cast<int>(msg.correctionReason) << "\n";
            break;
        }
        default:
            std::cerr << "Unknown message type: " << messageType << "\n";
            break;
    }
}

void debugHexDump(const uint8_t* data, size_t length, const std::string& label) {
    std::cout << "[Debug] Hex Dump (" << label << "):\n";
    for (size_t i = 0; i < length; ++i) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

void parsePillarStream(const uint8_t* data, uint16_t length) {
    if (length < 16) {
        std::cerr << "[Error] Insufficient data for Packet Header\n";
        return;
    }

    // Parse Packet Header
    uint16_t pktSize;
    uint8_t numberOfMessages;
    uint32_t sequenceNumber;
    uint64_t sendTime;

    std::memcpy(&pktSize, data, sizeof(pktSize));
    numberOfMessages = *(data + 3);
    std::memcpy(&sequenceNumber, data + 4, sizeof(sequenceNumber));
    std::memcpy(&sendTime, data + 8, sizeof(sendTime));

    std::cout << "[Packet Header] Packet Size: " << pktSize
              << ", Number of Messages: " << static_cast<int>(numberOfMessages)
              << ", Sequence Number: " << sequenceNumber
              << ", Send Time: " << sendTime << "\n";

    // Validate packet size
    if (pktSize != length) {
        std::cerr << "[Error] Packet size mismatch. Expected: " << pktSize
                  << ", Actual: " << length << "\n";
        return;
    }

    // Start parsing messages
    const uint8_t* messagePtr = data + 16; // Skip 16-byte Packet Header
    uint16_t bytesProcessed = 16;

    for (uint8_t i = 0; i < numberOfMessages; ++i) {
        if ((bytesProcessed + 4) > length) {
            std::cerr << "[Error] Insufficient data for Message Header\n";
            break;
        }

        // Parse Message Header
        uint16_t msgSize, msgType;
        memcpy(&msgSize, messagePtr, sizeof(msgSize));
        memcpy(&msgType, messagePtr + 2, sizeof(msgType));

        // Debug: Validate raw msgSize bytes
        std::cout << "[Debug] Hex Dump (Message Header):\n";
        printHex(messagePtr, 4);
        std::cout << "[Debug] Raw Message Size Bytes: " << std::hex
                  << static_cast<int>(messagePtr[0]) << " "
                  << static_cast<int>(messagePtr[1]) << std::dec << "\n";
        
        std::cout << "[Debug] Message Size (before validation): " << msgSize << "\n";
        std::cout << "[Message Header] Message Type: " << msgType
                  << ", Message Size: " << msgSize << "\n";

        // Pass message data for further processing
        const uint8_t* msgData = messagePtr + 4;
        uint16_t msgLength = msgSize - 4;
        
        handleMessage(msgType, msgData, msgLength);

        // Advance to the next message
        bytesProcessed += msgSize;
        messagePtr += msgSize;
    }
}

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
        
        // Extract UDP Payload
        uint16_t ipHeaderLength = (*(packet_data + 14) & 0x0F) * 4; // IHL field (IPv4 header length)
        uint16_t udpHeaderOffset = 14 + ipHeaderLength;
        uint16_t udpPayloadOffset = udpHeaderOffset + 8; // 8 bytes UDP header
        uint16_t udpPayloadLength = ntohs(*(reinterpret_cast<const uint16_t*>(packet_data + udpHeaderOffset + 4))) - 8;

        if (udpPayloadOffset + udpPayloadLength > packet_header->len) {
            std::cerr << "[Error] UDP payload exceeds packet length\n";
            continue;
        }

        // Extract and parse Pillar stream
        const uint8_t* pillarData = packet_data + udpPayloadOffset;
        uint16_t pillarLength = udpPayloadLength;
        parsePillarStream(pillarData, pillarLength);

    }

    pcap_close(handle);
    return 0;
}