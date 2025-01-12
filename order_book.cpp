#include <iostream>
#include <vector>
#include <unordered_map>
#include <map>
#include <list>
#include <string>
#include <iomanip>
#include <pcap.h>
#include <cstring>
#include <cstdint>
#include <arpa/inet.h>
#include <bitset>
#include <algorithm>
#include <cmath>

#pragma pack(push, 1)

// Order Definition
struct Order {
    uint64_t orderID;
    uint32_t price;
    uint32_t volume;
    char side;
    std::string firmID;

    Order(uint64_t id, uint32_t p, uint32_t v, char s, const std::string& f)
        : orderID(id), price(p), volume(v), side(s), firmID(f) {}
    
    bool operator==(const Order& other) const {
        return orderID == other.orderID;
    }
};

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
constexpr uint16_t MSG_TYPE_ADD_ORDER_REFRESH = 106;
constexpr uint16_t MSG_TYPE_NON_DISPLAYED_TRADE = 110;
constexpr uint16_t MSG_TYPE_CROSS_TRADE = 111;
constexpr uint16_t MSG_TYPE_TRADE_CANCEL = 112;
constexpr uint16_t MSG_TYPE_CROSS_CORRECTION = 113;
constexpr uint16_t MSG_TYPE_RETAIL_PRICE_IMPROVEMENT = 114;

// Sequence Number Reset Message (Msg Type 1)
struct SequenceNumberResetMessage {
    uint32_t sourceTime;
    uint32_t sourceTimeNS;
    uint8_t productID;
    uint8_t channelID;
};

// Source Time Reference Message (Msg Type 2)
struct SourceTimeReferenceMessage {
    uint32_t id;
    uint32_t symbolSeqNum;
    uint32_t sourceTime;
};

// Symbol Index Mapping Message (Msg Type 3)
struct SymbolIndexMappingMessage {
    uint32_t symbolIndex;
    char symbol[11];
    uint8_t reserved1;
    uint16_t marketID;
    uint8_t systemID;
    char exchangeCode;
    uint8_t priceScaleCode;
    char securityType;
    uint16_t lotSize;
    uint32_t prevClosePrice;
    uint32_t prevCloseVolume;
    uint8_t priceResolution;
    char roundLot;
    uint16_t mpv;
    uint16_t unitOfTrade;
    uint16_t reserved2;
};

// Symbol Clear Message (Msg Type 32)
struct SymbolClearMessage {
    uint32_t sourceTime;
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t nextSourceSeqNum;
};

// Security Status Message (Msg Type 34)
struct SecurityStatusMessage {
    uint32_t sourceTime;
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    char securityStatus;
    char haltCondition;
    uint32_t reserved;
    uint32_t price1;
    uint32_t price2;
    char ssrTriggeringExchangeID;
    uint32_t ssrTriggeringVolume;
    uint32_t time;
    char ssrState;                
    char marketState;
    char sessionState;
};

// Add Order Message (Msg Type 100)
struct AddOrderMessage {
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    uint64_t orderID;
    uint32_t price;
    uint32_t volume;
    char side;
    char firmID[5];
    uint8_t reserved1;
};

// Modify Order Message (Msg Type 101)
struct ModifyOrderMessage {
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    uint64_t orderID;
    uint32_t price;
    uint32_t volume;
    uint8_t positionChange;
    char side;
    uint8_t reserved2;
};

// Delete Order Message (Msg Type 102)
struct DeleteOrderMessage {
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    uint64_t orderID;
    uint8_t reserved1;
};

// Order Execution Message (Msg Type 103)
struct OrderExecutionMessage {
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    uint64_t orderID;
    uint32_t tradeID;
    uint32_t price;
    uint32_t volume;
    uint8_t printableFlag;
    uint8_t reserved1;
    char tradeCond1;
    char tradeCond2;
    char tradeCond3;
    char tradeCond4;
};

// Replace Order Message (Msg Type 104)
struct ReplaceOrderMessage {
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    uint64_t orderID;
    uint64_t newOrderID;
    uint32_t price;
    uint32_t volume;
    char side;
    uint8_t reserved2;
};

// Imbalance Message (Msg Type 105)
struct ImbalanceMessage {
    uint32_t sourceTime;
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    uint32_t referencePrice;
    uint32_t pairedQty;
    uint32_t totalImbalanceQty;
    uint32_t marketImbalanceQty;
    uint16_t auctionTime;
    char auctionType;
    char imbalanceSide;
    uint32_t continuousBookClearingPrice;
    uint32_t auctionInterestClearingPrice;
    uint32_t ssrFilingPrice;
    uint32_t indicativeMatchPrice;
    uint32_t upperCollar;
    uint32_t lowerCollar;
    uint8_t auctionStatus;
    uint8_t freezeStatus;
    uint8_t numExtensions;
    uint32_t unpairedQty;
    char unpairedSide;
    char significantImbalance;
};

// Add Order Refresh Message (Msg Type 106)
struct AddOrderRefreshMessage {
    uint32_t sourceTime;
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    uint64_t orderID;
    uint32_t price;
    uint32_t volume;
    char side;
    char firmID[5];
    uint8_t reserved1;
};

// Non-Displayed Trade Message (Msg Type 110)
struct NonDisplayedTradeMessage {
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    uint32_t tradeID;
    uint32_t price;
    uint32_t volume;
    uint8_t printableFlag;
    char tradeCond1;
    char tradeCond2;
    char tradeCond3;
    char tradeCond4;
};

// Cross Trade Message (Msg Type 111)
struct CrossTradeMessage {
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    uint32_t crossID;
    uint32_t price;
    uint32_t volume;
    char crossType;
};

// Trade Cancel Message (Msg Type 112)
struct TradeCancelMessage {
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    uint32_t tradeID;
};

// Cross Correction Message (Msg Type 113)
struct CrossCorrectionMessage {
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    uint32_t crossID;
    uint32_t volume;
};

// Retail Price Improvement Message (Msg Type 114)
struct RetailPriceImprovementMessage {
    uint32_t sourceTimeNS;
    uint32_t symbolIndex;
    uint32_t symbolSeqNum;
    char rpiIndicator;
};

#pragma pack(pop)

class OrderBook {
private:
    std::unordered_map<uint64_t, Order*> orderMap;
    std::map<uint32_t, std::list<Order>> bids;
    std::map<uint32_t, std::list<Order>> asks;
    std::vector<uint32_t> top10Bids;
    std::vector<uint32_t> top10Asks;

    std::vector<uint32_t> getTopPrices(const std::map<uint32_t, std::list<Order>>& book, bool reverse = false) const {
        std::vector<uint32_t> topPrices;
        if (reverse) {
            for (auto it = book.rbegin(); it != book.rend() && topPrices.size() < 10; ++it) {
                topPrices.push_back(it->first);
            }
        } else {
            for (auto it = book.begin(); it != book.end() && topPrices.size() < 10; ++it) {
                topPrices.push_back(it->first);
            }
        }
        return topPrices;
    }

public:
    void clearOrders() {
        bids.clear();
        asks.clear();
        orderMap.clear();
        std::cout << "Order book cleared.\n";
    }
    void addOrder(uint32_t sourceTimeNS, uint32_t symbolIndex, uint32_t symbolSeqNum, 
                  uint64_t orderID, uint32_t price, uint32_t volume, char side, 
                  const std::string& firmID, bool& top10Changed) {
        Order newOrder(orderID, price, volume, side, firmID);
        auto& bookSide = (side == 'B') ? bids : asks;

        bookSide[price].push_back(newOrder);
        orderMap[orderID] = &bookSide[price].back();

        const auto& newTopBids = getTopPrices(bids, true);
        const auto& newTopAsks = getTopPrices(asks);

        top10Changed = (newTopBids != top10Bids || newTopAsks != top10Asks);
        if (top10Changed) {
            top10Bids = newTopBids;
            top10Asks = newTopAsks;
        }

        std::cout << "Added Order: " << orderID << "\n";
    }
    void modifyOrder(uint32_t sourceTimeNS, uint32_t symbolIndex, uint32_t symbolSeqNum,
                     uint64_t orderID, uint32_t price, uint32_t volume,
                     uint8_t positionChange, char side, bool& top10Changed) {
        auto it = orderMap.find(orderID);
        
        if (it != orderMap.end()) {
            Order* order = it->second;

            std::cout << "Modifying Order: " << order->orderID << "\n";

            order->price = price;
            order->volume = volume;
            order->side = side;

            const auto& newTopBids = getTopPrices(bids, true);
            const auto& newTopAsks = getTopPrices(asks);

            top10Changed = (newTopBids != top10Bids || newTopAsks != top10Asks);
            if (top10Changed) {
                top10Bids = newTopBids;
                top10Asks = newTopAsks;
            }

            std::cout << "Order Modified. New Order ID: " << order->orderID << "\n";
        } else {
            std::cerr << "Order ID " << orderID << " not found for modification\n";
        }
    }
    void orderExecution(uint32_t sourceTimeNS, uint32_t symbolIndex, uint32_t symbolSeqNum,
                    uint64_t orderID, uint64_t tradeID, uint32_t price, uint32_t volume,
                    uint8_t printableFlag, char tradeCond1, char tradeCond2, 
                    char tradeCond3, char tradeCond4, bool& top10Changed) {
        auto it = orderMap.find(orderID);

        if (it != orderMap.end()) {
            Order* order = it->second;

            std::cout << "Executing Order: " << order->orderID << "\n";

            if (order->volume >= volume) {
                order->volume -= volume;
            } else {
                std::cerr << "Error: Execution volume exceeds order volume for Order ID " << orderID << "\n";
                return;
            }

            if (order->volume == 0) {
                auto& bookSide = (order->side == 'B') ? bids : asks;
                auto levelIt = bookSide.find(order->price);

                if (levelIt != bookSide.end()) {
                    auto& orderList = levelIt->second;
                    auto orderInList = std::find_if(orderList.begin(), orderList.end(),
                        [&](const Order& o) { return o.orderID == order->orderID; });

                    if (orderInList != orderList.end()) {
                        orderList.erase(orderInList);

                        if (orderList.empty()) {
                            bookSide.erase(levelIt);
                        }
                    }
                }

                orderMap.erase(it);
            }

            const auto& newTopBids = getTopPrices(bids, true);
            const auto& newTopAsks = getTopPrices(asks);

            top10Changed = (newTopBids != top10Bids || newTopAsks != top10Asks);
            if (top10Changed) {
                top10Bids = newTopBids;
                top10Asks = newTopAsks;
            }

            std::cout << "Order Executed: " << orderID << "\n"
                      << "  Price: " << price << "\n"
                      << "  Volume: " << volume << "\n";
        } else {
            std::cerr << "Order ID " << orderID << " not found for execution\n";
        }
    }
    void replaceOrder(uint32_t sourceTimeNS, uint32_t symbolIndex, uint32_t symbolSeqNum, 
                  uint64_t oldOrderID, uint64_t newOrderID, uint32_t price, 
                  uint32_t volume, char side, bool& top10Changed) {
        deleteOrder(sourceTimeNS, symbolIndex, symbolSeqNum, oldOrderID, top10Changed);

        addOrder(sourceTimeNS, symbolIndex, symbolSeqNum, newOrderID, price, volume, side, "", top10Changed);
    }
    void deleteOrder(uint32_t sourceTimeNS, uint32_t symbolIndex, uint32_t symbolSeqNum, 
                     uint64_t orderID, bool& top10Changed) {
        auto it = orderMap.find(orderID);
        
        if (it != orderMap.end()) {
            Order* order = it->second;
            auto& bookSide = (order->side == 'B') ? bids : asks;

            auto levelIt = bookSide.find(order->price);
            if (levelIt != bookSide.end()) {
                auto& orderList = levelIt->second;

                auto orderInList = std::find_if(orderList.begin(), orderList.end(),
                    [&](const Order& o) { return o.orderID == order->orderID; });
                
                if (orderInList != orderList.end()) {
                    orderList.erase(orderInList);

                    if (orderList.empty()) {
                        bookSide.erase(levelIt);
                    }
                } else {
                    std::cerr << "Order not found in price level for deletion: " << orderID << "\n";
                }
            } else {
                std::cerr << "Price level not found for order deletion: Price=" << order->price << "\n";
            }

            orderMap.erase(it);

            const auto& newTopBids = getTopPrices(bids, true);
            const auto& newTopAsks = getTopPrices(asks);

            top10Changed = (newTopBids != top10Bids || newTopAsks != top10Asks);
            if (top10Changed) {
                top10Bids = newTopBids;
                top10Asks = newTopAsks;
            }

            std::cout << "Deleted Order: " << orderID << "\n";
        } else {
            std::cerr << "Order ID " << orderID << " not found for deletion\n";
        }
    }
    void printOrderBook(uint32_t symbolIndex,
                        const std::unordered_map<uint32_t, std::string>& symbolMappings,
                        const std::unordered_map<uint32_t, uint8_t>& symbolPriceScaleCodes) const {
        auto symbolIt = symbolMappings.find(symbolIndex);
        std::string symbolName = (symbolIt != symbolMappings.end()) ? symbolIt->second : "Unknown";

        auto scaleIt = symbolPriceScaleCodes.find(symbolIndex);
        uint8_t priceScaleCode = (scaleIt != symbolPriceScaleCodes.end()) ? scaleIt->second : 0;
        double priceDivisor = std::pow(10, priceScaleCode);

        std::cout << "\nOrder Book for Symbol: " << symbolName << " (SymbolIndex: " << symbolIndex << ")\n";

        std::cout << "Top 10 Bids:\n";
        for (const auto& price : top10Bids) {
            const auto& orders = bids.at(price);
            std::cout << "Price " << (price / priceDivisor) << ": ";
            for (const auto& order : orders) {
                std::cout << "[ID=" << order.orderID << ", Vol=" << order.volume << "] ";
            }
            std::cout << "\n";
        }
        std::cout << "\n";

        std::cout << "Top 10 Asks:\n";
        for (const auto& price : top10Asks) {
            const auto& orders = asks.at(price);
            std::cout << "Price " << (price / priceDivisor) << ": ";
            for (const auto& order : orders) {
                std::cout << "[ID=" << order.orderID << ", Vol=" << order.volume << "] ";
            }
            std::cout << "\n";
        }
        std::cout << "\n";
    }
};

// Global map of SymbolIndex to OrderBook
std::unordered_map<uint32_t, OrderBook> symbolOrderBooks;
uint32_t currentSymbolIndex = 0;
std::unordered_map<uint32_t, std::string> symbolMappings;
std::unordered_map<uint32_t, uint8_t> symbolPriceScaleCodes;

// Symbol Clear Order Function
void symbolClear(uint32_t symbolIndex, 
                 const std::unordered_map<uint32_t, std::string>& symbolMappings) {
    auto it = symbolOrderBooks.find(symbolIndex);
    if (it != symbolOrderBooks.end()) {
        auto& orderBook = it->second;
        orderBook.clearOrders();

        auto symbolIt = symbolMappings.find(symbolIndex);
        std::string symbolName = (symbolIt != symbolMappings.end()) ? symbolIt->second : "Unknown";

        std::cout << "Cleared Order Book for Symbol: " << symbolName 
                  << " (SymbolIndex: " << symbolIndex << ")\n";
    } else {
        std::cerr << "No order book found for SymbolIndex: " << symbolIndex << "\n";
    }
}

// Add Order Function
void addOrder(uint32_t sourceTimeNS, uint32_t symbolIndex, uint32_t symbolSeqNum, 
              uint64_t orderID, uint32_t price, uint32_t volume, char side, 
              const std::string& firmID) {
    bool symbolChanged = (symbolIndex != currentSymbolIndex);
    if (symbolChanged) {
        currentSymbolIndex = symbolIndex;
    }
    
    auto& orderBook = symbolOrderBooks[symbolIndex];

    bool top10Changed = false;
    orderBook.addOrder(sourceTimeNS, symbolIndex, symbolSeqNum, orderID, price, volume, side, firmID, top10Changed);

    if (symbolChanged || top10Changed) {
        orderBook.printOrderBook(symbolIndex, symbolMappings, symbolPriceScaleCodes);
    }
}

// Modify Order Function
void modifyOrder(uint32_t sourceTimeNS, uint32_t symbolIndex, uint32_t symbolSeqNum,
                 uint64_t orderID, uint32_t price, uint32_t volume,
                 uint8_t positionChange, char side) {
    bool symbolChanged = (symbolIndex != currentSymbolIndex);
    if (symbolChanged) {
        currentSymbolIndex = symbolIndex;
    }

    auto& orderBook = symbolOrderBooks[symbolIndex];

    bool top10Changed = false;
    orderBook.modifyOrder(sourceTimeNS, symbolIndex, symbolSeqNum, orderID, price, volume, positionChange, side, top10Changed);

    if (symbolChanged || top10Changed) {
        orderBook.printOrderBook(symbolIndex, symbolMappings, symbolPriceScaleCodes);
    }
}

// Order Execution Function
void orderExecution(uint32_t sourceTimeNS, uint32_t symbolIndex, uint32_t symbolSeqNum,
                    uint64_t orderID, uint64_t tradeID, uint32_t price, uint32_t volume,
                    uint8_t printableFlag, char tradeCond1, char tradeCond2, 
                    char tradeCond3, char tradeCond4) {
    bool symbolChanged = (symbolIndex != currentSymbolIndex);
    if (symbolChanged) {
        currentSymbolIndex = symbolIndex;
    }

    auto& orderBook = symbolOrderBooks[symbolIndex];

    bool top10Changed = false;
    orderBook.orderExecution(sourceTimeNS, symbolIndex, symbolSeqNum, orderID, tradeID, 
                             price, volume, printableFlag, tradeCond1, tradeCond2, 
                             tradeCond3, tradeCond4, top10Changed);

    if (symbolChanged || top10Changed) {
        orderBook.printOrderBook(symbolIndex, symbolMappings, symbolPriceScaleCodes);
    }
}

// Replace Order Function
void replaceOrder(uint32_t sourceTimeNS, uint32_t symbolIndex, uint32_t symbolSeqNum, 
                  uint64_t oldOrderID, uint64_t newOrderID, uint32_t price, 
                  uint32_t volume, char side, 
                  const std::unordered_map<uint32_t, std::string>& symbolMappings) {
    bool symbolChanged = (symbolIndex != currentSymbolIndex);
    if (symbolChanged) {
        currentSymbolIndex = symbolIndex;
    }

    auto& orderBook = symbolOrderBooks[symbolIndex];

    bool top10Changed = false;
    orderBook.replaceOrder(sourceTimeNS, symbolIndex, symbolSeqNum, oldOrderID, newOrderID, price, volume, side, top10Changed);

    if (symbolChanged || top10Changed) {
        orderBook.printOrderBook(symbolIndex, symbolMappings, symbolPriceScaleCodes);
    }
}

// Delete Order Function
void deleteOrder(uint32_t sourceTimeNS, uint32_t symbolIndex, uint32_t symbolSeqNum, uint64_t orderID) {
    bool symbolChanged = (symbolIndex != currentSymbolIndex);
    if (symbolChanged) {
        currentSymbolIndex = symbolIndex;
    }
    
    auto& orderBook = symbolOrderBooks[symbolIndex];

    bool top10Changed = false;
    orderBook.deleteOrder(sourceTimeNS, symbolIndex, symbolSeqNum, orderID, top10Changed);

    if (symbolChanged || top10Changed) {
        orderBook.printOrderBook(symbolIndex, symbolMappings, symbolPriceScaleCodes);
    }
}

// Print Order Book Function
void printOrderBook(uint32_t symbolIndex, const std::unordered_map<uint32_t, std::string>& symbolMappings) {
    auto it = symbolOrderBooks.find(symbolIndex);
    if (it != symbolOrderBooks.end()) {
        auto symbolIt = symbolMappings.find(symbolIndex);
        if (symbolIt != symbolMappings.end()) {
            const std::string& symbol = symbolIt->second;
            std::cout << "Order Book for Symbol: " << symbol << " (SymbolIndex: " << symbolIndex << ")\n";
        } else {
            std::cout << "Order Book for SymbolIndex: " << symbolIndex << " (Symbol not found in mappings)\n";
        }
        it->second.printOrderBook(symbolIndex, symbolMappings, symbolPriceScaleCodes);
    } else {
        std::cerr << "Order book for SymbolIndex " << symbolIndex << " not found.\n";
    }
}

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

    return true;
}

// Function to parse UDP Header
bool parseUDPHeader(const u_char* data, udp_hdr_t& udp_header) {
    if (data == nullptr) return false;

    std::memcpy(&udp_header, data, sizeof(udp_hdr_t));
    udp_header.src_port = ntohs(udp_header.src_port);
    udp_header.dest_port = ntohs(udp_header.dest_port);
    udp_header.length = ntohs(udp_header.length);

    return true;
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
            
            std::memcpy(&msg.sourceTime, buffer, sizeof(msg.sourceTime));

            std::memcpy(&msg.sourceTimeNS, buffer + 4, sizeof(msg.sourceTimeNS));

            msg.productID = buffer[8];

            msg.channelID = buffer[9];

            std::cout << "Sequence Number Reset Message Processed.\n";
            break;
        }
        case MSG_TYPE_SOURCE_TIME_REFERENCE: {
            if (size < sizeof(SourceTimeReferenceMessage)) {
                std::cerr << "Invalid Source Time Reference Message size.\n";
                return;
            }
            SourceTimeReferenceMessage msg;
            
            std::memcpy(&msg.id, buffer, sizeof(msg.id));

            std::memcpy(&msg.symbolSeqNum, buffer + 4, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.sourceTime, buffer + 8, sizeof(msg.sourceTime));

            std::cout << "Source Time Reference Message Processed.\n";

            break;
        }
        case MSG_TYPE_SYMBOL_INDEX_MAPPING: {
            if (size < sizeof(SymbolIndexMappingMessage)) {
                std::cerr << "Invalid Symbol Index Mapping Message size.\n";
                return;
            }
            SymbolIndexMappingMessage msg;
            
            std::memcpy(&msg.symbolIndex, buffer, sizeof(msg.symbolIndex));

            std::memcpy(msg.symbol, buffer + 4, sizeof(msg.symbol));
            msg.symbol[10] = '\0';

            msg.reserved1 = buffer[15];

            std::memcpy(&msg.marketID, buffer + 16, sizeof(msg.marketID));

            msg.systemID = buffer[18];

            msg.exchangeCode = static_cast<char>(buffer[19]);

            msg.priceScaleCode = buffer[20];

            msg.securityType = static_cast<char>(buffer[21]);

            std::memcpy(&msg.lotSize, buffer + 22, sizeof(msg.lotSize));

            std::memcpy(&msg.prevClosePrice, buffer + 24, sizeof(msg.prevClosePrice));

            std::memcpy(&msg.prevCloseVolume, buffer + 28, sizeof(msg.prevCloseVolume));

            msg.priceResolution = buffer[32];

            msg.roundLot = static_cast<char>(buffer[33]);

            std::memcpy(&msg.mpv, buffer + 34, sizeof(msg.mpv));

            std::memcpy(&msg.unitOfTrade, buffer + 36, sizeof(msg.unitOfTrade));

            std::memcpy(&msg.reserved2, buffer + 38, sizeof(msg.reserved2));

            // Check if the symbolIndex exists, if not add it
            if (symbolMappings.find(msg.symbolIndex) == symbolMappings.end()) {
                symbolMappings[msg.symbolIndex] = msg.symbol;
            }
            symbolPriceScaleCodes[msg.symbolIndex] = msg.priceScaleCode; 

            std::cout << "Symbol Index Mapping Message Processed.\n";
            break;
        }
        case MSG_TYPE_SYMBOL_CLEAR: {
            if (size < sizeof(SymbolClearMessage)) {
                std::cerr << "Invalid Symbol Clear Message size.\n";
                return;
            }
            SymbolClearMessage msg;
            
            std::memcpy(&msg.sourceTime, buffer, sizeof(msg.sourceTime));

            std::memcpy(&msg.sourceTimeNS, buffer + 4, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 8, sizeof(msg.symbolIndex));

            std::memcpy(&msg.nextSourceSeqNum, buffer + 12, sizeof(msg.nextSourceSeqNum));

            symbolClear(msg.symbolIndex, symbolMappings);
            break;
        }
        case MSG_TYPE_SECURITY_STATUS: {
            if (size < sizeof(SecurityStatusMessage)) {
                std::cerr << "Invalid Security Status Message size.\n";
                return;
            }
            SecurityStatusMessage msg;
            
            std::memcpy(&msg.sourceTime, buffer, sizeof(msg.sourceTime));

            std::memcpy(&msg.sourceTimeNS, buffer + 4, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 8, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 12, sizeof(msg.symbolSeqNum));

            msg.securityStatus = static_cast<char>(buffer[16]);

            msg.haltCondition = static_cast<char>(buffer[17]);

            std::memcpy(&msg.reserved, buffer + 18, sizeof(msg.reserved));

            std::memcpy(&msg.price1, buffer + 22, sizeof(msg.price1));

            std::memcpy(&msg.price2, buffer + 26, sizeof(msg.price2));

            msg.ssrTriggeringExchangeID = static_cast<char>(buffer[30]);

            std::memcpy(&msg.ssrTriggeringVolume, buffer + 31, sizeof(msg.ssrTriggeringVolume));

            std::memcpy(&msg.time, buffer + 35, sizeof(msg.time));

            msg.ssrState = static_cast<char>(buffer[39]);

            msg.marketState = static_cast<char>(buffer[40]);

            msg.sessionState = static_cast<char>(buffer[41]);

            std::cout << "Security Status Message Processed.\n";
            break;
        }
        case MSG_TYPE_ADD_ORDER: {
            if (size < sizeof(AddOrderMessage)) {
                std::cerr << "Invalid Add Order Message size.\n";
                return;
            }
            AddOrderMessage msg;

            std::memcpy(&msg.sourceTimeNS, buffer, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 4, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 8, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.orderID, buffer + 12, sizeof(msg.orderID));

            std::memcpy(&msg.price, buffer + 20, sizeof(msg.price));

            std::memcpy(&msg.volume, buffer + 24, sizeof(msg.volume));

            msg.side = static_cast<char>(buffer[28]);

            std::memcpy(msg.firmID, buffer + 29, sizeof(msg.firmID));
            msg.firmID[4] = '\0';

            msg.reserved1 = buffer[34];

            addOrder(msg.sourceTimeNS, msg.symbolIndex, msg.symbolSeqNum, msg.orderID, msg.price, msg.volume, msg.side, msg.firmID);
            break;
        }
        case MSG_TYPE_MODIFY_ORDER: {
            if (size < sizeof(ModifyOrderMessage)) {
                std::cerr << "Invalid Modify Order Message size.\n";
                return;
            }
            ModifyOrderMessage msg;

            std::memcpy(&msg.sourceTimeNS, buffer, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 4, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 8, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.orderID, buffer + 12, sizeof(msg.orderID));

            std::memcpy(&msg.price, buffer + 20, sizeof(msg.price));

            std::memcpy(&msg.volume, buffer + 24, sizeof(msg.volume));

            msg.positionChange = buffer[28];

            msg.side = static_cast<char>(buffer[29]);

            msg.reserved2 = buffer[30];

            modifyOrder(msg.sourceTimeNS, msg.symbolIndex, msg.symbolSeqNum, msg.orderID, msg.price, msg.volume, msg.positionChange, msg.side);
            break;
        }
        case MSG_TYPE_DELETE_ORDER: {
            if (size < sizeof(DeleteOrderMessage)) {
                std::cerr << "Invalid Delete Order Message size.\n";
                return;
            }
            DeleteOrderMessage msg;
            
            std::memcpy(&msg.sourceTimeNS, buffer, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 4, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 8, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.orderID, buffer + 12, sizeof(msg.orderID));

            msg.reserved1 = buffer[20];

            deleteOrder(msg.sourceTimeNS, msg.symbolIndex, msg.symbolSeqNum, msg.orderID);
            break;
        }
        case MSG_TYPE_ORDER_EXECUTION: {
            if (size < sizeof(OrderExecutionMessage)) {
                std::cerr << "Invalid Order Execution Message size.\n";
                return;
            }
            OrderExecutionMessage msg;

            std::memcpy(&msg.sourceTimeNS, buffer, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 4, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 8, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.orderID, buffer + 12, sizeof(msg.orderID));

            std::memcpy(&msg.tradeID, buffer + 20, sizeof(msg.tradeID));

            std::memcpy(&msg.price, buffer + 28, sizeof(msg.price));

            std::memcpy(&msg.volume, buffer + 32, sizeof(msg.volume));

            msg.printableFlag = buffer[36];

            msg.tradeCond1 = buffer[37];
            
            msg.tradeCond2 = buffer[38];
            
            msg.tradeCond3 = buffer[39];
            
            msg.tradeCond4 = buffer[40];

            orderExecution(msg.sourceTimeNS, msg.symbolIndex, msg.symbolSeqNum, msg.orderID, msg.tradeID, msg.price, msg.volume, msg.printableFlag, msg.tradeCond1, msg.tradeCond2, msg.tradeCond3, msg.tradeCond4);
            break;
        }
        case MSG_TYPE_REPLACE_ORDER: {
            if (size < sizeof(ReplaceOrderMessage)) {
                std::cerr << "Invalid Replace Order Message size.\n";
                return;
            }
            ReplaceOrderMessage msg;
            
            std::memcpy(&msg.sourceTimeNS, buffer, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 4, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 8, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.orderID, buffer + 12, sizeof(msg.orderID));

            std::memcpy(&msg.newOrderID, buffer + 20, sizeof(msg.newOrderID));

            std::memcpy(&msg.price, buffer + 28, sizeof(msg.price));

            std::memcpy(&msg.volume, buffer + 32, sizeof(msg.volume));

            msg.side = static_cast<char>(buffer[36]);

            msg.reserved2 = buffer[37];

            replaceOrder(msg.sourceTimeNS, msg.symbolIndex, msg.symbolSeqNum, 
                         msg.orderID, msg.newOrderID, msg.price, msg.volume, 
                         msg.side, symbolMappings);
            break;
        }
        case MSG_TYPE_IMBALANCE: {
            if (size < sizeof(ImbalanceMessage)) {
                std::cerr << "Invalid Imbalance Message size.\n";
                return;
            }
            ImbalanceMessage msg;
            
            std::memcpy(&msg.sourceTime, buffer, sizeof(msg.sourceTime));

            std::memcpy(&msg.sourceTimeNS, buffer + 4, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 8, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 12, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.referencePrice, buffer + 16, sizeof(msg.referencePrice));

            std::memcpy(&msg.pairedQty, buffer + 20, sizeof(msg.pairedQty));

            std::memcpy(&msg.totalImbalanceQty, buffer + 24, sizeof(msg.totalImbalanceQty));

            std::memcpy(&msg.marketImbalanceQty, buffer + 28, sizeof(msg.marketImbalanceQty));

            msg.auctionTime = ntohs(*(reinterpret_cast<const uint16_t*>(buffer + 32)));
            
            msg.auctionType = buffer[34];
            
            msg.imbalanceSide = buffer[35];

            std::memcpy(&msg.continuousBookClearingPrice, buffer + 36, sizeof(msg.continuousBookClearingPrice));

            std::memcpy(&msg.auctionInterestClearingPrice, buffer + 40, sizeof(msg.auctionInterestClearingPrice));

            std::memcpy(&msg.ssrFilingPrice, buffer + 44, sizeof(msg.ssrFilingPrice));

            std::memcpy(&msg.indicativeMatchPrice, buffer + 48, sizeof(msg.indicativeMatchPrice));

            std::memcpy(&msg.upperCollar, buffer + 52, sizeof(msg.upperCollar));

            std::memcpy(&msg.lowerCollar, buffer + 56, sizeof(msg.lowerCollar));

            msg.auctionStatus = buffer[60];
    
            msg.freezeStatus = buffer[61];
            
            msg.numExtensions = buffer[62];

            std::memcpy(&msg.unpairedQty, buffer + 64, sizeof(msg.unpairedQty));

            msg.unpairedSide = buffer[68];
    
            msg.significantImbalance = buffer[69];

            std::cout << "Imbalance Message Processed.\n";
            break;
        }
        case MSG_TYPE_ADD_ORDER_REFRESH: {
            if (size < sizeof(AddOrderRefreshMessage)) {
                std::cerr << "Invalid Add Order Refresh Message size.\n";
                return;
            }
            AddOrderRefreshMessage msg;
            
            std::memcpy(&msg.sourceTime, buffer, sizeof(msg.sourceTime));

            std::memcpy(&msg.sourceTimeNS, buffer + 4, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 8, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 12, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.orderID, buffer + 16, sizeof(msg.orderID));

            std::memcpy(&msg.price, buffer + 24, sizeof(msg.price));

            std::memcpy(&msg.volume, buffer + 28, sizeof(msg.volume));

            msg.side = static_cast<char>(buffer[32]);

            std::memcpy(msg.firmID, buffer + 33, sizeof(msg.firmID));
            msg.firmID[4] = '\0';

            msg.reserved1 = buffer[38];

            std::cout << "Add Order Refresh Message Processed.\n";
            break;
        }
        case MSG_TYPE_NON_DISPLAYED_TRADE: {
            if (size < sizeof(NonDisplayedTradeMessage)) {
                std::cerr << "Invalid Non-Displayed Trade Message size.\n";
                return;
            }
            NonDisplayedTradeMessage msg;
            
            std::memcpy(&msg.sourceTimeNS, buffer, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 4, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 8, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.tradeID, buffer + 12, sizeof(msg.tradeID));

            std::memcpy(&msg.price, buffer + 20, sizeof(msg.price));

            std::memcpy(&msg.volume, buffer + 24, sizeof(msg.volume));

            msg.printableFlag = buffer[28];

            msg.tradeCond1 = static_cast<char>(buffer[29]);

            msg.tradeCond1 = static_cast<char>(buffer[30]);

            msg.tradeCond1 = static_cast<char>(buffer[31]);
            
            msg.tradeCond1 = static_cast<char>(buffer[32]);

            std::cout << "Non Displayed Trade Message Processed.\n";
            break;
        }
        case MSG_TYPE_CROSS_TRADE: {
            if (size < sizeof(CrossTradeMessage)) {
                std::cerr << "Invalid Cross Trade Message size.\n";
                return;
            }
            CrossTradeMessage msg;
            
            std::memcpy(&msg.sourceTimeNS, buffer, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 4, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 8, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.crossID, buffer + 12, sizeof(msg.crossID));

            std::memcpy(&msg.price, buffer + 16, sizeof(msg.price));

            std::memcpy(&msg.volume, buffer + 20, sizeof(msg.volume));

            msg.crossType = static_cast<char>(buffer[24]);

            std::cout << "Cross Trade Message Processed.\n";
            break;
        }
        case MSG_TYPE_TRADE_CANCEL: {
            if (size < sizeof(TradeCancelMessage)) {
                std::cerr << "Invalid Trade Cancel Message size.\n";
                return;
            }
            TradeCancelMessage msg;
            
            std::memcpy(&msg.sourceTimeNS, buffer, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 4, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 8, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.tradeID, buffer + 12, sizeof(msg.tradeID));

            std::cout << "Trade Cancel Message Processed.\n";
            break;
        }
        case MSG_TYPE_CROSS_CORRECTION: {
            if (size < sizeof(CrossCorrectionMessage)) {
                std::cerr << "Invalid Cross Correction Message size.\n";
                return;
            }
            CrossCorrectionMessage msg;

            std::memcpy(&msg.sourceTimeNS, buffer, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 4, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 8, sizeof(msg.symbolSeqNum));

            std::memcpy(&msg.crossID, buffer + 12, sizeof(msg.crossID));

            std::memcpy(&msg.volume, buffer + 16, sizeof(msg.volume));

            std::cout << "Cross Correction Message Processed.\n";
            break;
        }
        case MSG_TYPE_RETAIL_PRICE_IMPROVEMENT: {
            if (size < sizeof(RetailPriceImprovementMessage)) {
                std::cerr << "Invalid Retail Price Improvement Message size.\n";
                return;
            }
            RetailPriceImprovementMessage msg;

            std::memcpy(&msg.sourceTimeNS, buffer, sizeof(msg.sourceTimeNS));

            std::memcpy(&msg.symbolIndex, buffer + 4, sizeof(msg.symbolIndex));

            std::memcpy(&msg.symbolSeqNum, buffer + 8, sizeof(msg.symbolSeqNum));

            msg.rpiIndicator = static_cast<char>(buffer[12]);

            std::cout << "Retail Price Improvement Message Processed.\n";
            break;
        }
        default:
            std::cerr << "Unknown message type: " << messageType << "\n";
            break;
    }
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

    // Validate packet size
    if (pktSize != length) {
        std::cerr << "[Error] Packet size mismatch. Expected: " << pktSize
                  << ", Actual: " << length << "\n";
        return;
    }

    // Start parsing messages
    const uint8_t* messagePtr = data + 16;
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

        // Pass message data for further processing
        const uint8_t* msgData = messagePtr + 4;
        
        handleMessage(msgType, msgData, msgSize);

        // Advance to the next message
        bytesProcessed += msgSize;
        messagePtr += msgSize;
    }
}

// Main Function
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << "\n";
        return 1;
    }

    const char* file_name = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the PCAP file
    pcap_t* handle = pcap_open_offline(file_name, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening file: " << errbuf << "\n";
        return 1;
    }

    struct pcap_pkthdr* packet_header;
    const u_char* packet_data;

    // Loop through packets
    while (pcap_next_ex(handle, &packet_header, &packet_data) > 0) {
        // Parse Ethernet Header
        mac_hdr_t eth_header;
        if (!parseEthernetHeader(packet_data, eth_header)) {
            std::cerr << "Error parsing Ethernet header\n";
            continue;
        }

        // Handle only IPv4 packets
        if (eth_header.ethertype != static_cast<uint16_t>(ethertype_e::ipv4)) {
            std::cerr << "Skipping non-IPv4 packet\n";
            continue;
        }

        // Parse IPv4 Header
        ipv4_hdr_t ipv4_header;
        if (!parseIPv4Header(packet_data + sizeof(mac_hdr_t), ipv4_header)) {
            std::cerr << "Error parsing IPv4 header\n";
            continue;
        }

        // Handle only UDP packets
        if (ipv4_header.protocol != 17) { // Protocol 17 = UDP
            std::cerr << "Skipping non-UDP packet\n";
            continue;
        }

        // Calculate IPv4 Header Length (IHL * 4)
        uint8_t ipv4_header_length = (ipv4_header.version_ihl & 0x0F) * 4;

        // Parse UDP Header
        udp_hdr_t udp_header;
        if (!parseUDPHeader(packet_data + sizeof(mac_hdr_t) + ipv4_header_length, udp_header)) {
            std::cerr << "Error parsing UDP header\n";
            continue;
        }
        
        // Extract UDP Payload
        uint16_t ipHeaderLength = (*(packet_data + 14) & 0x0F) * 4;
        uint16_t udpHeaderOffset = 14 + ipHeaderLength;
        uint16_t udpPayloadOffset = udpHeaderOffset + 8;
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