/*
 * PcapInspector — High-performance TCP session analyzer for huge PCAP/PCAPng files
 *
 * WHY FASTER THAN TSHARK:
 *   1. Memory-mapped I/O + MADV_SEQUENTIAL: kernel read-ahead, zero-copy page cache
 *   2. Direct PCAP/PCAPng parsing: no libpcap dispatch overhead
 *   3. Single-pass streaming: packets are processed inline, never buffered
 *   4. FNV-based hash map: tight session lookup with no regex/Lua overhead
 *   5. Minimal allocations in hot path: only notable events are heap-allocated
 *   6. No general protocol dissector stack: only Ethernet→IP→TCP
 *
 * BUILD:
 *   g++ -std=c++17 -O3 -march=native -Wall -Wextra -o pcap_inspector src/pcap_inspector.cpp
 *
 * USAGE:
 *   pcap_inspector <file.pcap|file.pcapng> [OPTIONS]
 *
 * OPTIONS:
 *   --summary-only          Print only the global stats table
 *   --notable-only          Show only notable events per session [default]
 *   --all-events            Show every packet event in the session map
 *   --min-pkts  <N>         Only report sessions with ≥ N packets   (default 2)
 *   --top       <N>         Show at most N sessions (by packet count)
 *   --filter-ip <A.B.C.D>   Only report sessions involving this IPv4 address
 *   --no-color              Disable ANSI color codes
 */

// ─────────────────────────────────────────────────────────────────────────────
// Includes
// ─────────────────────────────────────────────────────────────────────────────
#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────
static constexpr uint32_t PCAP_MAGIC_LE    = 0xa1b2c3d4u; // pcap, LE, μs
static constexpr uint32_t PCAP_MAGIC_NS_LE = 0xa1b23c4du; // pcap, LE, ns
static constexpr uint32_t PCAP_MAGIC_BE    = 0xd4c3b2a1u; // pcap, BE, μs
static constexpr uint32_t PCAP_MAGIC_NS_BE = 0x4d3cb2a1u; // pcap, BE, ns
static constexpr uint32_t PCAPNG_SHB_TYPE  = 0x0a0d0d0au; // PCAPng Section Header Block
static constexpr uint32_t PCAPNG_IDB_TYPE  = 0x00000001u; // Interface Description Block
static constexpr uint32_t PCAPNG_EPB_TYPE  = 0x00000006u; // Enhanced Packet Block
static constexpr uint32_t PCAPNG_OPB_TYPE  = 0x00000002u; // Obsolete Packet Block
static constexpr uint32_t PCAPNG_SPB_TYPE  = 0x00000003u; // Simple Packet Block
static constexpr uint32_t PCAPNG_BOM       = 0x1a2b3c4du; // byte-order magic

static constexpr uint16_t ETHERTYPE_IP     = 0x0800u;
static constexpr uint16_t ETHERTYPE_8021Q  = 0x8100u;
static constexpr uint16_t ETHERTYPE_8021AD = 0x88a8u;
static constexpr uint8_t  IP_PROTO_TCP     = 6u;

static constexpr uint8_t  TF_FIN = 0x01u;
static constexpr uint8_t  TF_SYN = 0x02u;
static constexpr uint8_t  TF_RST = 0x04u;
static constexpr uint8_t  TF_PSH = 0x08u;
static constexpr uint8_t  TF_ACK = 0x10u;
static constexpr uint8_t  TF_URG = 0x20u;
static constexpr uint8_t  TF_ECE = 0x40u;
static constexpr uint8_t  TF_CWR = 0x80u;

// RFC 793 sequence number comparison (handles wraparound)
#define SEQ_LT(a,b)  ((int32_t)((uint32_t)(a) - (uint32_t)(b)) < 0)
#define SEQ_LEQ(a,b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <= 0)
#define SEQ_GT(a,b)  ((int32_t)((uint32_t)(a) - (uint32_t)(b)) > 0)
#define SEQ_GEQ(a,b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) >= 0)

// ─────────────────────────────────────────────────────────────────────────────
// Wire-format structures (packed, no padding)
// ─────────────────────────────────────────────────────────────────────────────
#pragma pack(push, 1)

struct PcapGlobalHdr {
    uint32_t magic;
    uint16_t ver_major, ver_minor;
    int32_t  thiszone;
    uint32_t sigfigs, snaplen, link_type;
};

struct PcapPktHdr {
    uint32_t ts_sec, ts_sub;   // ts_sub is μs or ns depending on magic
    uint32_t incl_len, orig_len;
};

// PCAPng generic block header
struct NgBlockHdr {
    uint32_t block_type;
    uint32_t block_total_length;
};

struct NgSHB {
    uint32_t block_type;       // 0x0A0D0D0A
    uint32_t block_total_length;
    uint32_t byte_order_magic; // 0x1A2B3C4D
    uint16_t major_version;
    uint16_t minor_version;
    int64_t  section_length;
};

struct NgIDB {
    uint32_t block_type;       // 1
    uint32_t block_total_length;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snap_len;
};

struct NgEPB {
    uint32_t block_type;       // 6
    uint32_t block_total_length;
    uint32_t interface_id;
    uint32_t ts_high;
    uint32_t ts_low;
    uint32_t cap_len;
    uint32_t orig_len;
};

struct NgOPB {
    uint32_t block_type;       // 2
    uint32_t block_total_length;
    uint16_t interface_id;
    uint16_t drops_count;
    uint32_t ts_high;
    uint32_t ts_low;
    uint32_t cap_len;
    uint32_t orig_len;
};

struct EtherHdr {
    uint8_t  dst[6], src[6];
    uint16_t ethertype;
};

struct VlanHdr {
    uint16_t tci, ethertype;
};

struct LinuxSLLHdr {  // cooked capture
    uint16_t pkt_type, ha_type, ha_len;
    uint8_t  addr[8];
    uint16_t proto;
};

struct IPv4Hdr {
    uint8_t  ver_ihl, tos;
    uint16_t total_len, id, frag_off;
    uint8_t  ttl, proto;
    uint16_t cksum;
    uint32_t src, dst;
};

struct TCPHdr {
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t  doff, flags;
    uint16_t win, cksum, urg;
};

#pragma pack(pop)

// ─────────────────────────────────────────────────────────────────────────────
// Session key: normalized 4-tuple (lower endpoint first)
// ─────────────────────────────────────────────────────────────────────────────
struct FlowKey {
    uint32_t ip_a, ip_b;
    uint16_t port_a, port_b;

    bool operator==(const FlowKey& o) const noexcept {
        return ip_a == o.ip_a && ip_b == o.ip_b &&
               port_a == o.port_a && port_b == o.port_b;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
        // FNV-1a 64-bit over 12 bytes
        uint64_t h = 14695981039346656037ULL;
        auto mix64 = [&](uint64_t v) { h = (h ^ v) * 1099511628211ULL; };
        mix64(((uint64_t)k.ip_a   << 32) | k.ip_b);
        mix64(((uint64_t)k.port_a << 16) | k.port_b);
        return h;
    }
};

// Returns the normalized key and whether the packet goes A→B (client→server).
// "A" side is the one with the lower (ip, port) — stable across directions.
static inline std::pair<FlowKey, bool> normalize_flow(
    uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp) noexcept
{
    bool fwd = (sip < dip) || (sip == dip && sp < dp);
    FlowKey k;
    if (fwd) { k.ip_a = sip; k.ip_b = dip; k.port_a = sp; k.port_b = dp; }
    else     { k.ip_a = dip; k.ip_b = sip; k.port_a = dp; k.port_b = sp; }
    return {k, fwd};
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP event classification
// ─────────────────────────────────────────────────────────────────────────────
enum class EvType : uint8_t {
    SYN, SYN_ACK,
    ACK, DATA,
    RETRANSMISSION, OUT_OF_ORDER,
    DUPLICATE_ACK, ZERO_WINDOW, WINDOW_UPDATE,
    FIN, FIN_ACK,
    RST,
    UNKNOWN
};

static const char* ev_name(EvType t) noexcept {
    switch (t) {
    case EvType::SYN:            return "SYN";
    case EvType::SYN_ACK:        return "SYN-ACK";
    case EvType::ACK:            return "ACK";
    case EvType::DATA:           return "DATA";
    case EvType::RETRANSMISSION: return "RETRANSMISSION";
    case EvType::OUT_OF_ORDER:   return "OUT-OF-ORDER";
    case EvType::DUPLICATE_ACK:  return "DUPLICATE-ACK";
    case EvType::ZERO_WINDOW:    return "ZERO-WINDOW";
    case EvType::WINDOW_UPDATE:  return "WINDOW-UPDATE";
    case EvType::FIN:            return "FIN";
    case EvType::FIN_ACK:        return "FIN-ACK";
    case EvType::RST:            return "RST";
    default:                     return "UNKNOWN";
    }
}

static bool is_notable(EvType t) noexcept {
    switch (t) {
    case EvType::SYN:
    case EvType::SYN_ACK:
    case EvType::FIN:
    case EvType::FIN_ACK:
    case EvType::RST:
    case EvType::RETRANSMISSION:
    case EvType::OUT_OF_ORDER:
    case EvType::DUPLICATE_ACK:
    case EvType::ZERO_WINDOW:
        return true;
    default:
        return false;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP stream state (per direction)
// ─────────────────────────────────────────────────────────────────────────────
struct StreamState {
    bool     ok       = false; // has been initialized by a SYN/first packet
    uint32_t isn      = 0;     // initial sequence number
    uint32_t next_seq = 0;     // next expected sequence number
    uint32_t high_seq = 0;     // highest sequence number end seen (seq+len)
    uint32_t last_ack = 0;     // last ACK value this side has sent
    uint16_t last_win = 0;     // last window size advertised

    void init_from_syn(uint32_t seq) noexcept {
        ok       = true;
        isn      = seq;
        next_seq = seq + 1;  // SYN consumes one sequence slot
        high_seq = seq + 1;
    }

    // relative seq (from 0) for human-readable display
    uint32_t rel(uint32_t seq) const noexcept { return seq - isn; }
};

// ─────────────────────────────────────────────────────────────────────────────
// Recorded event (kept only for notable or --all-events mode)
// ─────────────────────────────────────────────────────────────────────────────
struct TcpEvent {
    uint64_t ts_us;        // epoch microseconds
    EvType   type;
    bool     from_client;
    uint8_t  flags;
    uint32_t seq;
    uint32_t ack;
    uint32_t payload_len;
    uint16_t window;
};

// ─────────────────────────────────────────────────────────────────────────────
// TCP session (one per 4-tuple)
// ─────────────────────────────────────────────────────────────────────────────
enum class SessState : uint8_t {
    CLOSED, SYN_SENT, SYN_RCVD, ESTABLISHED,
    FIN_WAIT, CLOSE_WAIT, LAST_ACK, TIME_WAIT, RESET
};

static const char* sess_state_name(SessState s) noexcept {
    switch (s) {
    case SessState::CLOSED:      return "CLOSED";
    case SessState::SYN_SENT:    return "SYN_SENT";
    case SessState::SYN_RCVD:    return "SYN_RCVD";
    case SessState::ESTABLISHED: return "ESTABLISHED";
    case SessState::FIN_WAIT:    return "FIN_WAIT";
    case SessState::CLOSE_WAIT:  return "CLOSE_WAIT";
    case SessState::LAST_ACK:    return "LAST_ACK";
    case SessState::TIME_WAIT:   return "TIME_WAIT";
    case SessState::RESET:       return "RESET";
    default:                     return "UNKNOWN";
    }
}

struct TcpSession {
    // Identification
    uint32_t  client_ip  = 0;  // SYN sender
    uint32_t  server_ip  = 0;
    uint16_t  client_port= 0;
    uint16_t  server_port= 0;

    // Per-direction stream state
    StreamState cli;   // client → server
    StreamState srv;   // server → client

    // State machine
    SessState state = SessState::CLOSED;

    // Timing
    uint64_t start_ts       = 0;
    uint64_t established_ts = 0;
    uint64_t last_ts        = 0;

    // Counters
    uint32_t total_pkts    = 0;
    uint32_t syn_count     = 0;
    uint32_t synack_count  = 0;
    uint32_t rst_count     = 0;
    uint32_t fin_count     = 0;
    uint32_t retrans_count = 0;
    uint32_t ooo_count     = 0;    // out-of-order
    uint32_t dupack_count  = 0;
    uint32_t zwin_count    = 0;    // zero-window
    uint64_t bytes_cli     = 0;    // payload bytes client→server
    uint64_t bytes_srv     = 0;    // payload bytes server→client

    // Event map (notable events, or all if --all-events)
    std::vector<TcpEvent> events;
};

// ─────────────────────────────────────────────────────────────────────────────
// Classify + update a single packet against a session
// ─────────────────────────────────────────────────────────────────────────────
static EvType classify_and_update(
    TcpSession& sess,
    const TCPHdr* tcp,
    uint32_t payload_len,
    bool from_client) noexcept
{
    uint8_t  fl  = tcp->flags;
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack = ntohl(tcp->ack);
    uint16_t win = ntohs(tcp->win);

    StreamState& sender   = from_client ? sess.cli : sess.srv;
    StreamState& receiver = from_client ? sess.srv : sess.cli;

    // ── RST: highest priority ──────────────────────────────────────────────
    if (fl & TF_RST) {
        sess.rst_count++;
        sess.state = SessState::RESET;
        return EvType::RST;
    }

    // ── SYN variants ──────────────────────────────────────────────────────
    if (fl & TF_SYN) {
        if (fl & TF_ACK) {
            // SYN-ACK: server side
            sender.init_from_syn(seq);
            sess.synack_count++;
            if (sess.state == SessState::SYN_SENT)
                sess.state = SessState::SYN_RCVD;
            // Update receiver's ACK tracking
            if (fl & TF_ACK) { receiver.last_ack = ack; receiver.last_win = win; }
            return EvType::SYN_ACK;
        } else {
            // Detect SYN retransmission: same ISN as a previous SYN
            if (sender.ok && seq == sender.isn) {
                sess.syn_count++;
                sess.retrans_count++;
                return EvType::RETRANSMISSION;  // SYN retransmission
            }
            sender.init_from_syn(seq);
            sess.syn_count++;
            if (sess.state == SessState::CLOSED || sess.state == SessState::SYN_SENT)
                sess.state = SessState::SYN_SENT;
            return EvType::SYN;
        }
    }

    // ── FIN variants ──────────────────────────────────────────────────────
    if (fl & TF_FIN) {
        sess.fin_count++;
        if (sess.state == SessState::ESTABLISHED)
            sess.state = from_client ? SessState::FIN_WAIT : SessState::CLOSE_WAIT;
        else if (sess.state == SessState::FIN_WAIT || sess.state == SessState::CLOSE_WAIT)
            sess.state = SessState::LAST_ACK;
        // Advance seq for FIN (consumes 1 slot)
        if (sender.ok) {
            uint32_t end = seq + 1;
            if (SEQ_GT(end, sender.high_seq)) sender.high_seq = end;
            sender.next_seq = end;
        }
        if (fl & TF_ACK) { receiver.last_ack = ack; receiver.last_win = win; }
        return (fl & TF_ACK) ? EvType::FIN_ACK : EvType::FIN;
    }

    // ── Transition to ESTABLISHED on first ACK after SYN-ACK ─────────────
    if (sess.state == SessState::SYN_RCVD && (fl & TF_ACK) && payload_len == 0) {
        sess.state       = SessState::ESTABLISHED;
        sess.established_ts = sess.last_ts; // will be updated below
    }

    // ── Data / ACK packets ────────────────────────────────────────────────
    EvType result = EvType::UNKNOWN;

    if (!sender.ok) {
        // Mid-flow capture, no SYN seen: bootstrap state
        sender.ok       = true;
        sender.isn      = seq;
        sender.next_seq = seq + payload_len;
        sender.high_seq = seq + payload_len;
    }

    if (payload_len > 0) {
        uint32_t end_seq = seq + payload_len;
        if (SEQ_LT(seq, sender.next_seq)) {
            // Seq is below what we expected → retransmission
            result = EvType::RETRANSMISSION;
            sess.retrans_count++;
        } else if (SEQ_GT(seq, sender.next_seq)) {
            // Gap: out-of-order segment arrived ahead of time
            result = EvType::OUT_OF_ORDER;
            sess.ooo_count++;
            // Advance high_seq but don't move next_seq (gap still open)
            if (SEQ_GT(end_seq, sender.high_seq)) sender.high_seq = end_seq;
        } else {
            // seq == next_seq: normal in-order delivery
            result = EvType::DATA;
            sender.next_seq = end_seq;
            if (SEQ_GT(end_seq, sender.high_seq)) sender.high_seq = end_seq;
        }
    } else {
        // Pure ACK / control
        if (fl & TF_ACK) {
            if (win == 0) {
                result = EvType::ZERO_WINDOW;
                sess.zwin_count++;
            } else if (receiver.ok && ack == receiver.last_ack) {
                if (win != receiver.last_win) {
                    result = EvType::WINDOW_UPDATE;
                } else {
                    result = EvType::DUPLICATE_ACK;
                    sess.dupack_count++;
                }
            } else {
                result = EvType::ACK;
            }
        }
    }

    // Update receiver ACK bookkeeping
    if (fl & TF_ACK) {
        receiver.last_ack = ack;
        receiver.last_win = win;
    }

    // Byte accounting
    if (from_client) sess.bytes_cli += payload_len;
    else             sess.bytes_srv += payload_len;

    // LAST_ACK → TIME_WAIT: when we receive the final ACK acknowledging our FIN
    if (sess.state == SessState::LAST_ACK && (fl & TF_ACK) && payload_len == 0)
        sess.state = SessState::TIME_WAIT;

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet layer parser: returns pointer to TCP header & fills src/dst/payload
// Returns nullptr if not IPv4-TCP or if malformed / fragmented
// ─────────────────────────────────────────────────────────────────────────────
static const TCPHdr* parse_to_tcp(
    const uint8_t* pkt, uint32_t pkt_len,
    uint32_t link_type,
    uint32_t& src_ip, uint32_t& dst_ip,
    uint32_t& payload_len) noexcept
{
    const uint8_t* p   = pkt;
    const uint8_t* end = pkt + pkt_len;
    uint16_t ethertype = 0;

    // ── Layer 2 ───────────────────────────────────────────────────────────
    switch (link_type) {
    case 1: {  // Ethernet
        if (p + 14 > end) return nullptr;
        const auto* eth = reinterpret_cast<const EtherHdr*>(p);
        ethertype = ntohs(eth->ethertype);
        p += 14;
        // Unwrap VLAN stacks
        while (ethertype == ETHERTYPE_8021Q || ethertype == ETHERTYPE_8021AD) {
            if (p + 4 > end) return nullptr;
            const auto* v = reinterpret_cast<const VlanHdr*>(p);
            ethertype = ntohs(v->ethertype);
            p += 4;
        }
        break;
    }
    case 101: // Raw IPv4
        ethertype = ETHERTYPE_IP;
        break;
    case 113: { // Linux cooked (SLL)
        if (p + 16 > end) return nullptr;
        const auto* sll = reinterpret_cast<const LinuxSLLHdr*>(p);
        ethertype = ntohs(sll->proto);
        p += 16;
        break;
    }
    default:
        return nullptr;
    }

    if (ethertype != ETHERTYPE_IP) return nullptr;

    // ── IPv4 ──────────────────────────────────────────────────────────────
    if (p + 20 > end) return nullptr;
    const auto* ip = reinterpret_cast<const IPv4Hdr*>(p);

    uint8_t  ihl      = (ip->ver_ihl & 0x0fu) * 4u;
    if (ihl < 20) return nullptr;
    if (ip->proto != IP_PROTO_TCP) return nullptr;

    // Ignore fragments (MF bit or nonzero fragment offset)
    uint16_t frag = ntohs(ip->frag_off);
    if (frag & 0x3fffu) return nullptr;

    uint16_t ip_total = ntohs(ip->total_len);
    src_ip = ip->src;
    dst_ip = ip->dst;
    p += ihl;

    // ── TCP ───────────────────────────────────────────────────────────────
    if (p + 20 > end) return nullptr;
    const auto* tcp = reinterpret_cast<const TCPHdr*>(p);

    uint8_t tcp_hdr_len = (tcp->doff >> 4u) * 4u;
    if (tcp_hdr_len < 20) return nullptr;
    if (p + tcp_hdr_len > end) return nullptr;

    // payload_len from IP header (authoritative, handles snap truncation)
    uint32_t ip_data  = (ip_total > ihl) ? ip_total - ihl : 0u;
    payload_len = (ip_data > tcp_hdr_len) ? ip_data - tcp_hdr_len : 0u;

    return tcp;
}

// ─────────────────────────────────────────────────────────────────────────────
// PCAP file reader (classic .pcap format via mmap)
// ─────────────────────────────────────────────────────────────────────────────
class PcapReader {
public:
    explicit PcapReader(const uint8_t* data, size_t size)
        : p_(data), end_(data + size), ok_(false),
          byte_swap_(false), ns_ts_(false), link_type_(1)
    {
        if (size < sizeof(PcapGlobalHdr)) return;
        const auto* gh = reinterpret_cast<const PcapGlobalHdr*>(data);
        switch (gh->magic) {
        case PCAP_MAGIC_LE:    byte_swap_=false; ns_ts_=false; break;
        case PCAP_MAGIC_NS_LE: byte_swap_=false; ns_ts_=true;  break;
        case PCAP_MAGIC_BE:    byte_swap_=true;  ns_ts_=false; break;
        case PCAP_MAGIC_NS_BE: byte_swap_=true;  ns_ts_=true;  break;
        default: return;
        }
        link_type_ = bs32(gh->link_type);
        p_ += sizeof(PcapGlobalHdr);
        ok_ = true;
    }

    bool ok()        const noexcept { return ok_; }
    uint32_t ltype() const noexcept { return link_type_; }

    struct Pkt { uint64_t ts_us; uint32_t cap_len; const uint8_t* data; };

    bool next(Pkt& out) noexcept {
        if (p_ + sizeof(PcapPktHdr) > end_) return false;
        const auto* ph = reinterpret_cast<const PcapPktHdr*>(p_);
        uint32_t ts_sec  = bs32(ph->ts_sec);
        uint32_t ts_sub  = bs32(ph->ts_sub);
        uint32_t cap_len = bs32(ph->incl_len);
        p_ += sizeof(PcapPktHdr);
        if (p_ + cap_len > end_) return false;
        out.data    = p_;
        out.cap_len = cap_len;
        out.ts_us   = ns_ts_ ? (uint64_t)ts_sec * 1'000'000 + ts_sub / 1000
                              : (uint64_t)ts_sec * 1'000'000 + ts_sub;
        p_ += cap_len;
        return true;
    }

private:
    uint32_t bs32(uint32_t v) const noexcept {
        return byte_swap_ ? __builtin_bswap32(v) : v;
    }

    const uint8_t* p_;
    const uint8_t* end_;
    bool ok_, byte_swap_, ns_ts_;
    uint32_t link_type_;
};

// ─────────────────────────────────────────────────────────────────────────────
// PCAPng file reader
// ─────────────────────────────────────────────────────────────────────────────
class PcapNgReader {
public:
    explicit PcapNgReader(const uint8_t* data, size_t size)
        : p_(data), end_(data + size), ok_(false),
          byte_swap_(false)
    {
        if (size < sizeof(NgSHB)) return;
        const auto* shb = reinterpret_cast<const NgSHB*>(data);
        if (shb->block_type != PCAPNG_SHB_TYPE) return;
        // Byte-order detection
        if (shb->byte_order_magic == PCAPNG_BOM) {
            byte_swap_ = false;
        } else if (__builtin_bswap32(shb->byte_order_magic) == PCAPNG_BOM) {
            byte_swap_ = true;
        } else {
            return;
        }
        // Skip past SHB
        uint32_t shb_len = bs32(shb->block_total_length);
        p_ += shb_len;
        ok_ = true;
    }

    bool ok() const noexcept { return ok_; }

    struct Pkt {
        uint64_t ts_us;
        uint32_t cap_len;
        uint32_t link_type; // interface link type
        const uint8_t* data;
    };

    bool next(Pkt& out) noexcept {
        while (p_ + sizeof(NgBlockHdr) <= end_) {
            const auto* bh = reinterpret_cast<const NgBlockHdr*>(p_);
            uint32_t btype = bs32(bh->block_type);
            uint32_t blen  = bs32(bh->block_total_length);
            if (blen < 12 || p_ + blen > end_) return false;

            const uint8_t* block_end = p_ + blen;

            if (btype == PCAPNG_IDB_TYPE) {
                if (p_ + sizeof(NgIDB) <= block_end) {
                    const auto* idb = reinterpret_cast<const NgIDB*>(p_);
                    uint32_t lt = bs32(idb->link_type);
                    // link_type stored in lower 16 bits
                    ifaces_.push_back((uint16_t)(lt & 0xffff));
                    // ts resolution: default μs; options would refine this
                    ts_res_.push_back(1'000'000ULL); // default: 1 tick = 1 μs
                }
                p_ = block_end;
                continue;
            }

            if (btype == PCAPNG_EPB_TYPE) {
                if (p_ + sizeof(NgEPB) > block_end) { p_ = block_end; continue; }
                const auto* epb = reinterpret_cast<const NgEPB*>(p_);
                uint32_t iface  = bs32(epb->interface_id);
                uint32_t tsh    = bs32(epb->ts_high);
                uint32_t tsl    = bs32(epb->ts_low);
                uint32_t caplen = bs32(epb->cap_len);
                uint64_t ts64   = ((uint64_t)tsh << 32) | tsl;
                uint64_t res    = (iface < ifaces_.size()) ? ts_res_[iface] : 1'000'000ULL;
                // Convert ts64 ticks → μs
                // ts_res = ticks per second; μs = ts64 * 1e6 / ts_res
                out.ts_us    = ts64 * 1'000'000ULL / res;
                out.cap_len  = caplen;
                out.link_type= (iface < ifaces_.size()) ? ifaces_[iface] : 1u;
                out.data     = p_ + sizeof(NgEPB);
                p_ = block_end;
                return true;
            }

            if (btype == PCAPNG_OPB_TYPE) {
                if (p_ + sizeof(NgOPB) > block_end) { p_ = block_end; continue; }
                const auto* opb = reinterpret_cast<const NgOPB*>(p_);
                uint32_t iface  = bs32(opb->interface_id);
                uint32_t tsh    = bs32(opb->ts_high);
                uint32_t tsl    = bs32(opb->ts_low);
                uint32_t caplen = bs32(opb->cap_len);
                uint64_t ts64   = ((uint64_t)tsh << 32) | tsl;
                uint64_t res    = (iface < ifaces_.size()) ? ts_res_[iface] : 1'000'000ULL;
                out.ts_us    = ts64 * 1'000'000ULL / res;
                out.cap_len  = caplen;
                out.link_type= (iface < ifaces_.size()) ? ifaces_[iface] : 1u;
                out.data     = p_ + sizeof(NgOPB);
                p_ = block_end;
                return true;
            }

            if (btype == PCAPNG_SPB_TYPE) {
                // SPB: no timestamp, no interface id — skip
                p_ = block_end;
                continue;
            }

            if (btype == PCAPNG_SHB_TYPE) {
                // New section — reset interface table
                ifaces_.clear(); ts_res_.clear();
                p_ = block_end;
                continue;
            }

            // Unknown block — skip
            p_ = block_end;
        }
        return false;
    }

private:
    uint32_t bs32(uint32_t v) const noexcept {
        return byte_swap_ ? __builtin_bswap32(v) : v;
    }

    const uint8_t*        p_;
    const uint8_t*        end_;
    bool                  ok_, byte_swap_;
    std::vector<uint16_t> ifaces_;   // link type per interface index
    std::vector<uint64_t> ts_res_;   // ticks-per-second per interface
};

// ─────────────────────────────────────────────────────────────────────────────
// Output / reporter helpers
// ─────────────────────────────────────────────────────────────────────────────
static bool g_color = true;

#define CLR_RESET  (g_color ? "\033[0m"  : "")
#define CLR_BOLD   (g_color ? "\033[1m"  : "")
#define CLR_RED    (g_color ? "\033[91m" : "")
#define CLR_GREEN  (g_color ? "\033[92m" : "")
#define CLR_YELLOW (g_color ? "\033[93m" : "")
#define CLR_CYAN   (g_color ? "\033[96m" : "")
#define CLR_GRAY   (g_color ? "\033[90m" : "")
#define CLR_MAG    (g_color ? "\033[95m" : "")

static char* ip4_str(uint32_t ip_be, char buf[16]) noexcept {
    // ip is in network byte order (from wire)
    uint8_t* b = reinterpret_cast<uint8_t*>(&ip_be);
    snprintf(buf, 16, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

static void ts_str(uint64_t ts_us, char buf[24]) noexcept {
    time_t  sec = (time_t)(ts_us / 1'000'000);
    uint32_t us = (uint32_t)(ts_us % 1'000'000);
    struct tm t;
    gmtime_r(&sec, &t);
    snprintf(buf, 24, "%02d:%02d:%02d.%06u",
             t.tm_hour, t.tm_min, t.tm_sec, us);
}

static const char* flags_str(uint8_t fl, char buf[9]) noexcept {
    char* p = buf;
    if (fl & TF_CWR) *p++ = 'C';
    if (fl & TF_ECE) *p++ = 'E';
    if (fl & TF_URG) *p++ = 'U';
    if (fl & TF_ACK) *p++ = 'A';
    if (fl & TF_PSH) *p++ = 'P';
    if (fl & TF_RST) *p++ = 'R';
    if (fl & TF_SYN) *p++ = 'S';
    if (fl & TF_FIN) *p++ = 'F';
    if (p == buf) *p++ = '.';
    *p = '\0';
    return buf;
}

// Compact human-readable byte count
static void fmt_bytes(uint64_t b, char buf[16]) noexcept {
    if      (b < 1024)           snprintf(buf, 16, "%" PRIu64 " B",  b);
    else if (b < 1024*1024)      snprintf(buf, 16, "%.1f KB", b/1024.0);
    else if (b < 1024*1024*1024) snprintf(buf, 16, "%.1f MB", b/(1024.0*1024));
    else                         snprintf(buf, 16, "%.2f GB", b/(1024.0*1024*1024));
}

static const char* ev_color(EvType t) noexcept {
    switch (t) {
    case EvType::SYN:
    case EvType::SYN_ACK:        return CLR_GREEN;
    case EvType::RST:            return CLR_RED;
    case EvType::FIN:
    case EvType::FIN_ACK:        return CLR_YELLOW;
    case EvType::RETRANSMISSION: return CLR_MAG;
    case EvType::OUT_OF_ORDER:   return CLR_CYAN;
    case EvType::DUPLICATE_ACK:  return CLR_GRAY;
    case EvType::ZERO_WINDOW:    return CLR_RED;
    default:                     return "";
    }
}

// Event printing function
static void print_events(const TcpSession& s, bool all_events) {
    char ts_buf[24], fb[9];

    for (const auto& ev : s.events) {
        if (!all_events && !is_notable(ev.type)) continue;

        ts_str(ev.ts_us, ts_buf);
        flags_str(ev.flags, fb);

        const char* dir  = ev.from_client ? "C→S" : "S→C";
        const char* name = ev_name(ev.type);
        const char* col  = ev_color(ev.type);

        uint32_t rel_seq, rel_ack;
        if (ev.from_client) {
            rel_seq = s.cli.ok ? ev.seq - s.cli.isn : ev.seq;
            rel_ack = s.srv.ok ? ev.ack - s.srv.isn : ev.ack;
        } else {
            rel_seq = s.srv.ok ? ev.seq - s.srv.isn : ev.seq;
            rel_ack = s.cli.ok ? ev.ack - s.cli.isn : ev.ack;
        }

        if (ev.flags & TF_ACK) {
            printf("║  %-15s %-4s %s%-18s%s %-11u %-11u %-7u %s\n",
                   ts_buf, dir, col, name, CLR_RESET,
                   rel_seq, rel_ack, ev.payload_len, fb);
        } else {
            printf("║  %-15s %-4s %s%-18s%s %-11u %-11s %-7u %s\n",
                   ts_buf, dir, col, name, CLR_RESET,
                   rel_seq, "-", ev.payload_len, fb);
        }
    }
}

// Final clean session printer that calls print_events
static void print_session_report(const TcpSession& s, uint32_t idx, bool all_events) {
    char ci[16], si[16], bb[16];
    ip4_str(s.client_ip, ci);
    ip4_str(s.server_ip, si);

    double dur_ms = s.start_ts ? (double)(s.last_ts - s.start_ts) / 1000.0 : 0.0;

    printf("\n");
    printf("%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n",
           CLR_BOLD, CLR_RESET);
    printf("║  %sSession #%-5u%s  %s%s:%-5u → %s:%-5u%s\n",
           CLR_BOLD, idx, CLR_RESET,
           CLR_CYAN, ci, s.client_port, si, s.server_port, CLR_RESET);
    printf("║  State: %s%-13s%s  Duration: %8.3f ms   Packets: %u\n",
           CLR_BOLD, sess_state_name(s.state), CLR_RESET,
           dur_ms, s.total_pkts);
    fmt_bytes(s.bytes_cli, bb); printf("║  C→S bytes: %-12s", bb);
    fmt_bytes(s.bytes_srv, bb); printf("  S→C bytes: %s\n", bb);

    printf("%s╠─ SUMMARY ───────────────────────────────────────────────────────────────────╣%s\n",
           CLR_BOLD, CLR_RESET);
    printf("║  %sSYN%s         : %-5u   %sSYN-ACK%s    : %-5u\n",
           CLR_GREEN, CLR_RESET, s.syn_count,
           CLR_GREEN, CLR_RESET, s.synack_count);
    printf("║  %sFIN%s         : %-5u   %sRST%s        : %-5u\n",
           CLR_YELLOW, CLR_RESET, s.fin_count,
           CLR_RED,    CLR_RESET, s.rst_count);
    printf("║  %sRetrans%s     : %-5u   %sOut-of-Order%s: %-5u\n",
           CLR_MAG, CLR_RESET, s.retrans_count,
           CLR_CYAN, CLR_RESET, s.ooo_count);
    printf("║  %sDup-ACK%s     : %-5u   %sZero-Window%s : %-5u\n",
           CLR_GRAY, CLR_RESET, s.dupack_count,
           CLR_RED,  CLR_RESET, s.zwin_count);

    printf("%s╠─ EVENT MAP ─────────────────────────────────────────────────────────────────╣%s\n",
           CLR_BOLD, CLR_RESET);
    printf("║  %s%-15s %-4s %-18s %-11s %-11s %-7s %-8s%s\n",
           CLR_BOLD,
           "Time(UTC)", "Dir", "Event", "Seq(rel)", "Ack(rel)", "Len", "Flags",
           CLR_RESET);
    printf("║  %s%-15s %-4s %-18s %-11s %-11s %-7s %-8s%s\n",
           CLR_GRAY,
           "───────────────", "────", "──────────────────",
           "───────────", "───────────", "───────", "────────",
           CLR_RESET);

    print_events(s, all_events);

    printf("%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n",
           CLR_BOLD, CLR_RESET);
}

// ─────────────────────────────────────────────────────────────────────────────
// mmap helper
// ─────────────────────────────────────────────────────────────────────────────
struct MmapFile {
    void*  data = nullptr;
    size_t size = 0;
    int    fd   = -1;

    bool open(const char* path) {
        fd = ::open(path, O_RDONLY);
        if (fd < 0) { perror("open"); return false; }
        struct stat st;
        if (fstat(fd, &st) < 0) { perror("fstat"); return false; }
        size = (size_t)st.st_size;
        if (size == 0) { fprintf(stderr, "Empty file\n"); return false; }
        data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
        if (data == MAP_FAILED) { perror("mmap"); data=nullptr; return false; }
        // Hint: sequential read pattern → triggers aggressive kernel read-ahead
        madvise(data, size, MADV_SEQUENTIAL | MADV_WILLNEED);
        return true;
    }

    ~MmapFile() {
        if (data) munmap(data, size);
        if (fd >= 0) ::close(fd);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <file.pcap|file.pcapng> [OPTIONS]\n"
            "\n"
            "Options:\n"
            "  --summary-only          Only print global statistics\n"
            "  --notable-only          Show only notable events per session [default]\n"
            "  --all-events            Show every packet event in session maps\n"
            "  --min-pkts  <N>         Only show sessions with >= N packets (default 2)\n"
            "  --top       <N>         Show at most N sessions (highest packet count first)\n"
            "  --filter-ip <A.B.C.D>   Only show sessions involving this IP\n"
            "  --no-color              Disable ANSI colors\n"
            "\n"
            "Examples:\n"
            "  %s capture.pcap\n"
            "  %s capture.pcapng --min-pkts 10 --top 100\n"
            "  %s capture.pcap --filter-ip 192.168.1.5 --all-events\n"
            "  %s capture.pcap --summary-only\n",
            argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    const char* path       = argv[1];
    bool  summary_only     = false;
    bool  all_events       = false;
    uint32_t min_pkts      = 2;
    uint32_t top_n         = UINT32_MAX;
    uint32_t filter_ip     = 0;  // 0 = no filter

    for (int i = 2; i < argc; i++) {
        if      (!strcmp(argv[i], "--summary-only"))  summary_only = true;
        else if (!strcmp(argv[i], "--notable-only"))  all_events   = false;
        else if (!strcmp(argv[i], "--all-events"))    all_events   = true;
        else if (!strcmp(argv[i], "--no-color"))      g_color      = false;
        else if (!strcmp(argv[i], "--min-pkts") && i+1 < argc)
            min_pkts = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--top") && i+1 < argc)
            top_n = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--filter-ip") && i+1 < argc) {
            struct in_addr a;
            if (inet_aton(argv[++i], &a)) filter_ip = a.s_addr;
            else { fprintf(stderr, "Invalid IP: %s\n", argv[i]); return 1; }
        }
    }

    // ── Memory-map the file ───────────────────────────────────────────────
    MmapFile mf;
    if (!mf.open(path)) return 1;

    const uint8_t* raw = reinterpret_cast<const uint8_t*>(mf.data);

    // ── Detect format ─────────────────────────────────────────────────────
    if (mf.size < 4) { fprintf(stderr, "File too small\n"); return 1; }
    uint32_t magic4;
    memcpy(&magic4, raw, 4);

    bool is_pcapng = (magic4 == PCAPNG_SHB_TYPE);
    bool is_pcap   = (magic4 == PCAP_MAGIC_LE || magic4 == PCAP_MAGIC_NS_LE ||
                      magic4 == PCAP_MAGIC_BE || magic4 == PCAP_MAGIC_NS_BE);
    if (!is_pcap && !is_pcapng) {
        fprintf(stderr, "Unrecognized file format (magic=0x%08x). "
                        "Supported: .pcap and .pcapng\n", magic4);
        return 1;
    }

    // ── Session table ─────────────────────────────────────────────────────
    std::unordered_map<FlowKey, TcpSession, FlowKeyHash> sessions;
    sessions.reserve(1 << 16);  // pre-allocate 64K buckets

    uint64_t total_pkts = 0;
    uint64_t tcp_pkts   = 0;
    uint64_t skipped    = 0;

    auto t0 = std::chrono::steady_clock::now();

    // ── Unified packet dispatch lambda ────────────────────────────────────
    auto dispatch = [&](uint64_t ts_us, uint32_t cap_len,
                        const uint8_t* pkt_data, uint32_t link_type)
    {
        total_pkts++;
        uint32_t src_ip, dst_ip, payload_len;
        const TCPHdr* tcp = parse_to_tcp(pkt_data, cap_len, link_type,
                                         src_ip, dst_ip, payload_len);
        if (!tcp) { skipped++; return; }
        tcp_pkts++;

        uint16_t sport = ntohs(tcp->sport);
        uint16_t dport = ntohs(tcp->dport);

        auto [key, fwd_hint] = normalize_flow(src_ip, sport, dst_ip, dport);

        auto it = sessions.find(key);
        bool is_new = (it == sessions.end());

        if (is_new) {
            TcpSession sess;
            // Determine client/server from this first packet
            uint8_t fl = tcp->flags;
            bool is_syn    = (fl & TF_SYN) && !(fl & TF_ACK);
            bool is_synack = (fl & TF_SYN) &&  (fl & TF_ACK);

            if (is_syn) {
                // SYN sender is the client
                sess.client_ip   = src_ip;
                sess.server_ip   = dst_ip;
                sess.client_port = sport;
                sess.server_port = dport;
            } else if (is_synack) {
                // SYN-ACK sender is server; client is the other end
                sess.client_ip   = dst_ip;
                sess.server_ip   = src_ip;
                sess.client_port = dport;
                sess.server_port = sport;
            } else {
                // Mid-flow: fall back to IP-ordering heuristic
                if (fwd_hint) {
                    sess.client_ip   = src_ip;  sess.server_ip   = dst_ip;
                    sess.client_port = sport;   sess.server_port = dport;
                } else {
                    sess.client_ip   = dst_ip;  sess.server_ip   = src_ip;
                    sess.client_port = dport;   sess.server_port = sport;
                }
            }

            sess.start_ts = ts_us;
            sess.events.reserve(64);
            auto [it2, _] = sessions.emplace(key, std::move(sess));
            it = it2;
        }

        TcpSession& sess = it->second;
        sess.last_ts = ts_us;
        sess.total_pkts++;

        // Determine direction relative to established client/server roles
        bool from_client = (src_ip == sess.client_ip &&
                            sport  == sess.client_port);

        EvType etype = classify_and_update(sess, tcp, payload_len, from_client);

        // Record event (always record notable; record all if --all-events)
        if (all_events || is_notable(etype)) {
            TcpEvent ev;
            ev.ts_us       = ts_us;
            ev.type        = etype;
            ev.from_client = from_client;
            ev.flags       = tcp->flags;
            ev.seq         = ntohl(tcp->seq);
            ev.ack         = ntohl(tcp->ack);
            ev.payload_len = payload_len;
            ev.window      = ntohs(tcp->win);
            sess.events.push_back(ev);
        }
    };

    // ── Process packets ───────────────────────────────────────────────────
    if (is_pcap) {
        PcapReader rdr(raw, mf.size);
        if (!rdr.ok()) { fprintf(stderr, "Failed to parse PCAP header\n"); return 1; }
        PcapReader::Pkt pkt;
        while (rdr.next(pkt))
            dispatch(pkt.ts_us, pkt.cap_len, pkt.data, rdr.ltype());
    } else {
        PcapNgReader rdr(raw, mf.size);
        if (!rdr.ok()) { fprintf(stderr, "Failed to parse PCAPng header\n"); return 1; }
        PcapNgReader::Pkt pkt;
        while (rdr.next(pkt))
            dispatch(pkt.ts_us, pkt.cap_len, pkt.data, pkt.link_type);
    }

    auto t1 = std::chrono::steady_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // ── Collect, filter, sort sessions ───────────────────────────────────
    std::vector<const TcpSession*> report;
    report.reserve(sessions.size());

    for (const auto& [k, s] : sessions) {
        if (s.total_pkts < min_pkts) continue;
        if (filter_ip != 0) {
            if (s.client_ip != filter_ip && s.server_ip != filter_ip) continue;
        }
        report.push_back(&s);
    }

    // Sort: sessions with most packets first
    std::sort(report.begin(), report.end(),
        [](const TcpSession* a, const TcpSession* b) {
            return a->total_pkts > b->total_pkts;
        });

    if (report.size() > top_n) report.resize(top_n);

    // Re-sort by time for display (chronological)
    std::sort(report.begin(), report.end(),
        [](const TcpSession* a, const TcpSession* b) {
            return a->start_ts < b->start_ts;
        });

    // ── Print per-session reports ─────────────────────────────────────────
    if (!summary_only) {
        for (uint32_t i = 0; i < (uint32_t)report.size(); i++) {
            print_session_report(*report[i], i + 1, all_events);
        }
    }

    // ── Global summary ────────────────────────────────────────────────────
    uint64_t g_syn=0, g_synack=0, g_rst=0, g_fin=0;
    uint64_t g_retrans=0, g_ooo=0, g_dupacks=0, g_zwin=0;
    uint64_t g_bytes_cli=0, g_bytes_srv=0;

    for (const auto& [k, s] : sessions) {
        g_syn     += s.syn_count;
        g_synack  += s.synack_count;
        g_rst     += s.rst_count;
        g_fin     += s.fin_count;
        g_retrans += s.retrans_count;
        g_ooo     += s.ooo_count;
        g_dupacks += s.dupack_count;
        g_zwin    += s.zwin_count;
        g_bytes_cli += s.bytes_cli;
        g_bytes_srv += s.bytes_srv;
    }

    char tot_cli[16], tot_srv[16];
    fmt_bytes(g_bytes_cli, tot_cli);
    fmt_bytes(g_bytes_srv, tot_srv);

    double mpps = elapsed_ms > 0 ? (total_pkts / 1e6) / (elapsed_ms / 1000.0) : 0;

    printf("\n");
    printf("%s╔══════════════════════════════════════════════════════════════════════════════╗\n", CLR_BOLD);
    printf("║  GLOBAL SUMMARY%s\n", CLR_RESET);
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  File            : %s\n", path);
    printf("║  Format          : %s\n", is_pcapng ? "PCAPng" : "PCAP");
    printf("║  File size       : ");
    { char fb2[16]; fmt_bytes((uint64_t)mf.size, fb2); printf("%s\n", fb2); }
    printf("║  Total packets   : %" PRIu64 "\n", total_pkts);
    printf("║  TCP packets     : %" PRIu64 "\n", tcp_pkts);
    printf("║  Non-TCP/skipped : %" PRIu64 "\n", skipped);
    printf("║  TCP sessions    : %zu\n", sessions.size());
    printf("║  Reported sess.  : %zu  (min-pkts >= %u%s)\n",
           report.size(), min_pkts,
           filter_ip ? ", IP filtered" : "");
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  %sSYN connections%s  : %-8" PRIu64 "  (SYN-ACK replies: %" PRIu64 ")\n",
           CLR_GREEN, CLR_RESET, g_syn, g_synack);
    printf("║  %sFIN teardowns%s   : %-8" PRIu64 "\n", CLR_YELLOW, CLR_RESET, g_fin);
    printf("║  %sRST resets%s      : %-8" PRIu64 "\n", CLR_RED,    CLR_RESET, g_rst);
    printf("║  %sRetransmissions%s : %-8" PRIu64 "\n", CLR_MAG,    CLR_RESET, g_retrans);
    printf("║  %sOut-of-order%s    : %-8" PRIu64 "\n", CLR_CYAN,   CLR_RESET, g_ooo);
    printf("║  %sDuplicate ACKs%s  : %-8" PRIu64 "\n", CLR_GRAY,   CLR_RESET, g_dupacks);
    printf("║  Zero-window    : %" PRIu64 "\n", g_zwin);
    printf("║  Total C→S data : %s\n", tot_cli);
    printf("║  Total S→C data : %s\n", tot_srv);
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Analysis time  : %.2f ms\n", elapsed_ms);
    printf("║  Throughput     : %.2f Mpps\n", mpps);
    printf("╚══════════════════════════════════════════════════════════════════════════════╝\n");

    return 0;
}
