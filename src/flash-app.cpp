// flash_app.cpp
// Reimplementation of flash-app.js in C++ (Linux, SocketCAN)
// Compile: see CMakeLists.txt below
//
// Notes:
// - Requires Linux SocketCAN headers (linux/can.h, linux/can/raw.h) and a CAN interface configured (e.g. can0).
// - This implements a basic Intel HEX parser/writer and an in-memory map of blocks.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <signal.h>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <tqdm.h>
#include <vector>

using namespace std::chrono;

static const uint8_t BOOTLOADER_CMD_VERSION = 0x01;

// byte positions
static const int CAN_DATA_BYTE_MCU_ID_MSB   = 0;
static const int CAN_DATA_BYTE_MCU_ID_LSB   = 1;
static const int CAN_DATA_BYTE_CMD          = 2;
static const int CAN_DATA_BYTE_LEN_AND_ADDR = 3;

// default CAN IDs (integers)
static const uint32_t CAN_ID_MCU_TO_REMOTE_DEFAULT = 0x1FFFFF01;
static const uint32_t CAN_ID_REMOTE_TO_MCU_DEFAULT = 0x1FFFFF02;
static const int CAN_PING_INTERVAL_DEFAULT_MS = 75;

// commands
enum {
    CMD_PING                     = 0b00000000,
    CMD_BOOTLOADER_START         = 0b00000010,
    CMD_FLASH_INIT               = 0b00000110,
    CMD_FLASH_READY              = 0b00000100,
    CMD_FLASH_SET_ADDRESS        = 0b00001010,
    CMD_FLASH_ADDRESS_ERROR      = 0b00001011,
    CMD_FLASH_DATA               = 0b00001000,
    CMD_FLASH_DATA_ERROR         = 0b00001101,
    CMD_FLASH_DONE               = 0b00010000,
    CMD_FLASH_DONE_VERIFY        = 0b01010000,
    CMD_FLASH_ERASE              = 0b00100000,
    CMD_FLASH_READ               = 0b01000000,
    CMD_FLASH_READ_DATA          = 0b01001000,
    CMD_FLASH_READ_ADDRESS_ERROR = 0b01001011,
    CMD_START_APP                = 0b10000000
};

enum struct State {
    STATE_INIT,
    STATE_FLASHING,
    STATE_READING
};

struct Options {
    std::string file;
    std::string iface = "can0";
    std::string partno;
    uint32_t mcuid = 0;
    bool doErase = false;
    bool doVerify = true;
    bool doRead = false;
    uint32_t readMax = 0;
    bool force = false;
    std::string resetMsg;
    uint32_t canIdMcu = CAN_ID_MCU_TO_REMOTE_DEFAULT;
    uint32_t canIdRemote = CAN_ID_REMOTE_TO_MCU_DEFAULT;
    bool sff = false;
    int pingMs = 0;
    bool verbose = false;
};

// Simple memory map: address -> contiguous bytes
using MemoryMap = std::map<uint32_t, std::vector<uint8_t>>;

static volatile bool g_terminate = false;
static void sigint_handler(int) { g_terminate = true; }

static std::string hex_u8(uint8_t v) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << (int)v;
    return ss.str();
}

class IntelHex {
public:
    enum struct RecordType {
        DATA = 0x00,
        END_OF_FILE = 0x01,
        EXT_SEG_ADDR = 0x02,
        EXT_LIN_ADDR = 0x04
    };

    static MemoryMap parseFile(const std::string& filename) {
        constexpr size_t MIN_RECORD_LINE_CHARS = 11u;// 11 = 1  + 2   + 4    + 2       ... + 2
                                                     //     ':' + len + addr + rectype ... + checksum
        std::istream* in;
        std::ifstream fin;
        if (filename == "-") {
            in = &std::cin;
        } else {
            fin.open(filename, std::ios::in);
            if ( ! fin) {
                throw std::runtime_error("Cannot open input HEX file");
            }
            in = &fin;
        }

        MemoryMap map;
        std::string line;
        uint32_t upperAddr = 0;
        std::vector<uint8_t> data;// used to parse record data
        data.reserve(256u);
        while (std::getline(*in, line)) {
            if (line.length() < MIN_RECORD_LINE_CHARS) {
                continue;
            }
            if (line[0] != ':') {
                throw std::runtime_error("Invalid HEX record (no ':')");
            }
            // parse
            auto hexbyte = [](char c)->int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                return -1;
            };
            auto parse8 = [&](int idx)->uint8_t {
                int hi = hexbyte(line[idx]);
                int lo = hexbyte(line[idx+1]);
                if (hi < 0 || lo < 0) throw std::runtime_error("Invalid hex digit");
                return (uint8_t)((hi<<4) | lo);
            };
            const uint8_t len = parse8(1);
            const uint16_t addr = (parse8(3) << 8) | parse8(5);
            const auto rectype = static_cast<RecordType>(parse8(7));
            if (line.length() < (MIN_RECORD_LINE_CHARS + len)) {
                throw std::runtime_error(
                    "Invalid HEX record (not enough data char for record"
                    " len " + std::to_string(len) + ")");
            }
            data.resize(len);
            for (uint8_t i=0;i<len;i++) {
                data[i] = parse8(9 + i*2);
            }
            // checksum skip check for brevity (could be validated)
            switch (rectype) {
                case RecordType::DATA: {
                    const uint32_t fullAddr = upperAddr + addr;
                    map[fullAddr] = data; // append data to block starting at fullAddr. For simplicity, place as a block keyed by fullAddr.
                    break;
                }
                case RecordType::END_OF_FILE:
                    break;
                case RecordType::EXT_SEG_ADDR: {
                    if (data.size() < 2) throw std::runtime_error("Invalid ext segment addr");
                    upperAddr = ((uint32_t)data[0] << 8 | data[1]) << 4;
                    break;
                }
                case RecordType::EXT_LIN_ADDR: {
                    if (data.size() < 2) throw std::runtime_error("Invalid ext linear addr");
                    upperAddr = ((uint32_t)data[0] << 8 | data[1]) << 16;
                    break;
                }
                default:
                    // ignore other types
                    break;
            }
        }
        return map;
    }

    static void writeFile(const std::string& filename, const MemoryMap& map) {
        std::ostream* out;
        std::ofstream fout;
        if (filename == "-") {
            out = &std::cout;
        } else {
            fout.open(filename, std::ios::out | std::ios::trunc);
            if ( ! fout) {
                throw std::runtime_error("Cannot open output file");
            }
            out = &fout;
        }
        // Very simple: emit linear extended address records for each block base
        uint32_t lastUpper = UINT32_MAX;
        for (auto const& kv : map) {
            uint32_t addr = kv.first;
            const auto& data = kv.second;
            uint32_t upper = (addr >> 16) & 0xFFFF;
            if (upper != lastUpper) {
                // write extended linear address
                writeRecord(*out, RecordType::EXT_LIN_ADDR, 0x0000, { (uint8_t)(upper >> 8), (uint8_t)(upper & 0xFF) });
                lastUpper = upper;
            }
            uint16_t recAddr = addr & 0xFFFF;
            // write data in chunks up to 16 bytes
            size_t idx = 0;
            while (idx < data.size()) {
                const size_t chunkSize = std::min<size_t>(16u, data.size() - idx);
                std::vector<uint8_t> chunk(data.begin() + idx, data.begin() + idx + chunkSize);
                writeRecord(*out, RecordType::DATA, recAddr + idx, chunk);
                idx += chunkSize;
            }
        }
        writeRecord(*out, RecordType::END_OF_FILE, 0x0000, {});
    }

private:
    static void writeRecord(std::ostream& out, RecordType recType, uint16_t addr, const std::vector<uint8_t>& data) {
        const auto len = static_cast<uint8_t>(data.size());
        uint8_t csum = 0;
        csum += len;
        csum += (addr >> 8) & 0xFF;
        csum += addr & 0xFF;
        csum += static_cast<uint8_t>(recType);
        for (uint8_t d : data) csum += d;
        csum = (~csum) + 1;
        std::ostringstream line;
        line << ":" << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)len;
        line << std::setw(4) << static_cast<unsigned int>(addr);
        line << std::setw(2) << static_cast<unsigned int>(recType);
        for (uint8_t d : data) line << std::setw(2) << static_cast<unsigned int>(d);
        line << std::setw(2) << static_cast<unsigned int>(csum);
        out << line.str() << std::endl;
    }
};

// minimal simple helper: flatten memory map to contiguous stream ordered by ascending address
static uint64_t totalBytesInMemMap(const MemoryMap& mem) {
    uint64_t s = 0;
    for (auto &kv : mem) s += kv.second.size();
    return s;
}

class FlashApp {
public:
    explicit
    FlashApp(const Options& optsIn)
        : opt_(optsIn)
    {
        // mcu id bytes
        mcuIdBytes_[0] = (uint8_t)((opt_.mcuid >> 8) & 0xFF);
        mcuIdBytes_[1] = (uint8_t)(opt_.mcuid & 0xFF);
        deviceFlashSize_ = 0;
        loadDeviceInfo(opt_.partno);
        if ( ! opt_.doRead) {
            // read hex file
            memMap_ = IntelHex::parseFile(opt_.file);
            progressTotalBytes_ = totalBytesInMemMap(memMap_);
            remainingBytes_ = progressTotalBytes_;
            opt_.readMax = progressTotalBytes_;
        }
        memMapIter_ = memMap_.begin();
        memMapCurrentIdx_ = 0;

        curAddr_ = 0x0000;

        openCan(opt_.iface);

        if ( ! opt_.resetMsg.empty()) {
            sendReset(opt_.resetMsg);
            if (opt_.verbose) std::cerr << "Reset message sent\n";
        }

        if (opt_.pingMs > 0) {
            lastPing_ = steady_clock::now();
        }

        if (opt_.verbose) {
            std::cerr << "Waiting for bootloader start message for MCU ID 0x" 
                                << std::hex << std::uppercase << opt_.mcuid << std::dec << " ...\n";
        } else {
            std::cout << "Waiting for bootloader start message for MCU ID " 
                                << "0x" << std::hex << std::uppercase << opt_.mcuid << std::dec << " ...\n";
        }
    }

    ~FlashApp() {
        cleanup();
    }

    // abide by rule of 5: prevent copying, but permit move semantics
    FlashApp(const FlashApp & other) = delete;
    FlashApp(FlashApp && other) noexcept = default;
    FlashApp & operator=(const FlashApp & other) = delete;
    FlashApp & operator=(FlashApp && other) noexcept = default;

    void run() {
        fd_set readfds;
        while ( ! g_terminate) {
            FD_ZERO(&readfds);
            FD_SET(canSock_, &readfds);

            int nfds = canSock_ + 1;
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000; // 100ms poll

            int rv = select(nfds, &readfds, nullptr, nullptr, &tv);
            if (rv < 0) {
                if (errno == EINTR) continue;
                perror("select");
                break;
            }

            if (rv > 0 && FD_ISSET(canSock_, &readfds)) {
                struct can_frame frame;
                int n = read(canSock_, &frame, sizeof(frame));
                if (n < 0) {
                    if (errno == EINTR) continue;
                    perror("read");
                    break;
                }
                handleCanFrame(frame);
            }

            // check ping
            if (opt_.pingMs > 0 && duration_cast<milliseconds>(steady_clock::now() - lastPing_).count() >= opt_.pingMs) {
                sendPing();
                lastPing_ = steady_clock::now();
            }
        }
    }

private:
    Options opt_;
    int canSock_ = -1;
    State state_ = State::STATE_INIT;
    std::array<uint8_t, 2> mcuIdBytes_ = {0u, 0u};
    MemoryMap memMap_;
    MemoryMap::iterator memMapIter_;
    size_t memMapCurrentIdx_ = 0u;   // byte idx within current block
    size_t progressBytes_ = 0u;      // bytes we've processed relative to total
    size_t progressTotalBytes_ = 0u; // total bytes in hex file
    uint32_t curAddr_ = 0u;
    std::vector<uint8_t> readData_;
    size_t remainingBytes_ = 0u; // bytes remaining in read operation
    std::array<uint8_t, 3> deviceSignature_;
    size_t deviceFlashSize_ = 0u;
    steady_clock::time_point flashStartTs_;
    steady_clock::time_point lastPing_;
    tqdm tqdmBar_;

    void openCan(const std::string& iface) {
        canSock_ = socket(PF_CAN, SOCK_RAW, CAN_RAW);
        if (canSock_ < 0) throw std::runtime_error("socket(PF_CAN) failed");

        struct ifreq ifr;
        std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
        if (ioctl(canSock_, SIOCGIFINDEX, &ifr) < 0) {
            close(canSock_);
            throw std::runtime_error("SIOCGIFINDEX failed for " + iface);
        }
        struct sockaddr_can addr{};
        addr.can_family = AF_CAN;
        addr.can_ifindex = ifr.ifr_ifindex;
        if (bind(canSock_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(canSock_);
            throw std::runtime_error("bind failed for CAN socket");
        }
        // non-blocking
        int flags = fcntl(canSock_, F_GETFL, 0);
        fcntl(canSock_, F_SETFL, flags | O_NONBLOCK);
    }

    void sendFrame(uint32_t id, const std::vector<uint8_t>& data, bool ext) {
        struct can_frame frame{};
        frame.can_dlc = data.size();
        memcpy(frame.data, data.data(), frame.can_dlc);
        if (ext) {
            frame.can_id = id | CAN_EFF_FLAG;
        } else {
            frame.can_id = id & CAN_SFF_MASK;
        }
        int n = write(canSock_, &frame, sizeof(frame));
        if (n != sizeof(frame)) {
            if (errno != EWOULDBLOCK && errno != EAGAIN) {
                perror("write CAN");
            }
        }
    }

    void sendPing() {
        std::vector<uint8_t> data(8, 0);
        data[0] = mcuIdBytes_[0];
        data[1] = mcuIdBytes_[1];
        data[2] = CMD_PING;
        sendFrame(opt_.canIdRemote, data, !opt_.sff);
        if (opt_.verbose) std::cerr << "Sent ping\n";
    }

    void sendReset(const std::string& resetSpec) {
        // format: <can_id>#{hex_data}
        auto pos = resetSpec.find('#');
        std::string idStr = (pos == std::string::npos) ? resetSpec : resetSpec.substr(0,pos);
        std::string dataStr = (pos == std::string::npos) ? "" : resetSpec.substr(pos+1);
        uint32_t id = 0;
        std::stringstream ss; ss << std::hex << idStr;
        ss >> id;
        std::vector<uint8_t> data;
        for (size_t i=0;i < dataStr.size(); i += 2) {
            std::string s = dataStr.substr(i,2);
            uint8_t b = (uint8_t)std::stoi(s, nullptr, 16);
            data.push_back(b);
        }
        sendFrame(id, data, (idStr.length() > 3));
    }

    void handleCanFrame(const struct can_frame& frame) {
        if (frame.can_dlc != 8) return;
        uint32_t fid = frame.can_id & (frame.can_id & CAN_EFF_FLAG ? CAN_EFF_MASK : CAN_SFF_MASK);
        // ignore messages not for us
        if ((frame.can_id & CAN_EFF_FLAG) && !opt_.sff) {
            fid = frame.can_id & CAN_EFF_MASK;
        } else {
            fid = frame.can_id & CAN_SFF_MASK;
        }
        if (fid != opt_.canIdMcu) return;

        const uint8_t* data = frame.data;
        const uint16_t mcuid = (data[CAN_DATA_BYTE_MCU_ID_MSB] << 8) | data[CAN_DATA_BYTE_MCU_ID_LSB];
        if (mcuid != opt_.mcuid) return;

        const uint8_t cmd = data[CAN_DATA_BYTE_CMD];

        switch (state_) {
            case State::STATE_INIT:
                handleStateInit(data, cmd);
                break;
            case State::STATE_FLASHING:
                handleStateFlashing(data, cmd);
                break;
            case State::STATE_READING:
                handleStateReading(data, cmd);
                break;
        }
    }

    void handleStateInit(const uint8_t* data, const uint8_t cmd) {
        if (cmd == CMD_BOOTLOADER_START) {
            // check signature
            if (data[4] != deviceSignature_[0] || data[5] != deviceSignature_[1] || data[6] != deviceSignature_[2]) {
                std::cerr << "Error: Got bootloader start message but device signature mismatched!\n";
                std::cerr << "Expected: " << hex_u8(deviceSignature_[0]) << " " << hex_u8(deviceSignature_[1]) << " " << hex_u8(deviceSignature_[2])
                                    << " got: " << hex_u8(data[4]) << " " << hex_u8(data[5]) << " " << hex_u8(data[6]) << "\n";
                return;
            }
            // check bootloader version
            if (data[7] != BOOTLOADER_CMD_VERSION) {
                if (opt_.force) {
                    std::cerr << "WARNING: Bootloader version mismatch, forced.\n";
                } else {
                    std::cerr << "ERROR: Bootloader version mismatch (MCU " << (int)data[7] << " vs app " << (int)BOOTLOADER_CMD_VERSION << "). Use -F to force.\n";
                    return;
                }
            }
            std::cout << "Got bootloader start, entering flash mode ...\n";
            flashStartTs_ = steady_clock::now();
            // send FLASH_INIT
            std::vector<uint8_t> data = { mcuIdBytes_[0], mcuIdBytes_[1], (uint8_t)CMD_FLASH_INIT, 0x00,
                                                                        deviceSignature_[0], deviceSignature_[1], deviceSignature_[2], 0x00 };
            sendFrame(opt_.canIdRemote, data, !opt_.sff);
        } else if (cmd == CMD_FLASH_READY) {
            if (opt_.doRead) {
                std::cout << "Querying bootloader size ...\n";
                // set address to 0xFFFFFFFF to provoke address error -> get FLASHEND_BL
                sendSetFlashAddress(0xFFFFFFFF);
            } else if (opt_.doErase) {
                std::cout << "Got flash ready message, erasing flash ...\n";
                std::vector<uint8_t> data = {mcuIdBytes_[0], mcuIdBytes_[1], (uint8_t)CMD_FLASH_ERASE, 0,0,0,0,0};
                sendFrame(opt_.canIdRemote, data, !opt_.sff);
                opt_.doErase = false;
            } else {
                std::cout << "Got flash ready message, begin flashing ...\n";
                state_ = State::STATE_FLASHING;
                onFlashReady(data);
            }
        } else if (cmd == CMD_FLASH_ADDRESS_ERROR) {
            if (opt_.doRead) {
                uint32_t flashendBL = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
                uint32_t progSize = flashendBL + 1;
                uint32_t blSize = (deviceFlashSize_) - progSize;
                std::cout << "Bootloader size: " << blSize << " bytes\n";
                progressTotalBytes_ = opt_.readMax;
                if (opt_.readMax > progSize) {
                    std::cerr << "WARNING: read size of " << opt_.readMax <<
                        " exceeds program memory size " << progSize << ". Using program size instead.\n";
                    progressTotalBytes_ = progSize;
                }
                remainingBytes_ = progressTotalBytes_;
                readData_.reserve(progressBytes_);
                std::cout << "Reading " << progressTotalBytes_ << " bytes\n";
                state_ = State::STATE_READING;
                // request read at addr 0
                sendRead(curAddr_);
            } else {
                std::cerr << "WARNING: unexpected CMD_FLASH_ADDRESS_ERROR in STATE_INIT\n";
            }
        } else {
            if (opt_.verbose) std::cerr << "WARNING: unexpected cmd in STATE_INIT: " << (int)cmd << "\n";
        }
    }

    void handleStateFlashing(const uint8_t* data, const uint8_t cmd) {
        if (cmd == CMD_FLASH_DATA_ERROR) {
            std::cerr << "Flash data error!\n";
        } else if (cmd == CMD_FLASH_ADDRESS_ERROR) {
            std::cerr << "Flash address error!\n";
        } else if (cmd == CMD_FLASH_READY) {
            uint8_t byteCount = (data[CAN_DATA_BYTE_LEN_AND_ADDR] >> 5);
            progressUpdate();
            curAddr_ += byteCount;
            memMapCurrentIdx_ += byteCount;
            onFlashReady(data);
        } else if (cmd == CMD_START_APP) {
            auto elapsed = duration_cast<milliseconds>(steady_clock::now() - flashStartTs_).count();
            std::cout << "Flash done in " << elapsed << " ms. MCU starting app.\n";
            exitClean(0);
        } else {
            if (opt_.verbose) std::cerr << "WARNING: unexpected in STATE_FLASHING cmd=" << (int)cmd << "\n";
        }
    }

    void handleStateReading(const uint8_t* data, const uint8_t cmd) {
        if (cmd == CMD_FLASH_DONE_VERIFY) {
            std::cout << "Start reading flash to verify ...\n";
            // prepare for verify: reset iterators
            memMapIter_ = memMap_.begin();
            memMapCurrentIdx_ = 0;
            curAddr_ = memMapIter_ != memMap_.end() ? memMapIter_->first : 0;
            // request read
            sendRead(curAddr_);
        } else if (cmd == CMD_FLASH_READ_DATA) {
            uint8_t byteCount = (data[CAN_DATA_BYTE_LEN_AND_ADDR] >> 5);
            if (byteCount > remainingBytes_) {
                // bootloader can return more bytes than we needed in the
                // last block, so truncate to remainingBytes_
                byteCount = static_cast<uint8_t>(remainingBytes_);
            }
            const uint8_t addrPart = data[CAN_DATA_BYTE_LEN_AND_ADDR] & 0b00011111;
            if (((curAddr_) & 0b00011111) != addrPart) {
                std::cerr << "Unexpected address of read data from MCU!\n";
                sendStartApp();
                return;
            }
            if (opt_.verbose) {
                std::cerr << "Got flash data for"
                    " 0x" << std::hex << curAddr_ << std::dec <<
                    " (" << static_cast<unsigned int>(byteCount) << " bytes; " <<
                    progressBytes_ << "/" << progressTotalBytes_ << "; " <<
                    remainingBytes_ << " remaining)\n";
            }
            progressBytes_ += byteCount;
            remainingBytes_ -= byteCount;
            progressUpdate();
            if (opt_.doVerify) {
                for (uint32_t i=0;i<byteCount;i++) {
                    uint8_t expected = 0xFF;
                    if (memMapIter_ != memMap_.end()) {
                        const auto &vec = memMapIter_->second;
                        if (memMapCurrentIdx_ < vec.size()) {
                            expected = vec[memMapCurrentIdx_];
                        }
                    }
                    if (expected != data[4+i]) {
                        std::cerr << "ERROR: Verify failed at 0x" << std::hex << curAddr_ << std::dec << "\n";
                        sendStartApp();
                        return;
                    }
                    curAddr_++;
                    memMapCurrentIdx_++;
                    // advance map iterator if needed
                    if (memMapIter_ != memMap_.end() && memMapCurrentIdx_ >= memMapIter_->second.size()) {
                        memMapIter_++;
                        memMapCurrentIdx_ = 0;
                        if (memMapIter_ != memMap_.end()) {
                            curAddr_ = memMapIter_->first;
                        }
                    }
                }
                if (remainingBytes_ == 0) {
                    progressStop();
                    std::cout << "Flash and verify done.\n";
                    sendStartApp();
                    return;
                }
                // request next read
                sendRead(curAddr_);
            } else {
                // collecting read
                for (uint8_t i=0;i<byteCount;i++) {
                    readData_.push_back(data[4+i]);
                    curAddr_++;
                }
                if (remainingBytes_ == 0) {
                    readDone();
                    return;
                }
                sendRead(curAddr_);
            }
        } else if (cmd == CMD_FLASH_READ_ADDRESS_ERROR) {
            if (opt_.doVerify) {
                std::cerr << "ERROR: Reading flash failed during verify!\n";
                sendStartApp();
                return;
            } else {
                readDone();
            }
        } else if (cmd == CMD_START_APP) {
            std::cout << "MCU is starting the app.\n";
            exitClean(0);
        } else {
            if (opt_.verbose) std::cerr << "WARNING: unexpected in STATE_READING cmd=" << (int)cmd << "\n";
        }
    }

    void onFlashReady(const uint8_t* data) {
        uint32_t curAddrRemote = data[7] + (data[6] << 8) + (data[5] << 16) + (data[4] << 24);
        if (memMapIter_ == memMap_.end() || memMapIter_->second.empty() || memMapCurrentIdx_ >= memMapIter_->second.size()) {
            // move to next key
            memMapIter_ = next(memMapIter_);
            if (memMapIter_ == memMap_.end()) {
                progressUpdate();
                progressStop();
                std::cout << "All data transmitted. Finalizing ...\n";
                if (opt_.doVerify) {
                    progressBytes_ = 0u;
                    remainingBytes_ = progressTotalBytes_;
                    state_ = State::STATE_READING;
                    std::vector<uint8_t> data = { mcuIdBytes_[0], mcuIdBytes_[1], (uint8_t)CMD_FLASH_DONE_VERIFY, 0,0,0,0,0 };
                    sendFrame(opt_.canIdRemote, data, !opt_.sff);
                } else {
                    std::vector<uint8_t> data = { mcuIdBytes_[0], mcuIdBytes_[1], (uint8_t)CMD_FLASH_DONE, 0,0,0,0,0 };
                    sendFrame(opt_.canIdRemote, data, !opt_.sff);
                }
                return;
            }
            // set up first block
            memMapCurrentIdx_ = 0u;
            curAddr_ = memMapIter_->first;
            progressUpdate();
        }

        if (curAddr_ != curAddrRemote) {
            std::cout << "Setting flash address to 0x" << std::hex << curAddr_ << std::dec << " ...\n";
            sendSetFlashAddress(curAddr_);
            return;
        }

        // prepare data with up to 4 bytes
        std::vector<uint8_t> outData(8,0);
        outData[0] = mcuIdBytes_[0];
        outData[1] = mcuIdBytes_[1];
        outData[2] = CMD_FLASH_DATA;
        int dataBytes = 0;
        auto &vec = memMapIter_->second;
        for (int i=0;i<4;i++) {
            if (memMapCurrentIdx_ + i >= vec.size()) break;
            outData[4+i] = vec[memMapCurrentIdx_ + i];
            dataBytes++;
        }
        progressBytes_ += dataBytes;
        remainingBytes_ -= dataBytes;
        outData[3] = (dataBytes << 5) | (curAddr_ & 0b00011111);
        if (opt_.verbose) {
            std::cerr << "Sending flash data for 0x" << std::hex << curAddr_ << std::dec <<
            " (" << dataBytes << " bytes; " <<
            progressBytes_ << "/" << progressTotalBytes_ << "; " <<
            remainingBytes_ << " remaining)\n";
        }
        sendFrame(opt_.canIdRemote, outData, !opt_.sff);
    }

    void sendSetFlashAddress(const uint32_t addr) {
        std::vector<uint8_t> data = { mcuIdBytes_[0], mcuIdBytes_[1], (uint8_t)CMD_FLASH_SET_ADDRESS, 0,
                                                                    (uint8_t)((addr >> 24) & 0xFF),
                                                                    (uint8_t)((addr >> 16) & 0xFF),
                                                                    (uint8_t)((addr >> 8) & 0xFF),
                                                                    (uint8_t)(addr & 0xFF) };
        sendFrame(opt_.canIdRemote, data, !opt_.sff);
    }

    void sendRead(const uint32_t addr) {
        std::vector<uint8_t> data = { mcuIdBytes_[0], mcuIdBytes_[1], (uint8_t)CMD_FLASH_READ, 0,
                                                                    (uint8_t)((addr >> 24) & 0xFF),
                                                                    (uint8_t)((addr >> 16) & 0xFF),
                                                                    (uint8_t)((addr >> 8) & 0xFF),
                                                                    (uint8_t)(addr & 0xFF) };
        sendFrame(opt_.canIdRemote, data, !opt_.sff);
    }

    void sendStartApp() {
        std::cout << "Starting the app on the MCU ...\n";
        std::vector<uint8_t> data(8,0);
        data[0] = mcuIdBytes_[0];
        data[1] = mcuIdBytes_[1];
        data[2] = CMD_START_APP;
        sendFrame(opt_.canIdRemote, data, !opt_.sff);
    }

    void readDone() {
        progressStop();
        // create memmap with readData at 0x0000
        MemoryMap out;
        out[0x0000] = readData_;
        IntelHex::writeFile(opt_.file, out);
        std::cout << "Hex file written to " << opt_.file << "\n";
        auto elapsed = duration_cast<milliseconds>(steady_clock::now() - flashStartTs_).count();
        std::cout << "Reading flash done in " << elapsed << " ms.\n";
        sendStartApp();
    }

    void progressUpdate() {
        if ( ! opt_.verbose) {
            tqdmBar_.progress(progressBytes_, progressTotalBytes_);
        }
    }

    void progressStop() {
        if ( ! opt_.verbose) {
            tqdmBar_.finish();
            tqdmBar_.reset();
        }
    }

    void loadDeviceInfo(const std::string& partno) {
        std::string p = partno;
        std::transform(p.begin(), p.end(), p.begin(), ::tolower);
        if (p == "m32" || p=="mega32" || p=="atmega32") {
            deviceSignature_[0]=0x1E; deviceSignature_[1]=0x95; deviceSignature_[2]=0x02; deviceFlashSize_ = 32*1024;
        } else if (p=="m328p" || p=="atmega328p" || p=="mega328p") {
            deviceSignature_[0]=0x1E; deviceSignature_[1]=0x95; deviceSignature_[2]=0x0F; deviceFlashSize_ = 32*1024;
        } else if (p=="m1284p" || p=="atmega1284p") {
            deviceSignature_[0]=0x1E; deviceSignature_[1]=0x97; deviceSignature_[2]=0x05; deviceFlashSize_ = 128*1024;
        } else if (p=="m2560" || p=="mega2560" || p=="atmega2560") {
            deviceSignature_[0]=0x1E; deviceSignature_[1]=0x98; deviceSignature_[2]=0x01; deviceFlashSize_ = 256*1024;
        } else {
            deviceSignature_[0]=0; deviceSignature_[1]=0; deviceSignature_[2]=0; deviceFlashSize_ = 0;
        }
    }

    void cleanup() {
        if (canSock_ >= 0) {
            close(canSock_);
            canSock_ = -1;
        }
    }

    void exitClean(int code) {
        cleanup();
        exit(code);
    }
};

// Show usage information
static void showUsage(const char* progName) {
    std::cout << "Usage: " << progName << " -f <hexfile> -p <partno> -m <mcuid> [options]\n";
    std::cout << "Options:\n";
    std::cout << "  -f, --file <file>     Hex file to flash (or '-' for stdin/stdout)\n";
    std::cout << "  -i, --iface <iface>   CAN interface (default: can0)\n";
    std::cout << "  -p, --partno <partno> AVR device part number (e.g., m1284p)\n";
    std::cout << "  -m, --mcuid <id>      MCU bootloader ID (hex or decimal)\n";
    std::cout << "  -e                    Erase flash before flashing\n";
    std::cout << "  -V                    Do not verify after flashing\n";
    std::cout << "  -r <maxaddr>          Read flash up to max address and save to file\n";
    std::cout << "  -F                    Force flashing even on version mismatch\n";
    std::cout << "  --reset <id#data>     Send CAN reset message at startup\n";
    std::cout << "  --can-id-mcu <id>     CAN-ID from MCU to remote (default: 0x1FFFFF01)\n";
    std::cout << "  --can-id-remote <id>  CAN-ID from remote to MCU (default: 0x1FFFFF02)\n";
    std::cout << "  --sff                 Use Standard Frame Format (SFF)\n";
    std::cout << "  --ping <ms>           Send ping interval in ms (default 75)\n";
    std::cout << "  -v, --verbose         Enable verbose logging\n";
    std::cout << "  -h, --help            Show this help menu\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << progName << " -f firmware.hex -p m1284p -m 0x0042\n";
    std::cout << "  " << progName << " -f firmware.hex -p m1284p -m 0x0042 --reset 020040FF#4201FA\n";
    std::cout << "  " << progName << " -r 0x2000 -f dump.hex -p m328p -m 0x0042\n";
}

int main(int argc, char** argv) {
    signal(SIGINT, sigint_handler);
    Options opt;
    const char* shortopts = "f:i:p:m:er:VFRvh";
    static struct option longopts[] = {
        {"file"         , required_argument, 0, 'f' },
        {"iface"        , required_argument, 0, 'i' },
        {"partno"       , required_argument, 0, 'p' },
        {"mcuid"        , required_argument, 0, 'm' },
        {"e"            , no_argument      , 0, 'e' },
        {"V"            , no_argument      , 0, 'V' },
        {"r"            , required_argument, 0, 'r' },
        {"F"            , no_argument      , 0, 'F' },
        {"reset"        , required_argument, 0, 1000},
        {"can-id-mcu"   , required_argument, 0, 1001},
        {"can-id-remote", required_argument, 0, 1002},
        {"sff"          , no_argument      , 0, 1003},
        {"ping"         , required_argument, 0, 1004},
        {"verbose"      , no_argument      , 0, 'v' },
        {"help"         , no_argument      , 0, 'h' },
        {0,0,0,0}
    };

    if (argc == 1) {
        showUsage(argv[0]);
        return 1;
    }

    int c = '\0';
    int optidx = 0;
    constexpr int AUTO_BASE = 0u;
    while ((c = getopt_long(argc, argv, shortopts, longopts, &optidx)) != -1) {
        switch (c) {
            case 'f':  opt.file = optarg; break;
            case 'i':  opt.iface = optarg; break;
            case 'p':  opt.partno = optarg; break;
            case 'm':  opt.mcuid = std::stoul(optarg, 0u, AUTO_BASE); break;
            case 'e':  opt.doErase = true; break;
            case 'V':  opt.doVerify = false; break;
            case 'r':  opt.doRead = true; opt.readMax = std::stoul(optarg, 0u, AUTO_BASE); break;
            case 'F':  opt.force = true; break;
            case 'R':  /* alias handled by longopt */ break;
            case 'v':  opt.verbose = true; break;
            case 1000: opt.resetMsg = optarg; break;
            case 1001: opt.canIdMcu = std::stoul(optarg, 0u, AUTO_BASE); break;
            case 1002: opt.canIdRemote = std::stoul(optarg, 0u, AUTO_BASE); break;
            case 1003: opt.sff = true; break;
            case 1004: opt.pingMs = atoi(optarg); break;
            case 'h':  showUsage(argv[0]); return 0;
            case '?':
            default:
                std::cerr << "Unknown option\n";
                return 1;
        }
    }

    // required args
    if (opt.file.empty()) { std::cerr << "Missing -f/--file\n"; return 1; }
    if (opt.partno.empty()) { std::cerr << "Missing -p/--partno\n"; return 1; }
    if (opt.mcuid == 0) { std::cerr << "Missing -m/--mcuid (e.g. 0x0042)\n"; return 1; }

    // if read only, disable verify
    if (opt.doRead) opt.doVerify = false;

    try {
        FlashApp app(opt);
        app.run();
    } catch (const std::exception& ex) {
        std::cerr << "FATAL: " << ex.what() << "\n";
        return 2;
    }
    return 0;
}
