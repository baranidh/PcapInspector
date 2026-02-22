# PcapInspector — High-performance PCAP/PCAPng TCP session analyzer
# -----------------------------------------------------------------------
# Build targets:
#   make          → release build (fastest, -O3 -march=native)
#   make debug    → debug build with sanitizers
#   make clean    → remove build artifacts
# -----------------------------------------------------------------------

CXX      := g++
TARGET   := pcap_inspector
SRC      := src/pcap_inspector.cpp
BUILD    := build

# Release flags
# -O3                  : maximum optimisation
# -march=native        : use all CPU features on the build machine (AVX2, etc.)
# -funroll-loops       : unroll hot inner loops
# -flto                : link-time optimisation
# -DNDEBUG             : disable asserts
# -fno-exceptions      : no C++ exceptions → slightly leaner binary
CXXFLAGS_RELEASE := -std=c++17 -O3 -march=native -funroll-loops -flto \
                    -Wall -Wextra -Wpedantic \
                    -DNDEBUG

# Debug flags (AddressSanitizer + UBSan)
CXXFLAGS_DEBUG := -std=c++17 -O0 -g3 \
                  -Wall -Wextra -Wpedantic \
                  -fsanitize=address,undefined \
                  -fno-omit-frame-pointer

LDFLAGS_RELEASE :=
LDFLAGS_DEBUG   := -fsanitize=address,undefined

.PHONY: all release debug clean install

all: release

release: $(SRC)
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS_RELEASE) -o $(BUILD)/$(TARGET) $(SRC) $(LDFLAGS_RELEASE)
	@echo ""
	@echo "  Built: $(BUILD)/$(TARGET)"
	@echo "  Usage: $(BUILD)/$(TARGET) <file.pcap|file.pcapng> [--help]"
	@echo ""

debug: $(SRC)
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS_DEBUG) -o $(BUILD)/$(TARGET)_dbg $(SRC) $(LDFLAGS_DEBUG)
	@echo "  Built: $(BUILD)/$(TARGET)_dbg  (with ASAN + UBSan)"

clean:
	rm -rf $(BUILD)

# Optional: install to /usr/local/bin
install: release
	install -m 755 $(BUILD)/$(TARGET) /usr/local/bin/$(TARGET)
	@echo "  Installed to /usr/local/bin/$(TARGET)"
