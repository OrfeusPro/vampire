#include <intrin.h>
#include <stdint.h>

// No game linkage, process inspection, registry access or network.
extern "C" __declspec(dllexport) int vampir_read_cpu(
    char* vendor, uint32_t vendor_capacity, char* brand, uint32_t brand_capacity) {
    if (!vendor || !brand || vendor_capacity < 13 || brand_capacity < 49) return 0;
    int registers[4];
    __cpuid(registers, 0);
    const uint32_t vendor_words[3] = {
        static_cast<uint32_t>(registers[1]), static_cast<uint32_t>(registers[3]),
        static_cast<uint32_t>(registers[2])};
    for (unsigned word = 0; word < 3; ++word)
        for (unsigned byte = 0; byte < 4; ++byte)
            vendor[word * 4 + byte] = static_cast<char>(vendor_words[word] >> (byte * 8));
    vendor[12] = 0;
    for (unsigned index = 0; index < 49; ++index) brand[index] = 0;
    __cpuid(registers, static_cast<int>(0x80000000u));
    if (static_cast<uint32_t>(registers[0]) >= 0x80000004u) {
        for (unsigned part = 0; part < 3; ++part) {
            __cpuid(registers, static_cast<int>(0x80000002u + part));
            for (unsigned word = 0; word < 4; ++word)
                for (unsigned byte = 0; byte < 4; ++byte)
                    brand[part * 16 + word * 4 + byte] =
                        static_cast<char>(static_cast<uint32_t>(registers[word]) >> (byte * 8));
        }
    }
    return 1;
}
