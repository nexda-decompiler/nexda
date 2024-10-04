#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

struct ELFHeader
{
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry; // For 64-bit ELF
    uint64_t e_phoff; // Program header table offset
    uint64_t e_shoff; // Section header table offset
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct PEHeader
{
    uint32_t signature;
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
    uint16_t magic; // Optional header magic number for PE32/PE32+
};

struct BinaryInfo
{
    std::string format;
    std::string arch;
    size_t byteAmount;
    std::string hexFormat;
    int bits;
    std::string abi;
    std::string entryPoint;
    std::string sectionCount;
    std::string timestamp;
    std::string fileSize;
};

BinaryInfo
analyzeBinary(const std::string &filename)
{
    BinaryInfo info = {};
    std::ifstream file(filename, std::ios::binary);

    if (!file)
    {
        std::cerr << "Error: Could not open file." << std::endl;
        return info;
    }

    file.seekg(0, std::ios::end);
    info.byteAmount = file.tellg();
    file.seekg(0);

    unsigned char buffer[16];
    file.read(reinterpret_cast<char *>(buffer), sizeof(buffer));

    if (buffer[0] == 0x7F && buffer[1] == 'E' && buffer[2] == 'L' &&
        buffer[3] == 'F')
    {
        info.format = "ELF";
        info.bits = (buffer[4] == 2) ? 64 : 32;
        info.arch = (info.bits == 64) ? "x86_64" : "x86";
        info.abi = "System V";

        ELFHeader elfHeader;
        file.seekg(0);
        file.read(reinterpret_cast<char *>(&elfHeader), sizeof(elfHeader));

        std::ostringstream hexStream;
        for (std::streamoff i = 0;
             i < 16 &&
             file.tellg() < static_cast<std::streamoff>(info.byteAmount);
             ++i)
        {
            unsigned char byte;
            file.read(reinterpret_cast<char *>(&byte), sizeof(byte));
            hexStream << std::hex << std::setw(2) << std::setfill('0')
                      << (int)byte << " ";
        }
        info.hexFormat = hexStream.str();
        info.entryPoint = "0x" + std::to_string(elfHeader.e_entry);
        info.sectionCount = std::to_string(elfHeader.e_shnum);
        info.timestamp = "N/A";
    }
    else if (buffer[0] == 'M' && buffer[1] == 'Z')
    {
        info.format = "PE";
        info.bits = (buffer[0x18] == 0x20) ? 64 : 32;
        info.arch = (info.bits == 64) ? "x86_64" : "x86";
        info.abi = "Windows";

        file.seekg(0x3C);
        uint32_t peOffset;
        file.read(reinterpret_cast<char *>(&peOffset), sizeof(peOffset));

        file.seekg(peOffset);
        PEHeader peHeader;
        file.read(reinterpret_cast<char *>(&peHeader), sizeof(peHeader));

        std::ostringstream hexStream;
        for (std::streamoff i = 0;
             i < 16 &&
             file.tellg() < static_cast<std::streamoff>(info.byteAmount);
             ++i)
        {
            unsigned char byte;
            file.read(reinterpret_cast<char *>(&byte), sizeof(byte));
            hexStream << std::hex << std::setw(2) << std::setfill('0')
                      << (int)byte << " ";
        }
        info.hexFormat = hexStream.str();
        info.entryPoint = "0x" + std::to_string(peHeader.pointerToSymbolTable);
        info.sectionCount = std::to_string(peHeader.numberOfSections);
        info.timestamp = std::to_string(peHeader.timeDateStamp);
    }
    else
    {
        info.format = "Other";
        info.arch = "Unknown";
        info.bits = 0;
        info.abi = "Unknown";
        info.entryPoint = "N/A";
        info.sectionCount = "N/A";
        info.timestamp = "N/A";
    }

    info.fileSize = std::to_string(info.byteAmount) + " bytes";

    return info;
}

void
printBinaryInfo(const BinaryInfo &info)
{
    std::cout << "============================\n";
    std::cout << "  Binary Analysis Results:  \n";
    std::cout << "============================\n";
    std::cout << std::left << std::setw(15) << "Format:" << info.format << "\n"
              << std::left << std::setw(15) << "Architecture:" << info.arch
              << "\n"
              << std::left << std::setw(15) << "Byte Amount:" << info.byteAmount
              << "\n"
              << std::left << std::setw(15) << "Hex Format:" << info.hexFormat
              << "\n"
              << std::left << std::setw(15) << "Bits:" << info.bits << "\n"
              << std::left << std::setw(15) << "ABI:" << info.abi << "\n"
              << std::left << std::setw(15) << "Entry Point:" << info.entryPoint
              << "\n"
              << std::left << std::setw(15)
              << "Section Count:" << info.sectionCount << "\n"
              << std::left << std::setw(15) << "Timestamp:" << info.timestamp
              << "\n"
              << std::left << std::setw(15) << "File Size:" << info.fileSize
              << std::endl;
}

int
main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <binary file>" << std::endl;
        return 1;
    }

    BinaryInfo info = analyzeBinary(argv[1]);
    printBinaryInfo(info);

    return 0;
}