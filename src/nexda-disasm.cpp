#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <limits>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <algorithm>

// Custom ELF structure definitions
#define EI_NIDENT 16
#define ET_EXEC 2
#define EM_X86_64 62
#define EV_CURRENT 1
#define PT_LOAD 1
#define SHT_PROGBITS 1
#define SHF_EXECINSTR 0x4

struct Elf64_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

class Disassembler {
private:
    std::vector<uint8_t> buffer;
    Elf64_Ehdr elfHeader;
    std::vector<Elf64_Shdr> sectionHeaders;
    std::vector<Elf64_Phdr> programHeaders;
    std::map<std::string, Elf64_Shdr> sectionMap;
    uint64_t entryPoint;
    uint64_t baseAddress;

    struct Instruction {
        std::string mnemonic;
        std::vector<std::string> operands;
        uint64_t address;
        std::vector<uint8_t> bytes;
    };

    std::map<uint8_t, std::string> oneByteOpcodes = {
        {0x50, "push"}, {0x58, "pop"},
        {0x89, "mov"}, {0x8B, "mov"},
        {0x01, "add"}, {0x29, "sub"},
        {0xE8, "call"}, {0xC3, "ret"},
        {0x74, "je"}, {0x75, "jne"},
        {0x7C, "jl"}, {0x7D, "jge"},
        // Add more opcodes as needed
    };

    std::map<uint16_t, std::string> twoByteOpcodes = {
        {0x0F84, "je"}, {0x0F85, "jne"},
        {0x0F8C, "jl"}, {0x0F8D, "jge"},
        // Add more two-byte opcodes as needed
    };

    bool readElfFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            std::cerr << "Error: Could not open file " << filename << std::endl;
            return false;
        }

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        buffer.resize(fileSize);
        file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

        if (file.gcount() != fileSize) {
            std::cerr << "Error: Could not read entire file" << std::endl;
            return false;
        }

        memcpy(&elfHeader, buffer.data(), sizeof(Elf64_Ehdr));

        if (memcmp(elfHeader.e_ident, "\x7F\x45\x4C\x46", 4) != 0) {
            std::cerr << "Error: Not a valid ELF file" << std::endl;
            return false;
        }

        entryPoint = elfHeader.e_entry;

        // Read program headers
        programHeaders.resize(elfHeader.e_phnum);
        memcpy(programHeaders.data(), buffer.data() + elfHeader.e_phoff, elfHeader.e_phnum * sizeof(Elf64_Phdr));

        // Find the base address (lowest p_vaddr of LOAD segments)
        baseAddress = std::numeric_limits<uint64_t>::max();
        for (const auto& phdr : programHeaders) {
            if (phdr.p_type == PT_LOAD) {
                baseAddress = std::min(baseAddress, phdr.p_vaddr);
            }
        }

        // Read section headers
        sectionHeaders.resize(elfHeader.e_shnum);
        memcpy(sectionHeaders.data(), buffer.data() + elfHeader.e_shoff, elfHeader.e_shnum * sizeof(Elf64_Shdr));

        // Read section names
        Elf64_Shdr& shstrtab = sectionHeaders[elfHeader.e_shstrndx];
        for (const auto& shdr : sectionHeaders) {
            std::string name(reinterpret_cast<char*>(buffer.data() + shstrtab.sh_offset + shdr.sh_name));
            sectionMap[name] = shdr;
        }

        return true;
    }

    std::string getRegisterName(uint8_t reg, bool is64bit = true) {
        static const char* regs64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
        static const char* regs32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
        return is64bit ? regs64[reg & 0xF] : regs32[reg & 0xF];
    }

    Instruction decodeInstruction(const uint8_t* code, size_t& offset) {
        Instruction instr;
        instr.address = offset;

        uint8_t opcode = code[offset++];
        instr.bytes.push_back(opcode);

        if (oneByteOpcodes.find(opcode) != oneByteOpcodes.end()) {
            instr.mnemonic = oneByteOpcodes[opcode];

            if (opcode >= 0x50 && opcode <= 0x57) { // push reg
                instr.operands.push_back("%" + getRegisterName(opcode - 0x50));
            } else if (opcode >= 0x58 && opcode <= 0x5F) { // pop reg
                instr.operands.push_back("%" + getRegisterName(opcode - 0x58));
            } else if (opcode == 0xE8) { // call
                int32_t relAddr = *reinterpret_cast<const int32_t*>(&code[offset]);
                offset += 4;
                instr.operands.push_back("0x" + std::to_string(offset + relAddr));
                instr.bytes.insert(instr.bytes.end(), code + offset - 4, code + offset);
            } else if (opcode >= 0x74 && opcode <= 0x7F) { // conditional jumps (short)
                int8_t relAddr = code[offset++];
                instr.operands.push_back("0x" + std::to_string(offset + relAddr));
                instr.bytes.push_back(relAddr);
            } else {
                // Handle other one-byte instructions
                instr.operands.push_back("(not implemented)");
            }
        } else if (opcode == 0x0F) { // Two-byte opcode
            uint8_t secondByte = code[offset++];
            instr.bytes.push_back(secondByte);
            uint16_t fullOpcode = (opcode << 8) | secondByte;

            if (twoByteOpcodes.find(fullOpcode) != twoByteOpcodes.end()) {
                instr.mnemonic = twoByteOpcodes[fullOpcode];

                if (fullOpcode >= 0x0F80 && fullOpcode <= 0x0F8F) { // conditional jumps (near)
                    int32_t relAddr = *reinterpret_cast<const int32_t*>(&code[offset]);
                    offset += 4;
                    instr.operands.push_back("0x" + std::to_string(offset + relAddr));
                    instr.bytes.insert(instr.bytes.end(), code + offset - 4, code + offset);
                } else {
                    // Handle other two-byte instructions
                    instr.operands.push_back("(not implemented)");
                }
            } else {
                instr.mnemonic = "unknown";
                instr.operands.push_back("(unknown two-byte opcode)");
            }
        } else {
            instr.mnemonic = "unknown";
            instr.operands.push_back("(unknown opcode)");
        }

        return instr;
    }

    bool disassembleSection(const std::string& sectionName, std::ostream& output) {
        if (sectionMap.find(sectionName) == sectionMap.end()) {
            std::cerr << "Error: Section " << sectionName << " not found" << std::endl;
            return false;
        }

        const Elf64_Shdr& section = sectionMap[sectionName];
        const uint8_t* sectionData = buffer.data() + section.sh_offset;
        size_t sectionSize = section.sh_size;

        output << "Disassembly of section " << sectionName << ":" << std::endl;

        size_t offset = 0;
        while (offset < sectionSize) {
            Instruction instr = decodeInstruction(sectionData, offset);

            output << std::hex << std::setw(16) << std::setfill('0') << (section.sh_addr + instr.address) << ":";

            // Print instruction bytes
            for (size_t i = 0; i < instr.bytes.size(); ++i) {
                output << " " << std::setw(2) << std::setfill('0') << static_cast<int>(instr.bytes[i]);
            }
            output << std::string(5 * (8 - instr.bytes.size()), ' '); // Padding

            output << instr.mnemonic;
            if (!instr.operands.empty()) {
                output << "\t" << instr.operands[0];
                for (size_t i = 1; i < instr.operands.size(); ++i) {
                    output << ", " << instr.operands[i];
                }
            }
            output << std::endl;
        }

        return true;
    }

public:
    bool disassemble(const std::string& inputFile, const std::string& outputFile) {
        if (!readElfFile(inputFile)) {
            return false;
        }

        std::ofstream output(outputFile);
        if (!output) {
            std::cerr << "Error: Could not open output file " << outputFile << std::endl;
            return false;
        }

        output << "Disassembly of " << inputFile << std::endl << std::endl;

        output << "Entry point: 0x" << std::hex << entryPoint << std::endl;
        output << "Base address: 0x" << std::hex << baseAddress << std::endl << std::endl;

        // Disassemble .text section
        if (!disassembleSection(".text", output)) {
            return false;
        }

        // You can add more sections to disassemble here, e.g., .plt, .init, etc.

        std::cout << "Disassembly completed successfully." << std::endl;
        return true;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4 || strcmp(argv[2], "-o") != 0) {
        std::cerr << "Usage: " << argv[0] << " <input_file> -o <output_file>" << std::endl;
        return 1;
    }

    std::string inputFile = argv[1];
    std::string outputFile = argv[3];

    Disassembler disassembler;
    if (disassembler.disassemble(inputFile, outputFile)) {
        return 0;
    } else {
        std::cerr << "Disassembly failed." << std::endl;
        return 1;
    }
}