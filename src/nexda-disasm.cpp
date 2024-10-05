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

    // Opcode maps
    std::map<uint8_t, std::string> oneByteOpcodes = {
    {0x50, "push"}, {0x51, "push"}, {0x52, "push"}, {0x53, "push"},
    {0x54, "push"}, {0x55, "push"}, {0x56, "push"}, {0x57, "push"},
    {0x58, "pop"}, {0x59, "pop"}, {0x5A, "pop"}, {0x5B, "pop"},
    {0x5C, "pop"}, {0x5D, "pop"}, {0x5E, "pop"}, {0x5F, "pop"},
    {0x89, "mov"}, {0x8B, "mov"},
    {0x01, "add"}, {0x29, "sub"},
    {0x31, "xor"}, {0x39, "cmp"},
    {0x40, "inc"}, {0x48, "dec"},
    {0xE8, "call"}, {0xC3, "ret"},
    {0xEB, "jmp"}, {0xE9, "jmp"},
    {0x74, "je"}, {0x75, "jne"},
    {0x7C, "jl"}, {0x7D, "jge"},
    {0x6A, "push"}, {0x68, "push"}, {0xFF, "jmp/call"},
    {0xB8, "mov"}, {0xB9, "mov"}, {0xBA, "mov"}, {0xBB, "mov"},
    {0xBC, "mov"}, {0xBD, "mov"}, {0xBE, "mov"}, {0xBF, "mov"},
    {0x88, "mov"}, {0x80, "add/sub/cmp"}, {0x90, "nop"},
    {0xF7, "mul/div"}, {0xF8, "clc"}, {0xFC, "cld"}, {0xFD, "std"},
    {0x9C, "pushf"}, {0x9D, "popf"}
};

    std::map<uint16_t, std::string> twoByteOpcodes = {
    {0x0F84, "je"}, {0x0F85, "jne"},
    {0x0F8C, "jl"}, {0x0F8D, "jge"},
    {0x0F1F, "nop"}, {0x0FAF, "imul"},
    {0x0FB6, "movzx"}, {0x0FB7, "movzx"},
    {0x0FBE, "movsx"}, {0x0FBF, "movsx"},
    {0x0FC1, "xadd"}, {0x0F80, "jo"},
    {0x0F81, "jno"}, {0x0F82, "jb"}, {0x0F83, "jae"},
    {0x0FC7, "cmpxchg8b"}, {0x0F01F8, "swapgs"}
};

    struct ModRM {
        uint8_t mod;
        uint8_t reg;
        uint8_t rm;
    };

    struct SIB {
        uint8_t scale;
        uint8_t index;
        uint8_t base;
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
        static const char* regs64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                       "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
        static const char* regs32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                                       "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
        static const char* regs16[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
                                       "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
        static const char* regs8[]  = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
                                       "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};

        reg &= 0xF; // Ensure reg is within 0-15

        if (is64bit)
            return regs64[reg];
        else
            return regs32[reg];
    }

    ModRM parseModRM(uint8_t byte) {
        ModRM modrm;
        modrm.mod = (byte >> 6) & 0x3;
        modrm.reg = (byte >> 3) & 0x7;
        modrm.rm  = byte & 0x7;
        return modrm;
    }

    SIB parseSIB(uint8_t byte) {
        SIB sib;
        sib.scale = (byte >> 6) & 0x3;
        sib.index = (byte >> 3) & 0x7;
        sib.base  = byte & 0x7;
        return sib;
    }

    std::string formatMemoryOperand(ModRM modrm, const uint8_t* code, size_t& offset, size_t codeSize, bool is64bit, bool rex_b, bool rex_x) {
        std::string operand;
        uint8_t rm = modrm.rm | (rex_b ? 0x8 : 0x0);

        if (modrm.mod == 0b00) {
            if (rm == 0b100) { // SIB
                if (offset >= codeSize) return "(incomplete)";
                uint8_t sibByte = code[offset++];
                SIB sib = parseSIB(sibByte);

                uint8_t base = sib.base | (rex_b ? 0x8 : 0x0);
                uint8_t index = sib.index | (rex_x ? 0x8 : 0x0);
                int scale = 1 << sib.scale;

                operand = "(";
                if (index != 0b100) { // Not none
                    operand += getRegisterName(index, is64bit) + "*" + std::to_string(scale);
                }
                if (base != 0b101) {
                    if (index != 0b100) operand += "+";
                    operand += getRegisterName(base, is64bit);
                } else {
                    if (offset + 4 > codeSize) return "(incomplete)";
                    int32_t disp32 = *reinterpret_cast<const int32_t*>(&code[offset]);
                    offset += 4;
                    operand += std::to_string(disp32);
                }
                operand += ")";
            } else if (rm == 0b101) { // RIP-relative
                if (offset + 4 > codeSize) return "(incomplete)";
                int32_t disp32 = *reinterpret_cast<const int32_t*>(&code[offset]);
                offset += 4;
                uint64_t addr = offset + disp32;
                operand = std::to_string(addr);
            } else {
                operand = "(" + getRegisterName(rm, is64bit) + ")";
            }
        } else if (modrm.mod == 0b01) {
            int8_t disp8 = code[offset++];
            if (rm == 0b100) { // SIB
                if (offset >= codeSize) return "(incomplete)";
                uint8_t sibByte = code[offset++];
                SIB sib = parseSIB(sibByte);
                // Handle SIB with displacement
                // Skipping detailed implementation for brevity
                operand = "(sib+disp8)";
            } else {
                operand = std::to_string(disp8) + "(" + getRegisterName(rm, is64bit) + ")";
            }
        } else if (modrm.mod == 0b10) {
            if (offset + 4 > codeSize) return "(incomplete)";
            int32_t disp32 = *reinterpret_cast<const int32_t*>(&code[offset]);
            offset += 4;
            if (rm == 0b100) { // SIB
                if (offset >= codeSize) return "(incomplete)";
                uint8_t sibByte = code[offset++];
                SIB sib = parseSIB(sibByte);
                // Handle SIB with displacement
                // Skipping detailed implementation for brevity
                operand = "(sib+disp32)";
            } else {
                operand = std::to_string(disp32) + "(" + getRegisterName(rm, is64bit) + ")";
            }
        } else {
            operand = getRegisterName(rm, is64bit);
        }

        return operand;
    }

    Instruction decodeInstruction(const uint8_t* code, size_t codeSize, size_t& offset) {
        Instruction instr;
        instr.address = offset;

        size_t startOffset = offset;
        bool is64bit = true; // Assuming 64-bit mode

        // Parse prefixes
        uint8_t rex = 0;
        while (offset < codeSize) {
            uint8_t byte = code[offset];
            if ((byte & 0xF0) == 0x40) { // REX prefix
                rex = byte;
                instr.bytes.push_back(byte);
                offset++;
            } else {
                break;
            }
        }

        bool rex_w = rex & 0x08;
        bool rex_r = rex & 0x04;
        bool rex_x = rex & 0x02;
        bool rex_b = rex & 0x01;

        if (offset >= codeSize) {
            instr.mnemonic = "db";
            instr.operands.push_back("0x" + byteToHex(code[offset - 1]));
            return instr;
        }

        uint8_t opcode = code[offset++];
        instr.bytes.push_back(opcode);

        uint16_t fullOpcode = opcode;
        if (opcode == 0x0F && offset < codeSize) { // Two-byte opcode
            uint8_t secondByte = code[offset++];
            instr.bytes.push_back(secondByte);
            fullOpcode = (opcode << 8) | secondByte;
        }

        // Lookup mnemonic
        if (fullOpcode > 0xFF) {
            if (twoByteOpcodes.find(fullOpcode) != twoByteOpcodes.end()) {
                instr.mnemonic = twoByteOpcodes[fullOpcode];
            } else {
                instr.mnemonic = "unknown";
                instr.operands.push_back("(unknown two-byte opcode)");
                return instr;
            }
        } else {
            if (oneByteOpcodes.find(opcode) != oneByteOpcodes.end()) {
                instr.mnemonic = oneByteOpcodes[opcode];
            } else {
                instr.mnemonic = "unknown";
                instr.operands.push_back("(unknown opcode)");
                return instr;
            }
        }

        // Handle operands
        if (instr.mnemonic == "mov" || instr.mnemonic == "add" || instr.mnemonic == "sub" || instr.mnemonic == "xor" || instr.mnemonic == "test") {
            if (offset >= codeSize) {
                instr.operands.push_back("(incomplete instruction)");
                return instr;
            }
            uint8_t modrmByte = code[offset++];
            instr.bytes.push_back(modrmByte);
            ModRM modrm = parseModRM(modrmByte);

            uint8_t regField = (modrm.reg | (rex_r ? 0x8 : 0x0));
            uint8_t rmField = (modrm.rm | (rex_b ? 0x8 : 0x0));

            std::string regName = getRegisterName(regField, is64bit);
            std::string operand2;

            if (modrm.mod != 0b11) {
                // Memory operand
                operand2 = formatMemoryOperand(modrm, code, offset, codeSize, is64bit, rex_b, rex_x);
            } else {
                operand2 = getRegisterName(rmField, is64bit);
            }

            if (opcode == 0x89 || opcode == 0x29 || opcode == 0x31) {
                // Instructions where destination is operand2
                instr.operands.push_back(operand2);
                instr.operands.push_back(regName);
            } else {
                instr.operands.push_back(regName);
                instr.operands.push_back(operand2);
            }
        } else if (instr.mnemonic == "call") {
            if (opcode == 0xE8) {
                int32_t relAddr = *reinterpret_cast<const int32_t*>(&code[offset]);
                offset += 4;
                instr.bytes.insert(instr.bytes.end(), code + offset - 4, code + offset);
                uint64_t targetAddr = instr.address + offset - startOffset + relAddr;
                instr.operands.push_back("0x" + uint64ToHex(targetAddr));
            } else if (opcode == 0xFF) {
                // Indirect call/jmp
                uint8_t modrmByte = code[offset++];
                instr.bytes.push_back(modrmByte);
                ModRM modrm = parseModRM(modrmByte);
                uint8_t rmField = (modrm.rm | (rex_b ? 0x8 : 0x0));
                std::string operand = formatMemoryOperand(modrm, code, offset, codeSize, is64bit, rex_b, rex_x);
                instr.operands.push_back(operand);
            }
        } else if (instr.mnemonic == "jmp") {
            if (opcode == 0xE9) {
                int32_t relAddr = *reinterpret_cast<const int32_t*>(&code[offset]);
                offset += 4;
                instr.bytes.insert(instr.bytes.end(), code + offset - 4, code + offset);
                uint64_t targetAddr = instr.address + offset - startOffset + relAddr;
                instr.operands.push_back("0x" + uint64ToHex(targetAddr));
            } else if (opcode == 0xEB) {
                int8_t relAddr = code[offset++];
                instr.bytes.push_back(relAddr);
                uint64_t targetAddr = instr.address + offset - startOffset + relAddr;
                instr.operands.push_back("0x" + uint64ToHex(targetAddr));
            }
        } else if (instr.mnemonic == "je" || instr.mnemonic == "jne" || instr.mnemonic == "jl" || instr.mnemonic == "jge") {
            if (opcode == 0x0F) {
                int32_t relAddr = *reinterpret_cast<const int32_t*>(&code[offset]);
                offset += 4;
                instr.bytes.insert(instr.bytes.end(), code + offset - 4, code + offset);
                uint64_t targetAddr = instr.address + offset - startOffset + relAddr;
                instr.operands.push_back("0x" + uint64ToHex(targetAddr));
            } else {
                int8_t relAddr = code[offset++];
                instr.bytes.push_back(relAddr);
                uint64_t targetAddr = instr.address + offset - startOffset + relAddr;
                instr.operands.push_back("0x" + uint64ToHex(targetAddr));
            }
        } else if (instr.mnemonic == "push" || instr.mnemonic == "pop") {
            uint8_t reg = opcode - (instr.mnemonic == "push" ? 0x50 : 0x58);
            reg |= (rex_b ? 0x8 : 0x0);
            std::string regName = getRegisterName(reg, is64bit);
            instr.operands.push_back(regName);
        } else if (instr.mnemonic == "ret") {
            // No operands
        } else {
            instr.operands.push_back("(not implemented)");
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

        size_t offset = 0;
        while (offset < sectionSize) {
            Instruction instr = decodeInstruction(sectionData, sectionSize, offset);

            output << std::hex << std::setw(16) << std::setfill('0') << (section.sh_addr + instr.address) << ":";

            // Print instruction bytes
            for (size_t i = 0; i < instr.bytes.size(); ++i) {
                output << " " << std::setw(2) << std::setfill('0') << static_cast<int>(instr.bytes[i]);
            }
            output << std::string(5 * (8 - instr.bytes.size()), ' '); // Padding

            output << "\t" << instr.mnemonic;
            if (!instr.operands.empty()) {
                output << " " << instr.operands[0];
                for (size_t i = 1; i < instr.operands.size(); ++i) {
                    output << ", " << instr.operands[i];
                }
            }
            output << std::endl;
        }

        return true;
    }

    std::string byteToHex(uint8_t byte) {
        std::ostringstream oss;
        oss << std::hex << static_cast<int>(byte);
        return oss.str();
    }

    std::string uint64ToHex(uint64_t value) {
        std::ostringstream oss;
        oss << std::hex << value;
        return oss.str();
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