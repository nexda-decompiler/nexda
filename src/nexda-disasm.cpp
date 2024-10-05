#include <capstone/capstone.h>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <gelf.h>
#include <iostream>
#include <libelf.h>
#include <unistd.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

enum FileType
{
    UNKNOWN,
    ELF_FILE,
    PE_FILE
};

FileType
detect_file_type(int fd)
{
    unsigned char magic[4];
    if (read(fd, magic, 4) != 4)
    {
        return UNKNOWN;
    }

    if (memcmp(magic,
               "\x7F"
               "ELF",
               4) == 0)
    {
        return ELF_FILE;
    }
    else if (memcmp(magic, "MZ", 2) == 0)
    {
        return PE_FILE;
    }

    return UNKNOWN;
}

// PE header structures
struct DOSHeader
{
    uint16_t e_magic; // MZ signature
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew; // Offset to PE header
};

struct PEHeader
{
    uint32_t signature; // PE\0\0
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
};

struct SectionHeader
{
    char name[8];
    uint32_t virtualSize;
    uint32_t virtualAddress;
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
    uint32_t pointerToRelocations;
    uint32_t pointerToLinenumbers;
    uint16_t numberOfRelocations;
    uint16_t numberOfLinenumbers;
    uint32_t characteristics;
};

void
disassemble_pe(int fd, const std::string &outputFile, bool pure)
{
    lseek(fd, 0, SEEK_SET);

    DOSHeader dosHeader;
    if (read(fd, &dosHeader, sizeof(DOSHeader)) != sizeof(DOSHeader))
    {
        std::cerr << "Error: Cannot read DOS header" << std::endl;
        return;
    }

    if (dosHeader.e_magic != 0x5A4D)
    { // 'MZ'
        std::cerr << "Error: Invalid PE file (MZ signature missing)"
                  << std::endl;
        return;
    }

    lseek(fd, dosHeader.e_lfanew, SEEK_SET); // Jump to PE header

    PEHeader peHeader;
    if (read(fd, &peHeader, sizeof(PEHeader)) != sizeof(PEHeader))
    {
        std::cerr << "Error: Cannot read PE header" << std::endl;
        return;
    }

    if (peHeader.signature != 0x00004550)
    { // 'PE\0\0'
        std::cerr << "Error: Invalid PE signature" << std::endl;
        return;
    }

    SectionHeader sectionHeader;
    bool textSectionFound = false;
    uint32_t textSectionOffset = 0, textSectionSize = 0, textSectionVA = 0;

    for (int i = 0; i < peHeader.numberOfSections; i++)
    {
        if (read(fd, &sectionHeader, sizeof(SectionHeader)) !=
            sizeof(SectionHeader))
        {
            std::cerr << "Error: Cannot read section header" << std::endl;
            return;
        }

        if (strncmp(sectionHeader.name, ".text", 8) == 0)
        {
            textSectionOffset = sectionHeader.pointerToRawData;
            textSectionSize = sectionHeader.sizeOfRawData;
            textSectionVA = sectionHeader.virtualAddress;
            textSectionFound = true;
            break;
        }
    }

    if (!textSectionFound)
    {
        std::cerr << "Error: .text section not found in PE file" << std::endl;
        return;
    }

    // Read the .text section
    uint8_t *textSectionData = new uint8_t[textSectionSize];
    lseek(fd, textSectionOffset, SEEK_SET);
    if (read(fd, textSectionData, textSectionSize) != textSectionSize)
    {
        std::cerr << "Error: Cannot read .text section" << std::endl;
        delete[] textSectionData;
        return;
    }

    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
        std::cerr << "Error: Capstone initialization failed" << std::endl;
        delete[] textSectionData;
        return;
    }

    std::ofstream outFile(outputFile);
    if (!outFile.is_open())
    {
        std::cerr << "Error: Cannot open output file" << outputFile
                  << std::endl;
        cs_close(&handle);
        delete[] textSectionData;
        return;
    }

    count = cs_disasm(handle, textSectionData, textSectionSize, textSectionVA,
                      0, &insn);
    if (count > 0)
    {
        for (size_t j = 0; j < count; j++)
        {
            if (pure)
            {
                outFile << insn[j].mnemonic << " " << insn[j].op_str
                        << std::endl;
            }
            else
            {
                outFile << std::hex << insn[j].address << ": "
                        << insn[j].mnemonic << " " << insn[j].op_str
                        << std::endl;
            }
        }
        cs_free(insn, count);
    }
    else
    {
        std::cerr << "Error: Disassembly failed" << std::endl;
    }

    outFile.close();
    cs_close(&handle);
    delete[] textSectionData;
}

void
disassemble_elf(int fd, const std::string& outputFile, bool pure) {
    Elf* elf;
    Elf_Scn* scn = NULL;
    GElf_Shdr shdr;
    Elf_Data* data;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        std::cerr << "Error: ELF library initialization failed: " << elf_errmsg(-1) << std::endl;
        return;
    }

    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
        std::cerr << "Error: elf_begin() failed: " << elf_errmsg(-1) << std::endl;
        return;
    }

    size_t shstrndx;
    if (elf_getshstrndx(elf, &shstrndx) != 0) {
        std::cerr << "Error: elf_getshstrndx() failed: " << elf_errmsg(-1) << std::endl;
        elf_end(elf);
        return;
    }

    bool textSectionFound = false;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);
        const char* section_name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (section_name == NULL) {
            std::cerr << "Error: elf_strptr() failed: " << elf_errmsg(-1) << std::endl;
            elf_end(elf);
            return;
        }
        if (strcmp(section_name, ".text") == 0) {
            textSectionFound = true;
            break;
        }
    }

    if (!textSectionFound) {
        std::cerr << "Error: .text section not found" << std::endl;
        elf_end(elf);
        return;
    }

    if ((data = elf_getdata(scn, NULL)) == NULL) {
        std::cerr << "Error: elf_getdata() failed: " << elf_errmsg(-1) << std::endl;
        elf_end(elf);
        return;
    }

    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "Error: Capstone initialization failed" << std::endl;
        elf_end(elf);
        return;
    }

    std::ofstream outFile(outputFile);
    if (!outFile.is_open()) {
        std::cerr << "Error: Cannot open output file " << outputFile << std::endl;
        cs_close(&handle);
        elf_end(elf);
        return;
    }

    count = cs_disasm(handle, (const uint8_t*)data->d_buf, data->d_size, shdr.sh_addr, 0, &insn);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            if (pure) {
                outFile << insn[j].mnemonic << " " << insn[j].op_str << std::endl;
            } else {
                outFile << std::hex << insn[j].address << ": " << insn[j].mnemonic << " " << insn[j].op_str << std::endl;
            }
        }
        cs_free(insn, count);
    } else {
        std::cerr << "Error: Disassembly failed" << std::endl;
    }

    outFile.close();
    cs_close(&handle);
    elf_end(elf);
}

void
disassemble(const std::string &inputFile, const std::string &outputFile,
            bool pure)
{
    int fd;
    if ((fd = open(inputFile.c_str(), O_RDONLY, 0)) < 0)
    {
        std::cerr << "Error: Cannot open file " << inputFile << std::endl;
        return;
    }

    FileType fileType = detect_file_type(fd);
    switch (fileType)
    {
    case PE_FILE:
        disassemble_pe(fd, outputFile, pure);
        break;
    case ELF_FILE:
        disassemble_elf(fd, outputFile, pure);
        break;
    default:
        std::cerr << "Error: Unknown file type" << std::endl;
        break;
    }

    close(fd);
}

int
main(int argc, char *argv[])
{
    if (argc < 4 || std::string(argv[2]) != "-o")
    {
        std::cerr << "Usage: " << argv[0]
                  << " <input_file> -o <output_file> [-pure]" << std::endl;
        return 1;
    }

    std::string inputFile = argv[1];
    std::string outputFile = argv[3];
    bool pure = (argc == 5 && std::string(argv[4]) == "-pure");

    disassemble(inputFile, outputFile, pure);

    return 0;
}