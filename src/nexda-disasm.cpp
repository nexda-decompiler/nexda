#include <iostream>
#include <fstream>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

void disassemble(const std::string& inputFile, const std::string& outputFile) {
    int fd;
    Elf* elf;
    Elf_Scn* scn = NULL;
    GElf_Shdr shdr;
    Elf_Data* data;
    char* section_name;

    // Initialize ELF version
    if (elf_version(EV_CURRENT) == EV_NONE) {
        std::cerr << "Error: ELF library initialization failed: " << elf_errmsg(-1) << std::endl;
        return;
    }

    // Open the input file
    if ((fd = open(inputFile.c_str(), O_RDONLY, 0)) < 0) {
        std::cerr << "Error: Cannot open file " << inputFile << std::endl;
        return;
    }

    // Initialize ELF object
    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
        std::cerr << "Error: elf_begin() failed: " << elf_errmsg(-1) << std::endl;
        close(fd);
        return;
    }

    // Get section string table index from the ELF header
    size_t shstrndx;
    if (elf_getshstrndx(elf, &shstrndx) != 0) {
        std::cerr << "Error: elf_getshstrndx() failed: " << elf_errmsg(-1) << std::endl;
        elf_end(elf);
        close(fd);
        return;
    }

    // Find .text section
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);
        if ((section_name = elf_strptr(elf, shstrndx, shdr.sh_name)) == NULL) {
            std::cerr << "Error: elf_strptr() failed: " << elf_errmsg(-1) << std::endl;
            elf_end(elf);
            close(fd);
            return;
        }
        if (strcmp(section_name, ".text") == 0) {
            break;
        }
    }

    if (scn == NULL) {
        std::cerr << "Error: .text section not found" << std::endl;
        elf_end(elf);
        close(fd);
        return;
    }

    // Get section data
    if ((data = elf_getdata(scn, NULL)) == NULL) {
        std::cerr << "Error: elf_getdata() failed: " << elf_errmsg(-1) << std::endl;
        elf_end(elf);
        close(fd);
        return;
    }

    // Initialize Capstone
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "Error: Capstone initialization failed" << std::endl;
        elf_end(elf);
        close(fd);
        return;
    }

    // Open output file
    std::ofstream outFile(outputFile);
    if (!outFile.is_open()) {
        std::cerr << "Error: Cannot open output file " << outputFile << std::endl;
        cs_close(&handle);
        elf_end(elf);
        close(fd);
        return;
    }

    // Disassemble
    count = cs_disasm(handle, (const uint8_t*)data->d_buf, data->d_size, shdr.sh_addr, 0, &insn);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            outFile << std::hex << insn[j].address << ": "
                    << insn[j].mnemonic << " "
                    << insn[j].op_str << std::endl;
        }
        cs_free(insn, count);
    } else {
        std::cerr << "Error: Disassembly failed" << std::endl;
    }

    // Clean up
    outFile.close();
    cs_close(&handle);
    elf_end(elf);
    close(fd);
}

int main(int argc, char* argv[]) {
    if (argc != 4 || std::string(argv[2]) != "-o") {
        std::cerr << "Usage: " << argv[0] << " <input_file> -o <output_file>" << std::endl;
        return 1;
    }

    std::string inputFile = argv[1];
    std::string outputFile = argv[3];

    disassemble(inputFile, outputFile);

    return 0;
}