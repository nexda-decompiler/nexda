#include <capstone/capstone.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>
#endif

Decompiler(const char *inputFile, const char *outputFile)
{
    std::ifstream file(inputFile, std::ios::binary);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file: " << inputFile << std::endl;
        return;
    }

    // Read the first 4 bytes to identify the file type
    uint32_t magic;
    file.read(reinterpret_cast<char *>(&magic), sizeof(magic));

    if (magic == 0x464C457F) // ELF magic number (0x7F 'E' 'L' 'F')
    {
#ifdef _WIN32
        std::cerr << "PE parsing is only supported on Windows systems" << std::endl;
        return;
#else
        analyzeELFFile(inputFile);
#endif
    }
    else if (magic == 0x5A4D) // PE magic number ('M' 'Z')
    {
#ifdef _WIN32
        analyzePEFile(inputFile);
#else
        std::cerr << "PE parsing is only supported on Windows systems" << std::endl;
        return;
#endif
    }
    else
    {
        std::cerr << "Unsupported file format" << std::endl;
        return;
    }

    file.close();

    // Initialize Capstone
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        std::cerr << "Failed to initialize Capstone" << std::endl;
        return;
    }

    outFile.open(outputFile);
    if (!outFile.is_open())
    {
        std::cerr << "Failed to open output file: " << outputFile << std::endl;
        cs_close(&handle);
        return;
    }
}

    ~Decompiler()
    {
#ifdef _WIN32
        if (peFile.is_open())
            peFile.close();
#else
        if (elf)
            elf_end(elf);
        if (fd >= 0)
            close(fd);
#endif
        cs_close(&handle);
        if (outFile.is_open())
            outFile.close();
    }

    void decompile()
    {
#ifdef _WIN32
        analyzePE();
#else
        analyzeELF();
#endif
        generateCCode();
    }

  private:
#ifdef _WIN32
    void analyzePE()
    {
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS ntHeaders;
        peFile.read(reinterpret_cast<char *>(&dosHeader), sizeof(dosHeader));

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        {
            std::cerr << "Not a valid PE file" << std::endl;
            return;
        }

        peFile.seekg(dosHeader.e_lfanew, std::ios::beg);
        peFile.read(reinterpret_cast<char *>(&ntHeaders), sizeof(ntHeaders));

        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        {
            std::cerr << "Invalid NT header" << std::endl;
            return;
        }

        analyzePEFunctions(ntHeaders);
    }

    void analyzePEFunctions(const IMAGE_NT_HEADERS &ntHeaders)
    {
        IMAGE_SECTION_HEADER sectionHeader;
        for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i)
        {
            peFile.read(reinterpret_cast<char *>(&sectionHeader), sizeof(sectionHeader));
            if (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                uint64_t address = ntHeaders.OptionalHeader.ImageBase + sectionHeader.VirtualAddress;
                functions[address] = "func_" + std::to_string(i);
            }
        }
    }
#else
    void analyzeELF()
    {
        Elf_Scn *scn = nullptr;
        GElf_Shdr shdr;
        size_t shstrndx;

        if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        {
            std::cerr << "Failed to get section header string index" << std::endl;
            return;
        }

        while ((scn = elf_nextscn(elf, scn)) != nullptr)
        {
            if (gelf_getshdr(scn, &shdr) != &shdr)
            {
                std::cerr << "Failed to get section header" << std::endl;
                continue;
            }

            const char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
            if (name == nullptr)
            {
                std::cerr << "Failed to get section name" << std::endl;
                continue;
            }

            if (shdr.sh_type == SHT_SYMTAB)
            {
                analyzeSymbolTable(scn, &shdr);
            }
        }
    }

    void analyzeSymbolTable(Elf_Scn *scn, GElf_Shdr *shdr)
    {
        Elf_Data *data = elf_getdata(scn, nullptr);
        int count = shdr->sh_size / shdr->sh_entsize;

        for (int i = 0; i < count; ++i)
        {
            GElf_Sym sym;
            if (gelf_getsym(data, i, &sym) == &sym)
            {
                if (GELF_ST_TYPE(sym.st_info) == STT_FUNC)
                {
                    char *name = elf_strptr(elf, shdr->sh_link, sym.st_name);
                    if (name)
                    {
                        functions[sym.st_value] = name;
                    }
                }
            }
        }
    }
#endif

    void generateCCode()
    {
        outFile << "#include <stdio.h>\n\n";
        for (const auto &func : functions)
        {
            outFile << "void " << func.second << "() {\n";
            disassembleFunction(func.first);
            outFile << "}\n\n";
        }
        outFile << "int main() {\n";
        outFile << "    return 0;\n";
        outFile << "}\n";
    }

    void disassembleFunction(uint64_t address)
    {
#ifdef _WIN32
        IMAGE_SECTION_HEADER sectionHeader;
        // Assume a single code section for simplicity
        peFile.seekg(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS), std::ios::beg);
        peFile.read(reinterpret_cast<char *>(&sectionHeader), sizeof(sectionHeader));

        uint64_t sectionStart = sectionHeader.VirtualAddress;
        uint64_t sectionEnd = sectionHeader.VirtualAddress + sectionHeader.SizeOfRawData;
        if (address >= sectionStart && address < sectionEnd)
        {
            disassembleSection(sectionStart, sectionEnd);
        }
#else
        Elf_Scn *scn = nullptr;
        GElf_Shdr shdr;
        while ((scn = elf_nextscn(elf, scn)) != nullptr)
        {
            if (gelf_getshdr(scn, &shdr) != &shdr)
            {
                continue;
            }
            if (shdr.sh_type == SHT_PROGBITS && (shdr.sh_flags & SHF_EXECINSTR))
            {
                if (address >= shdr.sh_addr && address < shdr.sh_addr + shdr.sh_size)
                {
                    disassembleSection(scn, &shdr, address);
                    break;
                }
            }
        }
#endif
    }

#ifdef _WIN32
    void disassembleSection(uint64_t start, uint64_t end)
    {
        size_t codeSize = end - start;
        std::vector<uint8_t> code(codeSize);
        peFile.seekg(start, std::ios::beg);
        peFile.read(reinterpret_cast<char *>(code.data()), codeSize);

        cs_insn *insn;
        size_t count = cs_disasm(handle, code.data(), codeSize, start, 0, &insn);

        if (count > 0)
        {
            for (size_t j = 0; j < count; j++)
            {
                generateHighLevelCode(insn[j]);
                if (std::string(insn[j].mnemonic) == "ret")
                {
                    break;
                }
            }
            cs_free(insn, count);
        }
        else
        {
            std::cerr << "Failed to disassemble function" << std::endl;
        }
    }
#else
    void disassembleSection(Elf_Scn *scn, GElf_Shdr *shdr, uint64_t startAddress)
    {
        Elf_Data *data = elf_getdata(scn, nullptr);
        if (data == nullptr || data->d_size == 0)
        {
            std::cerr << "Failed to get section data" << std::endl;
            return;
        }

        uint8_t *code = static_cast<uint8_t *>(data->d_buf);
        size_t code_size = data->d_size;
        uint64_t address = shdr->sh_addr;
        size_t offset = startAddress - address;

        cs_insn *insn;
        size_t count = cs_disasm(handle, code + offset, code_size - offset,
                                 startAddress, 0, &insn);

        if (count > 0)
        {
            for (size_t j = 0; j < count; j++)
            {
                generateHighLevelCode(insn[j]);
                if (std::string(insn[j].mnemonic) == "ret")
                {
                    break;
                }
            }
            cs_free(insn, count);
        }
        else
        {
            std::cerr << "Failed to disassemble function" << std::endl;
        }
    }
#endif

    void generateHighLevelCode(const cs_insn &insn)
    {
        std::string mnemonic(insn.mnemonic);
        std::string op_str(insn.op_str);

        outFile << "    ";

        if (mnemonic == "mov")
        {
            outFile << op_str.substr(op_str.find(',') + 1) << " = "
                    << op_str.substr(0, op_str.find(',')) << ";\n";
        }
        else if (mnemonic == "call")
        {
            outFile << op_str << "();\n";
        }
        else if (mnemonic == "ret")
        {
            outFile << "return;\n";
        }
        else
        {
            outFile << "// " << mnemonic << " " << op_str << "\n";
        }
    }
};

int main(int argc, char **argv)
{
    if (argc != 4 || strcmp(argv[2], "-o") != 0)
    {
        std::cerr << "Usage: " << argv[0] << " input.bin -o out.c" << std::endl;
        return 1;
    }

    Decompiler decompiler(argv[1], argv[3]);
    decompiler.decompile();

    return 0;
}