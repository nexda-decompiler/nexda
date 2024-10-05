#include <capstone/capstone.h>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <gelf.h>
#include <iomanip>
#include <iostream>
#include <libelf.h>
#include <map>
#include <unistd.h>
#include <vector>

class Decompiler
{
  private:
    Elf *elf;
    int fd;
    csh handle;
    std::ofstream outFile;
    std::map<uint64_t, std::string> functions;

  public:
    Decompiler(const char *inputFile, const char *outputFile)
        : elf(nullptr), fd(-1)
    {
        if (elf_version(EV_CURRENT) == EV_NONE)
        {
            std::cerr << "Failed to initialize libelf" << std::endl;
            return;
        }

        fd = open(inputFile, O_RDONLY);
        if (fd < 0)
        {
            std::cerr << "Failed to open file: " << inputFile << std::endl;
            return;
        }

        elf = elf_begin(fd, ELF_C_READ, nullptr);
        if (!elf)
        {
            std::cerr << "Failed to read ELF file" << std::endl;
            close(fd);
            return;
        }

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        {
            std::cerr << "Failed to initialize Capstone" << std::endl;
            elf_end(elf);
            close(fd);
            return;
        }

        outFile.open(outputFile);
        if (!outFile.is_open())
        {
            std::cerr << "Failed to open output file: " << outputFile
                      << std::endl;
            elf_end(elf);
            close(fd);
            cs_close(&handle);
            return;
        }
    }

    ~Decompiler()
    {
        if (elf)
            elf_end(elf);
        if (fd >= 0)
            close(fd);
        cs_close(&handle);
        if (outFile.is_open())
            outFile.close();
    }

    void
    decompile()
    {
        analyzeFunctions();
        generateCCode();
    }

  private:
    void
    analyzeFunctions()
    {
        Elf_Scn *scn = nullptr;
        GElf_Shdr shdr;
        size_t shstrndx;

        if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        {
            std::cerr << "Failed to get section header string index"
                      << std::endl;
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

    void
    analyzeSymbolTable(Elf_Scn *scn, GElf_Shdr *shdr)
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

    void
    generateCCode()
    {
        outFile << "#include <stdio.h>\n\n";

        for (const auto &func : functions)
        {
            outFile << "void " << func.second << "() {\n";
            disassembleFunction(func.first);
            outFile << "}\n\n";
        }

        outFile << "int main() {\n";
        outFile << "    // Call the entry point function here\n";
        outFile << "    return 0;\n";
        outFile << "}\n";
    }

    void
    disassembleFunction(uint64_t address)
    {
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
                if (address >= shdr.sh_addr &&
                    address < shdr.sh_addr + shdr.sh_size)
                {
                    disassembleSection(scn, &shdr, address);
                    break;
                }
            }
        }
    }

    void
    disassembleSection(Elf_Scn *scn, GElf_Shdr *shdr, uint64_t startAddress)
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
                generatePseudoCode(insn[j]);

                // Stop at return instruction
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

    void
    generatePseudoCode(const cs_insn &insn)
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

int
main(int argc, char **argv)
{
    if (argc != 4 || strcmp(argv[2], "-o") != 0)
    {
        std::cerr << "Usage: " << argv[0] << " input.elf -o out.c" << std::endl;
        return 1;
    }

    Decompiler decompiler(argv[1], argv[3]);
    decompiler.decompile();

    return 0;
}