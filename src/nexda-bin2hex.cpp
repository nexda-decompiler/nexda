#include <fstream>
#include <iomanip>
#include <iostream>
#include <string_view>
#include <vector>

void
printUsage(const std::string_view programName)
{
    std::cerr << "Usage: " << programName << " input.bin -o out.hex"
              << std::endl;
}

int
main(int argc, char *argv[])
{
    if (argc != 4 || std::string_view(argv[2]) != "-o")
    {
        printUsage(argv[0]);
        return 1;
    }

    std::ifstream inputFile(argv[1], std::ios::binary);
    if (!inputFile)
    {
        std::cerr << "Error: Unable to open input file '" << argv[1] << "'."
                  << std::endl;
        return 1;
    }

    std::ofstream outputFile(argv[3]);
    if (!outputFile)
    {
        std::cerr << "Error: Unable to open output file '" << argv[3] << "'."
                  << std::endl;
        return 1;
    }

    std::vector<unsigned char> buffer(16);
    std::streamsize totalBytesRead = 0;

    while (inputFile)
    {
        inputFile.read(reinterpret_cast<char *>(buffer.data()), 16);
        std::streamsize bytesRead = inputFile.gcount();

        if (bytesRead > 0)
        {
            outputFile << std::setw(10) << std::setfill('0') << totalBytesRead
                       << ": ";

            for (std::streamsize i = 0; i < bytesRead; i += 2)
            {
                if (i > 0 && i % 8 == 0)
                {
                    outputFile << " ";
                }
                outputFile << std::setw(2) << std::setfill('0') << std::hex
                           << static_cast<int>(buffer[i]);
                if (i + 1 < bytesRead)
                {
                    outputFile << std::setw(2) << std::setfill('0') << std::hex
                               << static_cast<int>(buffer[i + 1]);
                }
                else
                {
                    outputFile << "  ";
                }
                outputFile << " ";
            }

            outputFile << std::endl;
            totalBytesRead += bytesRead;
        }
    }

    if (outputFile.fail())
    {
        std::cerr << "Error: Failed to write to output file '" << argv[3]
                  << "'." << std::endl;
        return 1;
    }

    std::cout << "Conversion completed successfully." << std::endl;
    std::cout << "Processed " << totalBytesRead << " bytes." << std::endl;
    return 0;
}