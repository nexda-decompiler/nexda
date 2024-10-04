#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

struct MemoryRegion
{
    unsigned long start;
    unsigned long end;
    unsigned long size;
    std::string permissions;
    unsigned long offset;
    std::string path;
};

class ProcessMemoryAnalyzer
{
  private:
    pid_t pid;
    std::vector<MemoryRegion> regions;

    void
    parseMemoryMap()
    {
        std::stringstream ss;
        ss << "/proc/" << pid << "/maps";
        std::ifstream maps_file(ss.str());

        if (!maps_file.is_open())
        {
            throw std::runtime_error("Unable to open memory map file");
        }

        std::string line;
        while (std::getline(maps_file, line))
        {
            MemoryRegion region;
            std::istringstream iss(line);
            std::string address_range;
            iss >> address_range >> region.permissions >> std::hex >>
                region.offset;
            iss.ignore(2); // Skip two fields (dev and inode)
            std::getline(iss >> std::ws,
                         region.path); // Read the rest of the line as path

            sscanf(address_range.c_str(), "%lx-%lx", &region.start,
                   &region.end);
            region.size = region.end - region.start;

            regions.push_back(region);
        }
    }

  public:
    ProcessMemoryAnalyzer(pid_t pid) : pid(pid) { parseMemoryMap(); }

    size_t
    getTotalMemoryUsage() const
    {
        size_t total = 0;
        for (const auto &region : regions)
        {
            total += region.size;
        }
        return total;
    }

    size_t
    getHeapSize() const
    {
        for (const auto &region : regions)
        {
            if (region.path == "[heap]")
            {
                return region.size;
            }
        }
        return 0;
    }

    size_t
    getStackSize() const
    {
        for (const auto &region : regions)
        {
            if (region.path == "[stack]")
            {
                return region.size;
            }
        }
        return 0;
    }

    size_t
    getTextSegmentSize() const
    {
        for (const auto &region : regions)
        {
            if (region.permissions.find('x') != std::string::npos &&
                region.path.find('/') == 0)
            {
                return region.size;
            }
        }
        return 0;
    }

    size_t
    getDataSegmentSize() const
    {
        size_t total = 0;
        for (const auto &region : regions)
        {
            if (region.permissions.find('w') != std::string::npos &&
                region.path.find('/') == 0)
            {
                total += region.size;
            }
        }
        return total;
    }

    size_t
    getSharedLibrariesSize() const
    {
        size_t total = 0;
        for (const auto &region : regions)
        {
            if (region.path.find(".so") != std::string::npos)
            {
                total += region.size;
            }
        }
        return total;
    }

    size_t
    getAnonymousMemorySize() const
    {
        size_t total = 0;
        for (const auto &region : regions)
        {
            if (region.path.empty() || region.path == "[anon]")
            {
                total += region.size;
            }
        }
        return total;
    }

    void
    printAnalysis() const
    {
        std::cout << "Memory Analysis for PID: " << pid << std::endl;
        std::cout << "1. Total Memory Usage: " << getTotalMemoryUsage() / 1024
                  << " KB" << std::endl;
        std::cout << "2. Heap Size: " << getHeapSize() / 1024 << " KB"
                  << std::endl;
        std::cout << "3. Stack Size: " << getStackSize() / 1024 << " KB"
                  << std::endl;
        std::cout << "4. Text Segment Size: " << getTextSegmentSize() / 1024
                  << " KB" << std::endl;
        std::cout << "5. Data Segment Size: " << getDataSegmentSize() / 1024
                  << " KB" << std::endl;
        std::cout << "6. Shared Libraries Size: "
                  << getSharedLibrariesSize() / 1024 << " KB" << std::endl;
        std::cout << "7. Anonymous Memory Size: "
                  << getAnonymousMemorySize() / 1024 << " KB" << std::endl;
    }
};

pid_t
getPIDFromExecutable(const std::string &executable)
{
    std::stringstream ss;
    ss << "pidof " << executable;
    FILE *fp = popen(ss.str().c_str(), "r");
    if (!fp)
    {
        throw std::runtime_error("Failed to run pidof command");
    }

    char buffer[128];
    if (fgets(buffer, sizeof(buffer), fp) == nullptr)
    {
        pclose(fp);
        throw std::runtime_error("Executable is not running");
    }

    pclose(fp);
    return std::stoi(buffer);
}

int
main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <executable>" << std::endl;
        return 1;
    }

    std::string executable = argv[1];
    try
    {
        pid_t pid = getPIDFromExecutable(executable);
        ProcessMemoryAnalyzer analyzer(pid);
        analyzer.printAnalysis();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}