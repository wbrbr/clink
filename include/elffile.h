#ifndef ELF_FILE_H
#define ELF_FILE_H
#include <elf.h>

struct Section
{
    char* name;
    uint64_t offset;
    uint64_t size;

    uint64_t new_offset;
};

struct Symbol
{
    char* name;
    uint64_t value;
    uint8_t info;
};

class ELFFile
{
public:
    ELFFile(const char* path);
    ~ELFFile();
    void* getSection(const char* name, uint64_t* size);
    Section* getSectionHeader(const char* name);

private:
    void doRela(int i, char* section);
    Elf64_Ehdr header;
    Section* sections;
    Symbol* symbols;
    unsigned char* data;
    uint64_t filesize;
};
#endif
