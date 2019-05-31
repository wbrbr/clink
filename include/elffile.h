#ifndef ELF_FILE_H
#define ELF_FILE_H
#include <elf.h>

typedef struct
{
    char* name;
    uint64_t offset;
    uint64_t size;

    uint64_t new_offset;
} Section;

typedef struct
{
    char* name;
    uint64_t value;
    uint8_t info;
} Symbol;

typedef struct
{
    Elf64_Ehdr header;
    Section* sections;
    Symbol* symbols;
    unsigned char* data;
    uint64_t filesize;
} ELFFile;

ELFFile file_init(const char* path);
void* file_get_section(ELFFile* file, const char* name, uint64_t* size);
Section* file_get_section_header(ELFFile* file, const char* name);
void file_do_rela(ELFFile* file, int i, char* section);

/* class ELFFile
{
public:
    ELFFile(const char* path);
    ~ELFFile();
    void* getSection(const char* name, uint64_t* size);
    Section* getSectionHeader(const char* name);

private:
    void doRela(int i, char* section);
}; */
#endif
