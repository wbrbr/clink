#ifndef ELF_FILE_H
#define ELF_FILE_H
#include <elf.h>
#include <stdbool.h>
#define EXEC_OFFSET 0x100000

typedef struct
{
    uint64_t addr;
} Segment;

typedef struct
{
    char* name;
    uint64_t offset;
    uint64_t size;
    
    Segment* segment;
    uint64_t new_offset;
} Section;

typedef struct
{
    bool undef;

    char* name;
    uint64_t value;
    uint8_t scope;
    Section* section;
} Symbol;

typedef struct
{
    Elf64_Ehdr header;
    Section* sections;
    Symbol* symbols;
    unsigned char* data;
    uint64_t filesize;
    int symbols_num;
} ELFFile;

ELFFile file_init(const char* path);
void* file_get_section(ELFFile* file, const char* name, uint64_t* size);
Section* file_get_section_header(ELFFile* file, const char* name);
void file_do_relocations(ELFFile* file);
void file_do_rela(ELFFile* file, int i, char* section);

#endif
