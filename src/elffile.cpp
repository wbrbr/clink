#include "elffile.h"
#include <cstdio>
#include <cassert>
#include <cstring>
#include <cstdlib>

ELFFile::ELFFile(const char* path)
{
    FILE* fp = fopen(path, "r");
    fseek(fp, 0, SEEK_END);
    filesize = ftell(fp);
    data = (unsigned char*)malloc(filesize);
    fseek(fp, 0, SEEK_SET);
    assert(fread(data, 1, filesize, fp) == filesize);

    header = *(Elf64_Ehdr*)(data);

    Elf64_Shdr* shstr = (Elf64_Shdr*)(data + header.e_shoff + header.e_shstrndx*header.e_shentsize);
    char* shstrings = (char*)(data + shstr->sh_offset);

    sections = (Section*)malloc(header.e_shnum * sizeof(Section));

    for (int i = 0; i < header.e_shnum; i++)
    {
        Elf64_Shdr* sec = (Elf64_Shdr*)(data + header.e_shoff + header.e_shentsize*i);
        char* name = shstrings + sec->sh_name;

        sections[i].name = name;
        sections[i].offset = sec->sh_offset;
        sections[i].size = sec->sh_size;
    }

    uint64_t strings_len;
    char* strings = (char*)getSection(".strtab", &strings_len);
    printf("%lu %s\n", strings_len, &strings[1]);

    uint64_t symbols_size;
    Elf64_Sym* symbols_arr = (Elf64_Sym*)getSection(".symtab", &symbols_size);
    uint64_t symbols_num = symbols_size / sizeof(Elf64_Sym);
    printf("%lu %lu\n", symbols_size, symbols_num);

    symbols = (Symbol*)malloc(symbols_num*sizeof(Symbol));

    for (uint64_t i = 0; i < symbols_num; i++)
    {
        symbols[i].name = strings + symbols_arr[i].st_name;
        symbols[i].info = symbols_arr[i].st_info;
        symbols[i].value = symbols_arr[i].st_value;
    }

    for (int i = 0; i < header.e_shnum; i++)
    {
        if (strlen(sections[i].name) >= 5 && sections[i].name[0] == '.'
                                          && sections[i].name[1] == 'r'
                                          && sections[i].name[2] == 'e'
                                          && sections[i].name[3] == 'l'
                                          && sections[i].name[4] == 'a') {
            doRela(i, sections[i].name+5);
        }
    }
}

ELFFile::~ELFFile()
{
    free(data);
    free(sections);
    free(symbols);
}

void* ELFFile::getSection(const char* name, uint64_t* size)
{
    for (int i = 0; i < header.e_shnum; i++)
    {
        if (strcmp(sections[i].name, name) == 0) {
            if (size != NULL) *size = sections[i].size;
            return (void*)(data + sections[i].offset);
        }
    }
    assert(0);
}

Section* ELFFile::getSectionHeader(const char* name)
{
    for (int i = 0; i < header.e_shnum; i++)
    {
        if (strcmp(sections[i].name, name) == 0) {
            return &sections[i];
        }
    }
    assert(0);
}

void ELFFile::doRela(int i, char* section)
{
    Elf64_Rela* relocs = (Elf64_Rela*)(data + sections[i].offset);
    uint64_t num = sections[i].size / sizeof(Elf64_Rela);

    Section* sec = getSectionHeader(section);
    sec->new_offset = 0x10000+4096;
    unsigned char* buf = (unsigned char*)getSection(section, NULL);

    uint32_t val;
    uint64_t val64;

    for (uint64_t j = 0; j < num; j++)
    {
        switch(ELF64_R_TYPE(relocs[j].r_info)) {
            case 1: // R_X86_64_64
                val64 = 0x100000+sizeof(Elf64_Ehdr)+2*sizeof(Elf64_Phdr)+8;
                memcpy(buf+relocs[j].r_offset, &val64, 8);
                break;
            case 11: // R_X86_64_32S
                // sign extension
                val = sec->new_offset + symbols[ELF64_R_SYM(relocs[j].r_info)].value + relocs[j].r_addend;
                val = 0x100000+sizeof(Elf64_Ehdr)+2*sizeof(Elf64_Phdr);
                memcpy(buf+relocs[j].r_offset, &val, 4);
                break;
            case 14: // R_X86_64_8
                // handle ABS
                buf[relocs[j].r_offset] = sec->new_offset + symbols[ELF64_R_SYM(relocs[j].r_info)].value + relocs[j].r_addend;
                break;
            default:
                fprintf(stderr, "Relocation type: %lu\n", ELF64_R_TYPE(relocs[j].r_info));
                
        }
    }
}
