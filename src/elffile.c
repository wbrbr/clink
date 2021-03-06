#include "elffile.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

ELFFile file_init(const char* path)
{
    ELFFile file;
    FILE* fp = fopen(path, "r");
    fseek(fp, 0, SEEK_END);
    file.filesize = ftell(fp);
    file.data = (unsigned char*)malloc(file.filesize);
    fseek(fp, 0, SEEK_SET);
    assert(fread(file.data, 1, file.filesize, fp) == file.filesize);

    file.header = *(Elf64_Ehdr*)(file.data);

    Elf64_Shdr* shstr = (Elf64_Shdr*)(file.data + file.header.e_shoff + file.header.e_shstrndx*file.header.e_shentsize);
    char* shstrings = (char*)(file.data + shstr->sh_offset);

    file.sections = (Section*)malloc(file.header.e_shnum * sizeof(Section));

    for (int i = 0; i < file.header.e_shnum; i++)
    {
        Elf64_Shdr* sec = (Elf64_Shdr*)(file.data + file.header.e_shoff + file.header.e_shentsize*i);
        char* name = shstrings + sec->sh_name;

        file.sections[i].name = name;
        file.sections[i].offset = sec->sh_offset;
        file.sections[i].size = sec->sh_size;
        file.sections[i].segment = NULL;
    }

    uint64_t strings_len;
    char* strings = (char*)file_get_section(&file, ".strtab", &strings_len);

    uint64_t symbols_size;
    Elf64_Sym* symbols_arr = (Elf64_Sym*)file_get_section(&file, ".symtab", &symbols_size);
    file.symbols_num = symbols_size / sizeof(Elf64_Sym);

    file.symbols = (Symbol*)malloc(file.symbols_num*sizeof(Symbol));

    for (int i = 1; i < file.symbols_num; i++)
    {
        file.symbols[i].name = strings + symbols_arr[i].st_name;
        if (symbols_arr[i].st_shndx == SHN_UNDEF) {
            file.symbols[i].undef = true;
        } else {
            file.symbols[i].undef = false;
            file.symbols[i].value = symbols_arr[i].st_value;
            file.symbols[i].scope = symbols_arr[i].st_info >> 4;
            file.symbols[i].section = file.sections+symbols_arr[i].st_shndx; // TODO: SHN_ABS
        }
    }

    return file;
}

void file_destroy(ELFFile* file)
{
    free(file->data);
    free(file->sections);
    free(file->symbols);
}

void* file_get_section(ELFFile* file, const char* name, uint64_t* size)
{
    for (int i = 0; i < file->header.e_shnum; i++)
    {
        if (strcmp(file->sections[i].name, name) == 0) {
            if (size != NULL) *size = file->sections[i].size;
            return (void*)(file->data + file->sections[i].offset);
        }
    }
    assert(0);
}

Section* file_get_section_header(ELFFile* file, const char* name)
{
    for (int i = 0; i < file->header.e_shnum; i++)
    {
        if (strcmp(file->sections[i].name, name) == 0) {
            return &file->sections[i];
        }
    }
    assert(0);
}

void file_do_relocations(ELFFile* file)
{
    for (int i = 0; i < file->header.e_shnum; i++)
    {
        if (strlen(file->sections[i].name) >= 5 && file->sections[i].name[0] == '.'
                                                && file->sections[i].name[1] == 'r'
                                                && file->sections[i].name[2] == 'e'
                                                && file->sections[i].name[3] == 'l'
                                                && file->sections[i].name[4] == 'a') {
            file_do_rela(file, i, file->sections[i].name+5);
        }
    }
}

void file_do_rela(ELFFile* file, int i, char* section)
{
    Elf64_Rela* relocs = (Elf64_Rela*)(file->data + file->sections[i].offset);
    uint64_t num = file->sections[i].size / sizeof(Elf64_Rela);

    Section* sec = file_get_section_header(file, section);
    unsigned char* buf = (unsigned char*)file_get_section(file, section, NULL);

    uint32_t val;
    uint32_t P;
    uint64_t val64;

    for (uint64_t j = 0; j < num; j++)
    {
        Symbol sym = file->symbols[ELF64_R_SYM(relocs[j].r_info)];

        switch(ELF64_R_TYPE(relocs[j].r_info)) {
            case R_X86_64_64: // R_X86_64_64
                // printf("Segment: %lx\nSection: %lx\nSymbol: %lx\nAddend: %lx\n", sym.section->segment->addr, sym.section->new_offset, sym.value, relocs[j].r_addend);
                val64 = sym.section->segment->addr + sym.section->new_offset + sym.value + relocs[j].r_addend;
                memcpy(buf+relocs[j].r_offset, &val64, 8);
                break;
            case R_X86_64_32S: // R_X86_64_32S
                // sign extension
                val = sym.section->segment->addr + sym.section->new_offset + sym.value + relocs[j].r_addend;
                assert(val == 0x100000+sizeof(Elf64_Ehdr)+2*sizeof(Elf64_Phdr));
                // val = 0x100000+sizeof(Elf64_Ehdr)+2*sizeof(Elf64_Phdr);
                memcpy(buf+relocs[j].r_offset, &val, 4);
                break;
            case R_X86_64_8: // R_X86_64_8
                // handle ABS
                buf[relocs[j].r_offset] = sec->new_offset + file->symbols[ELF64_R_SYM(relocs[j].r_info)].value + relocs[j].r_addend;
                break;
            case R_X86_64_PC32:
                P = sec->segment->addr + sec->new_offset + relocs[j].r_offset;
                val = sym.section->segment->addr + sym.section->new_offset + sym.value + relocs[j].r_addend - P;
                memcpy(buf+relocs[j].r_offset, &val, 4);
                break;
            default:
                fprintf(stderr, "Relocation type: %lu\n", ELF64_R_TYPE(relocs[j].r_info));
                
        }
    }
}
