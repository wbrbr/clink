#include <iostream>
#include <cstdio>
#include <cassert>
#include <cstring>

#define EI_NIDENT 16
#define EXEC_OFFSET 0x100000

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr;

int main(int argc, char** argv)
{
    assert(argc > 1);
    assert(sizeof(Elf64_Ehdr) == 64);
    FILE* input = fopen(argv[1], "r");
    Elf64_Ehdr input_hdr;
    fread(&input_hdr, sizeof(Elf64_Ehdr), 1, input);
    Elf64_Shdr* sections = (Elf64_Shdr*)malloc(input_hdr.e_shentsize * input_hdr.e_shnum);
    fseek(input, input_hdr.e_shoff, SEEK_SET);
    assert(fread(sections, input_hdr.e_shentsize, input_hdr.e_shnum, input) == input_hdr.e_shnum);

    std::cout << sections[input_hdr.e_shstrndx].sh_size << std::endl;
    char* strings = (char*)malloc(sections[input_hdr.e_shstrndx].sh_size);
    fseek(input, sections[input_hdr.e_shstrndx].sh_offset, SEEK_SET);
    fread(strings, sections[input_hdr.e_shstrndx].sh_size, 1, input);

    uint64_t text_size = 0;
    unsigned char* text = NULL;

    for (int i = 0; i < input_hdr.e_shnum; i++)
    {
        char* name = strings + sections[i].sh_name;
        if (strcmp(name, ".text") == 0) {
            std::cout << "found .text" << std::endl;
            text_size = sections[i].sh_size;
            std::cout << text_size << std::endl;
            text = (unsigned char*)malloc(text_size);
            fseek(input, sections[i].sh_offset, SEEK_SET);
            assert(fread(text, text_size, 1, input) == 1);
        }
    }


    Elf64_Ehdr header;
    header.e_ident[0] = 0x7F;
    header.e_ident[1] = 'E';
    header.e_ident[2] = 'L';
    header.e_ident[3] = 'F';
    header.e_ident[4] = 2; // class
    header.e_ident[5] = 1; // lsb
    header.e_ident[6] = 1; // version
    header.e_ident[7] = 0; // OS

    header.e_type = 2;
    header.e_machine = 0x3E;
    header.e_version = 1;
    header.e_entry = EXEC_OFFSET+sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr);
    header.e_phoff = 64;
    header.e_shoff = 0;
    header.e_flags = 0;
    header.e_ehsize = sizeof(Elf64_Ehdr);
    header.e_phentsize = sizeof(Elf64_Phdr);
    header.e_phnum = 1;
    header.e_shentsize = 0;
    header.e_shnum = 0;
    header.e_shstrndx = 0;

    Elf64_Phdr pheader;
    pheader.p_type = 1;
    pheader.p_flags = 5; // exec | read
    pheader.p_offset = 0;
    pheader.p_vaddr = EXEC_OFFSET;
    pheader.p_paddr = pheader.p_vaddr;
    pheader.p_filesz = text_size+sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr);
    pheader.p_memsz = pheader.p_filesz;
    pheader.p_align = 4096;

    /* char mystrings[] = { 0, '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', 0, '.', 't', 'e', 'x', 't', 0 };

    Elf64_Shdr null_header;
    memset(&null_header, 0, sizeof(Elf64_Shdr));
    Elf64_Shdr text_header;
    text_header.sh_name = 11;
    text_header.sh_type = 1;
    text_header.sh_flags = 6; // exec | alloc
    text_header.sh_addr = pheader.p_vaddr;
    text_header.sh_offset = sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)+3*sizeof(Elf64_Shdr);
    text_header.sh_size = text_size;
    text_header.sh_link = 0;
    text_header.sh_info = 0;
    text_header.sh_addralign = 1;
    text_header.sh_entsize = 0;
    Elf64_Shdr shstr_header;
    shstr_header.sh_name = 1;
    shstr_header.sh_type = 3;
    shstr_header.sh_flags = 0;
    shstr_header.sh_addr = 0;
    shstr_header.sh_offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + 3*sizeof(Elf64_Shdr) + text_size;
    shstr_header.sh_size = sizeof(mystrings);
    shstr_header.sh_link = 0;
    shstr_header.sh_info = 0;
    shstr_header.sh_addralign = 1;
    shstr_header.sh_entsize = 0; */

    FILE* fp = fopen("out", "w");
    fwrite(&header, sizeof(Elf64_Ehdr), 1, fp);
    fwrite(&pheader, sizeof(Elf64_Phdr), 1, fp);
    // fwrite(&null_header, sizeof(Elf64_Shdr), 1, fp);
    // fwrite(&text_header, sizeof(Elf64_Shdr), 1, fp);
    // fwrite(&shstr_header, sizeof(Elf64_Shdr), 1, fp);
    fwrite(text, text_size, 1, fp);
    // fwrite(mystrings, sizeof(mystrings), 1, fp);
    return 0;
}
