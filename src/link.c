#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <elf.h>
#include "elffile.h"

int main(int argc, char** argv)
{
    assert(argc > 1);
    assert(sizeof(Elf64_Ehdr) == 64);

    ELFFile input = file_init(argv[1]);

    Segment code_segment;
    Segment data_segment;
    uint64_t code_off = 0;
    uint64_t data_off = 0;
    for (int i = 0; i < input.header.e_shnum; i++)
    {
        if (strcmp(input.sections[i].name, ".text") == 0) {
            input.sections[i].segment = &code_segment;
            input.sections[i].new_offset = code_off;
            code_off += input.sections[i].size;
        } else if (strcmp(input.sections[i].name, ".data") == 0) {
            input.sections[i].segment = &data_segment;
            input.sections[i].new_offset = data_off+sizeof(Elf64_Ehdr)+2*sizeof(Elf64_Phdr);
            data_off += input.sections[i].size;
        }
    }

    unsigned char* text = (unsigned char*)file_get_section(&input, ".text", &code_off);
    unsigned char* data = (unsigned char*)file_get_section(&input, ".data", &data_off);

    Elf64_Ehdr header;
    memset(&header, 0, sizeof(header));
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
    header.e_phoff = 64;
    header.e_shoff = 0;
    header.e_flags = 0;
    header.e_ehsize = sizeof(Elf64_Ehdr);
    header.e_phentsize = sizeof(Elf64_Phdr);
    header.e_phnum = 2;
    header.e_shentsize = 0;
    header.e_shnum = 0;
    header.e_shstrndx = 0;

    Elf64_Phdr dataheader;
    dataheader.p_type = 1;
    dataheader.p_flags = 6; // read | write
    dataheader.p_offset = 0;
    dataheader.p_vaddr = EXEC_OFFSET;
    dataheader.p_paddr = dataheader.p_vaddr;
    dataheader.p_filesz = data_off+sizeof(Elf64_Ehdr)+2*sizeof(Elf64_Phdr);
    dataheader.p_memsz = dataheader.p_filesz;
    dataheader.p_align = 4096;

    Elf64_Phdr exeheader;
    exeheader.p_type = 1;
    exeheader.p_flags = 5; // exec | read
    exeheader.p_offset = dataheader.p_filesz;
    exeheader.p_vaddr = EXEC_OFFSET+4096+exeheader.p_offset;
    header.e_entry = exeheader.p_vaddr;
    exeheader.p_paddr = exeheader.p_vaddr;
    exeheader.p_filesz = code_off;
    exeheader.p_memsz = exeheader.p_filesz;
    exeheader.p_align = 4096;

    code_segment.addr = exeheader.p_vaddr;
    data_segment.addr = dataheader.p_vaddr;

    file_do_relocations(&input);

    FILE* fp = fopen("out", "w");
    if (fp == NULL) {
        perror(NULL);
        return 1;
    }
    fwrite(&header, sizeof(Elf64_Ehdr), 1, fp);
    fwrite(&dataheader, sizeof(Elf64_Phdr), 1, fp);
    fwrite(&exeheader, sizeof(Elf64_Phdr), 1, fp);
    // fwrite(&null_header, sizeof(Elf64_Shdr), 1, fp);
    // fwrite(&text_header, sizeof(Elf64_Shdr), 1, fp);
    // fwrite(&shstr_header, sizeof(Elf64_Shdr), 1, fp);
    fwrite(data, data_off, 1, fp);
    fwrite(text, code_off, 1, fp);
    // fwrite(mystrings, sizeof(mystrings), 1, fp);
    return 0;
}
