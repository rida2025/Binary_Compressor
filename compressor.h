#ifndef WOODY_H
#define WOODY_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <stdint.h>

typedef struct
{
    int fd;
    Elf64_Ehdr *elf64_hdr;
} Compressor;



typedef struct {
    uint64_t text_sh_addr; 
    uint64_t text_sh_offset; 
    uint64_t text_sh_size;
    uint64_t text_sh_new_size;
} sections;

void compress_algo(unsigned char *src, int src_sz, unsigned char *dest, int *dest_sz);
void decompress_algo(unsigned char *src, int src_sz, unsigned char *dest, int *dest_sz);
void print_section(unsigned char *section, int size);

#endif