#include "compressor.h"

unsigned char sig[8] = "mel-jira";
uint64_t new_entry_point;
int stub = 0;
unsigned char *stub64_bin;
int stub_size = 0;

void ft_error(const char *errorMsg){
    while (*errorMsg){
        write(2, &*errorMsg++, 1);
    }
}

void my_strncpy(unsigned char *dest, unsigned const char *src, int size){
    while (size > 0) {
        *dest = *src;
        dest++;
        src++;
        size--;
    }
}

unsigned char *load_stub(){
    int fd = open("stub64.bin", O_RDONLY);
    if (fd < 0){
        write(2, "Error can't open stub64.bin\n", 28);
        exit(1);
    }
    long long size = lseek(fd, 0, SEEK_END);
    unsigned char *buffer = malloc(size+1);
    if (!buffer){
        ft_error("Error malloc failed\n");
        exit(1);
    }
    lseek(fd, 0, SEEK_SET);
    stub_size = read(fd, buffer, size);
    printf("stub size: %d\n", stub_size);
    if (stub_size <= 0){
        ft_error("Error read failed\n");
        exit(1);
    }
    buffer[size+1] = '\0';
    return buffer;
}

void patch_stub(unsigned char *stub, size_t len, uint64_t text_va, uint64_t text_sz, uint64_t text_nsz,
    uint64_t oep) {
    for (size_t i = 0; i < len - 8; i++) {
        uint64_t *ptr = (uint64_t *)&stub[i];
        if (*ptr == 0xAAAAAAAAAAAAAAA1) *ptr = new_entry_point - text_va;
        else if (*ptr == 0xBBBBBBBBBBBBBBB1) *ptr = text_sz;
        else if (*ptr == 0xEEEEEEEEEEEEEEE1) *ptr = text_nsz;
        else if (*ptr == 0xCCCCCCCCCCCCCCCC) *ptr = new_entry_point - oep;
    }
}

int compressBinary(Compressor *data){
    unsigned char *buffer;
    
    buffer = NULL;
    off_t fileSize = lseek(data->fd, 0, SEEK_END);
    buffer = malloc(fileSize+4096);
    if (!buffer){
        perror("Error malloc\n"); 
        return (2);
    }
    lseek(data->fd, 0, SEEK_SET);
    if (read(data->fd, buffer, fileSize) < 0)
    {
        perror("Error read failed\n");
        free(buffer);
        return (4);
    }

    if (buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F'){ // .ELF
        if (buffer[8] == 0x6d && buffer[9] == 0x65 && buffer[10] == 0x6c && buffer[11] == 0x2d &&
            buffer[12] == 0x6a && buffer[13] == 0x69 && buffer[14] == 0x72 && buffer[15] == 0x61){
            ft_error("this binary already been compressed by mel-jira (:\n");
            free(buffer);
            return (1);
        }
        if (!(buffer[16] == ET_EXEC || buffer[16] == ET_DYN)){
            ft_error("this is not an Executable binary\n");
            free(buffer);
            return (1);
        }
        else if (buffer[4] == 2){

            Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buffer;

            uint64_t original_entry_point = ehdr->e_entry;

            Elf64_Shdr *strtab_shdr = (Elf64_Shdr *)(buffer + ehdr->e_shoff + (ehdr->e_shstrndx * ehdr->e_shentsize));
            char *strtab = (char *)(buffer + strtab_shdr->sh_offset);

            sections Sections;
            Sections.text_sh_size = 0;
            Sections.text_sh_new_size = 0;

            for (int i = 0; i < ehdr->e_shnum; i++) {
                Elf64_Shdr *shdr = (Elf64_Shdr *)(buffer + ehdr->e_shoff + (i * ehdr->e_shentsize));
                char *name = strtab + shdr->sh_name;

                if (!strcmp(name, ".text")) {
                    Sections.text_sh_addr = shdr->sh_addr;
                    Sections.text_sh_offset = shdr->sh_offset;
                    Sections.text_sh_size = shdr->sh_size;

                    unsigned char *tmp = malloc((Sections.text_sh_size*2)+1);
                    memset(tmp, 0, (Sections.text_sh_size * 2) + 1);
                    compress_algo(buffer+Sections.text_sh_offset, Sections.text_sh_size, tmp, (int *)&Sections.text_sh_new_size);
                    memcpy(buffer+Sections.text_sh_offset, tmp, Sections.text_sh_new_size);
                    free(tmp);
                    printf("we could safe: %lu\n", Sections.text_sh_size-Sections.text_sh_new_size);
                }
            }

            for (int i = 0; i < ehdr->e_phnum; i++) {
                Elf64_Phdr *ph = (Elf64_Phdr *)(buffer + ehdr->e_phoff + (i * ehdr->e_phentsize));

                if (ph->p_type  == 1) {
                    ph->p_flags = 7; 
                }
                if (ph->p_type  == 4  && stub == 0) {
                    stub = 1;
                    uint64_t highest_vaddr = 0;
                    for (int j = 0; j < ehdr->e_phnum; j++) {
                        Elf64_Phdr *temp_ph = (Elf64_Phdr *)(buffer + ehdr->e_phoff + (j * ehdr->e_phentsize));
                        if (temp_ph->p_type == 1) {
                            uint64_t end_vaddr = temp_ph->p_vaddr + temp_ph->p_memsz;
                            if (end_vaddr > highest_vaddr) {
                                highest_vaddr = end_vaddr;
                            }
                        }
                    }
                    highest_vaddr = (highest_vaddr + 4095) & ~4095;

                    uint64_t safe_vaddr = highest_vaddr + (fileSize % 4096);

                    ph->p_type = 1;
                    ph->p_flags = 7;
                    ph->p_offset = fileSize;
                    
                    ph->p_vaddr = safe_vaddr;
                    ph->p_paddr = safe_vaddr;
                    ph->p_paddr = fileSize;
                    ph->p_filesz = stub_size;
                    ph->p_memsz = stub_size;
                    ph->p_align = 4096;
                    
                    new_entry_point = ph->p_vaddr;
                    *(uint64_t *)(buffer + 24) = new_entry_point;
                }
                else if (ph->p_type  == 4){
                    ph->p_type = 0;
                }
            }
            
            stub64_bin = load_stub();

            patch_stub(stub64_bin, stub_size, Sections.text_sh_addr, Sections.text_sh_size, Sections.text_sh_new_size,
            original_entry_point);
            my_strncpy(buffer + 8, sig, 8);
            my_strncpy(buffer+fileSize, stub64_bin, stub_size);

            int fd = open("a.out", O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (fd < 0){
                perror("Unable to open file");
                free(buffer);
                exit(2);
            }
            ehdr->e_shoff = 0;
            ehdr->e_shentsize = 0;
            ehdr->e_shnum = 0;
            ehdr->e_shstrndx = 0;
            write(fd, buffer, fileSize+stub_size);
        }
        free(buffer);
        return 1;
    }
    free(buffer);
    return 0;
}

int main(int argc, char **argv)
{
    Compressor *var;

    var = malloc(sizeof(Compressor));
    if (!var){
        perror("Error malloc in main\n");
        return (2);
    }

    if (argc < 2){
        perror("No args where provided");
        free(var);
        return (1);
    }

    var->fd = open(argv[1], O_RDONLY);
    if (var->fd < 0){
        perror("Unable to open file");
        free(var);
        return (3);
    }
    if (compressBinary(var))
    {
        close(var->fd);
        free(var);
        return (1);
    }

    return (0);
}
