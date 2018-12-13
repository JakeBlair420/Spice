#include <errno.h>
#include <fcntl.h>              // open
#include <stdint.h>
#include <stdio.h>              // printf, fprintf, stderr
#include <string.h>             // strerror, strncmp
#include <sys/mman.h>           // mmap, munmap
#include <sys/stat.h>           // fstat
#include <unistd.h>             // close
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

typedef struct
{
    char     magic[16];
    uint32_t mappingOffset;
    uint32_t mappingCount;
    uint32_t imagesOffset;
    uint32_t imagesCount;
    uint64_t dyldBaseAddress;
    uint64_t codeSignatureOffset;
    uint64_t codeSignatureSize;
    uint64_t slideInfoOffset;
    uint64_t slideInfoSize;
    uint64_t localSymbolsOffset;
    uint64_t localSymbolsSize;
    uint8_t  uuid[16];
    uint64_t cacheType;
    uint32_t branchPoolsOffset;
    uint32_t branchPoolsCount;
    uint64_t accelerateInfoAddr;
    uint64_t accelerateInfoSize;
    uint64_t imagesTextOffset;
    uint64_t imagesTextCount;
} cache_hdr_t;

typedef struct
{
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;
    uint32_t maxProt;
    uint32_t initProt;
} cache_map_t;

typedef struct
{
    uint64_t address;
    uint64_t modTime;
    uint64_t inode;
    uint32_t pathFileOffset;
    uint32_t pad;
} cache_img_t;

typedef struct
{
    uint32_t nlistOffset;
    uint32_t nlistCount;
    uint32_t stringsOffset;
    uint32_t stringsSize;
    uint32_t entriesOffset;
    uint32_t entriesCount;
} cache_local_info_t;

typedef struct
{
    uint32_t dylibOffset;
    uint32_t nlistStartIndex;
    uint32_t nlistCount;
} cache_local_entry_t;

typedef struct mach_header      mach_hdr32_t;
typedef struct mach_header_64   mach_hdr64_t;
typedef struct load_command     mach_lc_t;
typedef struct symtab_command   mach_stab_t;
typedef struct nlist            nlist32_t;
typedef struct nlist_64         nlist64_t;

uint64_t realsym(const char *file, const char *sym)
{
    uint64_t addr = 0;
    int fd = -1;
    size_t filesize = 0;
    void *cache = NULL;

    errno = 0;

    fd = open(file, O_RDONLY);
    if(fd == -1) goto out;

    struct stat s;
    if(fstat(fd, &s) != 0) goto out;

    filesize = s.st_size;
    if(filesize < sizeof(cache_hdr_t)) goto out;

    cache = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    if(cache == MAP_FAILED) goto out;

    cache_hdr_t *hdr = cache;
    if(strncmp(hdr->magic, "dyld_v1 ", 8) != 0) goto out;

    if(!hdr->localSymbolsSize) goto out;

    cache_local_info_t *local_info = (cache_local_info_t*)((uintptr_t)cache + hdr->localSymbolsOffset);
    cache_local_entry_t *local_entries = (cache_local_entry_t*)((uintptr_t)local_info + local_info->entriesOffset);
    const char *local_strtab = (const char*)((uintptr_t)local_info + local_info->stringsOffset);

    for(size_t i = 0; i < local_info->entriesCount; ++i)
    {
        mach_hdr64_t *h64 = (mach_hdr64_t*)((uintptr_t)cache + local_entries[i].dylibOffset);
        if(h64->magic != MH_MAGIC_64) continue;

        cache_local_entry_t *local_entry = &local_entries[i];
        nlist64_t *local_syms = &((nlist64_t*)((uintptr_t)local_info + local_info->nlistOffset))[local_entry->nlistStartIndex];
        for(size_t n = 0; n < local_entry->nlistCount; ++n)
        {
            const char *name = &local_strtab[local_syms[n].n_un.n_strx];
            if(strcmp(name, sym) == 0)
            {
                addr = local_syms[n].n_value;
                goto out;
            }
        }
        for(mach_lc_t *cmd = (mach_lc_t*)(h64 + 1), *end = (mach_lc_t*)((uintptr_t)cmd + h64->sizeofcmds);
            cmd < end;
            cmd = (mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize))
        {
            if(cmd->cmd == LC_SYMTAB)
            {
                mach_stab_t *stab = (mach_stab_t*)cmd;
                nlist64_t *syms = (nlist64_t*)((uintptr_t)cache + stab->symoff);
                char *strs = (char*)((uintptr_t)cache + stab->stroff);
                for(size_t n = 0; n < stab->nsyms; ++n)
                {
                    if((syms[n].n_type & N_TYPE) != N_UNDF && (syms[n].n_type & N_EXT))
                    {
                        const char *name = &strs[syms[n].n_un.n_strx];
                        if(strcmp(name, sym) == 0)
                        {
                            addr = syms[n].n_value;
                            goto out;
                        }
                    }
                }
            }
        }
    }

out:;
    if(cache) munmap(cache, filesize);
    if(fd != -1) close(fd);
    return addr;
}

#ifdef REALSYM_MAIN
int main(int argc, const char **argv)
{
    if(argc != 3)
    {
        fprintf(stderr, "Usage: %s file sym\n", argv[0]);
        return -1;
    }
    uint64_t addr = realsym(argv[1], argv[2]);
    if(!addr)
    {
        fprintf(stderr, "%s\n", strerror(errno));
        return -1;
    }
    printf("0x%llx\n", addr);
    return 0;
}
#endif
