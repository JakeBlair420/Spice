#include <errno.h>
#include <fcntl.h>              // open
#include <stdint.h>
#include <stdio.h>              // printf, fprintf, stderr
#include <string.h>             // strerror, strncmp
#include <sys/mman.h>           // mmap, munmap
#include <sys/stat.h>           // fstat
#include <unistd.h>             // close
#include <mach/mach.h>
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

#ifndef REALSYM_MAPALL
#   ifdef __x86_64__
#       define REALSYM_MAPALL 1
#   else
#       define REALSYM_MAPALL 0
#   endif
#endif

typedef struct
{
    int fd;
    size_t filesize;
#if REALSYM_MAPALL
    void *mem;
#endif
} cache_handle_t;

static int cache_open(cache_handle_t *handle, const char *file)
{
    int fd = -1;
    size_t filesize = 0;
#if REALSYM_MAPALL
    void *mem = MAP_FAILED;
#endif

    handle->fd = -1;
    handle->filesize = 0;
#if REALSYM_MAPALL
    handle->mem = NULL;
#endif

    fd = open(file, O_RDONLY);
    if(fd == -1) goto bad;

    struct stat s;
    if(fstat(fd, &s) != 0) goto bad;

    filesize = s.st_size;
    if(!filesize) goto bad;

#if REALSYM_MAPALL
    mem = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    if(mem == MAP_FAILED) goto bad;

    handle->mem = mem;
#endif
    handle->filesize = filesize;
    handle->fd = fd;
    return 0;

bad:;
    if(fd != -1) close(fd);
    return -1;
}

static void* cache_get(cache_handle_t *handle, off_t off, size_t len)
{
    if(off >= handle->filesize || len >= handle->filesize - off)
    {
        errno = ESPIPE;
        return NULL;
    }
#if REALSYM_MAPALL
    return (void*)((uintptr_t)handle->mem + off);
#else
    size_t diff = off & ((uintptr_t)PAGE_SIZE - 1);
    void *mem = mmap(NULL, len + diff, PROT_READ, MAP_PRIVATE, handle->fd, off - diff);
    if(mem == MAP_FAILED)
    {
        mem = NULL;
    }
    else
    {
        mem = (void*)((uintptr_t)mem + diff);
    }
    return mem;
#endif
}

static void cache_free(void *mem, size_t len)
{
#if !REALSYM_MAPALL
    uintptr_t addr = (uintptr_t)mem;
    size_t diff = addr & ((uintptr_t)PAGE_SIZE - 1);
    munmap((void*)(addr - diff), len + diff);
#endif
}

static void cache_close(cache_handle_t *handle)
{
#if REALSYM_MAPALL
    munmap(handle->mem, handle->filesize);
#endif
    close(handle->fd);
}

uint64_t realsym(const char *file, const char *sym)
{
    uint64_t addr = 0;
    int r = 0;
    cache_handle_t handle = {};
    cache_hdr_t *hdr = NULL;
    cache_local_info_t *local_info = NULL;
    errno = 0;

    r = cache_open(&handle, file);
    if(r != 0) return 0; // don't wanna goto out here

    hdr = cache_get(&handle, 0, sizeof(cache_hdr_t));
    if(!hdr) goto out;
    if(strncmp(hdr->magic, "dyld_v1 ", 8) != 0) goto out;
    if(!hdr->localSymbolsSize) goto out;

    local_info = cache_get(&handle, hdr->localSymbolsOffset, hdr->localSymbolsSize);
    if(!local_info) goto out;

    cache_local_entry_t *local_entries = (cache_local_entry_t*)((uintptr_t)local_info + local_info->entriesOffset);
    const char *local_strtab = (const char*)((uintptr_t)local_info + local_info->stringsOffset);

    for(size_t i = 0; i < local_info->entriesCount; ++i)
    {
        cache_local_entry_t *local_entry = &local_entries[i];

        mach_hdr64_t *h64 = cache_get(&handle, local_entry->dylibOffset, sizeof(mach_hdr64_t));
        if(!h64) goto skip;
        if(h64->magic != MH_MAGIC_64) goto skip;

        nlist64_t *local_syms = &((nlist64_t*)((uintptr_t)local_info + local_info->nlistOffset))[local_entry->nlistStartIndex];
        for(size_t n = 0; n < local_entry->nlistCount; ++n)
        {
            const char *name = &local_strtab[local_syms[n].n_un.n_strx];
            if(strcmp(name, sym) == 0)
            {
                addr = local_syms[n].n_value;
                goto skip;
            }
        }

        mach_lc_t *lc = cache_get(&handle, local_entry->dylibOffset + sizeof(mach_hdr64_t), h64->sizeofcmds);
        if(!lc) goto skip;

        for(mach_lc_t *cmd = lc, *end = (mach_lc_t*)((uintptr_t)lc + h64->sizeofcmds);
            cmd < end && (mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize) <= end;
            cmd = (mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize))
        {
            if(cmd->cmd == LC_SYMTAB && cmd->cmdsize == sizeof(mach_stab_t))
            {
                mach_stab_t *stab = (mach_stab_t*)cmd;
                nlist64_t *syms = cache_get(&handle, stab->symoff, sizeof(nlist64_t) * stab->nsyms);
                if(!syms) goto next;
                char *strs = cache_get(&handle, stab->stroff, stab->strsize);
                if(!strs) goto next;
                for(size_t n = 0; n < stab->nsyms; ++n)
                {
                    if((syms[n].n_type & N_TYPE) != N_UNDF && (syms[n].n_type & N_EXT))
                    {
                        const char *name = &strs[syms[n].n_un.n_strx];
                        if(strcmp(name, sym) == 0)
                        {
                            addr = syms[n].n_value;
                            goto next;
                        }
                    }
                }
            next:;
                if(strs) cache_free(strs, stab->strsize);
                if(syms) cache_free(syms, sizeof(nlist64_t) * stab->nsyms);
                if(!strs || !syms || addr) break;
            }
        }
    skip:;
        if(lc) cache_free(lc, h64->sizeofcmds);
        if(h64) cache_free(h64, sizeof(mach_hdr64_t));
        if(!lc || !h64 || addr) break;
    }

out:;
    if(local_info) cache_free(local_info, hdr->localSymbolsSize);
    if(hdr) cache_free(hdr, sizeof(cache_hdr_t));
    cache_close(&handle);
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
        fprintf(stderr, "errno: %u, %s\n", errno, strerror(errno));
        return -1;
    }
    printf("0x%llx\n", addr);
    return 0;
}
#endif
