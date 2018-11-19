#include <stdlib.h>

#include "common.h"
#include "kents.h"
#include "kutils.h"
#include "kmem.h"
#include "cs_blobs.h"

uint64_t find_csblobs(int pid)
{
    uint64_t proc = find_proc(pid);
    if (proc == 0x0)
    {
        LOG("failed to find proc for pid %d", pid);
        return 0;
    }
    
    uint64_t textvp = rk64(proc + 0x248); // proc->p_textvp
    if (textvp == 0x0)
    {
        LOG("failed to find textvp for pid %d", pid);
        return 0;
    }
    
    uint64_t ubcinfo = rk64(textvp + 0x78); // vnode->v_ubcinfo
    if (ubcinfo == 0x0)
    {
        LOG("failed to find ubcinfo for pid %d", pid);
        return 0;
    }
    
    return rk64(ubcinfo + 0x50); // ubc_info->csblobs
}

const char *get_current_entitlements(int pid)
{
    uint64_t csblob = find_csblobs(pid);
    if (csblob == 0x0)
    {
        LOG("failed to find csblob for pid %d", pid);
        return NULL;
    }
    
    uint64_t csb_entitlements_blob = rk64(csblob + 0x90); // cs_blob->csb_entitlements_blob
    if (csb_entitlements_blob == 0x0)
    {
        LOG("failed to find csb_entitlements_blob for pid %d", pid);
        return NULL;
    }
    
    uint32_t blob_length = ntohl(rk32(csb_entitlements_blob + 0x4));
    if (blob_length == 0x0)
    {
        LOG("got blob length of 0 for pid %d", pid);
        return NULL;
    }
    
    // skip the header, just get the data
    blob_length -= 0x8;
    
    const char *ent_string = (const char *)malloc(blob_length);
    kread(csb_entitlements_blob + 0x8, (void *)ent_string, blob_length);
    
    return ent_string;
}

int assign_new_entitlements(int pid, const char *new_ents)
{
    uint64_t csblob = find_csblobs(pid);
    if (csblob == 0x0)
    {
        LOG("failed to find csblob for pid %d", pid);
        return -1;
    }
    
    int new_blob_length = 0x8 + (int)strlen(new_ents) + 0x1;
    
    CS_GenericBlob *new_blob = (CS_GenericBlob *)malloc(new_blob_length);
    new_blob->magic = ntohl(CSMAGIC_EMBEDDED_ENTITLEMENTS);
    new_blob->length = ntohl(new_blob_length);
    
    strncpy(new_blob->data, new_ents, strlen(new_ents) + 1);
    
    uint64_t blob_kern = kalloc(new_blob_length);
    if (blob_kern == 0x0)
    {
        LOG("failed to alloc %d bytes for new ent blob", new_blob_length);
        return -1;
    }
    
    kwrite(blob_kern, new_blob, new_blob_length);
    
    free(new_blob);
    
    wk64(csblob + 0x90, blob_kern);
    
    return 0;
}
