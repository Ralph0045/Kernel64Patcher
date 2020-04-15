#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <liboffsetfinder64/kernelpatchfinder64.hpp>
#include <liboffsetfinder64/machopatchfinder64.hpp>

#define HAS_ARG(x,y) (!strcmp(argv[i], x) && (i + y) < argc)

using namespace tihmstar::offsetfinder64;

int main(int argc, const char * argv[]) {
    FILE* fp = NULL;
    bool get_AMFI_patch = false;
    int flags = 0;
    
    if(argc < 5) {
        printf("Usage: %s <kernel_in> <kernel_out> <version> [args]\n", argv[0]);
        printf("\t-a\t\tDisable AMFI from kernel patch\n");
        return -1;
    }
    
    printf("%s: Starting...\n", __FUNCTION__);
    
    for(int i = 0; i < argc; i++) {
        
        if(HAS_ARG("-a", 0)) {
            get_AMFI_patch = true;
        }
    }
    
    if (!get_AMFI_patch) {
        printf("%s: Nothing to patch!\n", __FUNCTION__);
        return -1;
    }
    
    std::vector<patch> patches;
    kernelpatchfinder64 kpf(argv[1]);
    
    if (get_AMFI_patch) {
        printf("Kernel: Adding AMFI_get_out_of_my_way patch...\n");
        for(int i = 0; i < argc; i++) {
            if(HAS_ARG("10", 0)) {
                auto p = kpf.get_AMFI_10_patch();
                patches.insert(patches.end(), p.begin(), p.end());
            }
            if(HAS_ARG("11", 0)) {
                auto p = kpf.get_AMFI_11_patch();
                patches.insert(patches.end(), p.begin(), p.end());
            }
            if(HAS_ARG("12", 0)) {
                auto p = kpf.get_AMFI_12_patch();
                patches.insert(patches.end(), p.begin(), p.end());
            }
            if(HAS_ARG("13", 0)) {
                auto p = kpf.get_AMFI_13_patch();
                patches.insert(patches.end(), p.begin(), p.end());
            }
        }
    }
    
    
    /* Write out the patched file... */
    fp = fopen(argv[2], "wb+");
    if(!fp) {
        printf("%s: Unable to open %s!\n", __FUNCTION__, argv[2]);
        return -1;
    }
    
    for (auto p : patches) {
        char *buf = (char*)kpf.buf();
        tihmstar::offsetfinder64::offset_t off = (tihmstar::offsetfinder64::offset_t)((const char *)kpf.memoryForLoc(p._location) - buf);
        printf("applying patch=%p : ",p._location);
        for (int i=0; i<p._patchSize; i++) {
            printf("%02x",((uint8_t*)p._patch)[i]);
        }
        printf("\n");
        memcpy(&buf[off], p._patch, p._patchSize);
    }
    
    printf("%s: Writing out patched file to %s...\n", __FUNCTION__, argv[2]);
    fwrite(kpf.buf(), kpf.bufSize(), 1, fp);
    
    fflush(fp);
    fclose(fp);
    
    printf("%s: Quitting...\n", __FUNCTION__);
    
    return 0;
}

