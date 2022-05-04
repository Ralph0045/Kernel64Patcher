/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "patchfinder64.c"

#define GET_OFFSET(kernel_len, x) (x - (uintptr_t) kernel_buf)

#ifdef __linux__

/* Got memmem and put it here manually for ubuntu 20.04 it gives segmentation fault if this function is not added here */
void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
{
    int needle_first;
    const void *p = haystack;
    size_t plen = hlen;

    if (!nlen)
        return NULL;

    needle_first = *(unsigned char *)needle;

    while (plen >= nlen && (p = memchr(p, needle_first, plen - nlen + 1)))
    {
        if (!memcmp(p, needle, nlen))
            return (void *)p;

        p++;
        plen = hlen - (p - haystack);
    }

    return NULL;
}

#endif

// iOS 15 "%s: firmware validation failed %d\" @%s:%d SPU Firmware Validation Patch
int get_SPUFirmwareValidation_patch(void *kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    char rootvpString[43] = "\"%s: firmware validation failed %d\" @%s:%d";
    void* ent_loc = memmem(kernel_buf,kernel_len,rootvpString,42);
    if(!ent_loc) {
        printf("%s: Could not find \"%%s: firmware validation failed %%d\" @%%s:%%d string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s: firmware validation failed %%d\" @%%s:%%d\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"%%s: firmware validation failed %%d\" @%%s:%%d xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s: firmware validation failed %%d\" @%%s:%%d\" ref at %p\n",__FUNCTION__,(void*)xref_stuff);
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
        printf("%s: Could not find firmware validation function start\n",__FUNCTION__);
        return -1;
    }
    xref_stuff = xref64code(kernel_buf,0,(addr_t)GET_OFFSET(kernel_len, beg_func), beg_func);
    if(!xref_stuff) {
        printf("%s: Could not find previous xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found function xref at %p\n",__FUNCTION__,(void*)xref_stuff);
    addr_t next_bl = step64_back(kernel_buf, xref_stuff, 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64_back(kernel_buf, (next_bl - 0x4), 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64_back(kernel_buf, (next_bl - 0x4), 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    beg_func = bof64(kernel_buf,0,next_bl);
    if(!beg_func) {
        printf("%s: Could not find start of firmware validation function\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching SPU Firmware Validation at %p\n\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0xD65F03C0;
    return 0;
}

// iOS 15 rootvp not authenticated after mounting Patch
int get_RootVPNotAuthenticatedAfterMounting_patch(void *kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char rootVPString[40] = "rootvp not authenticated after mounting";
    char md0String[3] = "md0";
    void* ent_loc = memmem(kernel_buf,kernel_len,md0String,3);
    if(!ent_loc) {
        printf("%s: Could not find \"md0\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"md0\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"md0\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"md0\" ref at %p\n",__FUNCTION__,(void*)xref_stuff);
    addr_t next_bl = step64(kernel_buf, xref_stuff + 0x8, 100, INSN_CALL);
    if(!next_bl) {
        // Newer devices will fail here, so using another string is required
        printf("%s: Failed to use \"md0\", swapping to \"rootvp not authenticated after mounting\"\n",__FUNCTION__);
        ent_loc = memmem(kernel_buf,kernel_len,rootVPString,39);
        if(!ent_loc) {
            printf("%s: Could not find \"rootvp not authenticated after mounting\" string\n",__FUNCTION__);
            return -1;
        }
        printf("%s: Found \"rootvp not authenticated after mounting\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
        xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
        if(!xref_stuff) {
            printf("%s: Could not find \"rootvp not authenticated after mounting\" xref\n",__FUNCTION__);
            return -1;
        }
        printf("%s: Found \"rootvp not authenticated after mounting\" str xref at %p\n",__FUNCTION__,(void*)xref_stuff);
        addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
        if(!beg_func) {
            printf("%s: Could not find function start\n",__FUNCTION__);
            return -1;
        }
        beg_func = beg_func + 0xA98;
        printf("%s: Found function start at %p\n",__FUNCTION__,(void*)beg_func);
        next_bl = step64(kernel_buf, beg_func, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    } else {
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    }
    printf("%s: Patching ROOTVP at %p\n\n", __FUNCTION__,(void*)(next_bl + 0x4));
    *(uint32_t *) (kernel_buf + next_bl + 0x4) = 0xD503201F;

    return 0;
}

// iOS 15 AMFI Kernel Patch
int get_AMFIInitializeLocalSigningPublicKey_patch(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    char AMFIString[52] = "\"AMFI: %s: unable to obtain local signing public key";
    void* ent_loc = memmem(kernel_buf,kernel_len,AMFIString,51);
    if(!ent_loc) {
        printf("%s: Could not find \"AMFI: %%s: unable to obtain local signing public key\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"AMFI: %%s: unable to obtain local signing public key\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"AMFI: %%s: unable to obtain local signing public key\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"AMFI: %%s: unable to obtain local signing public key ref at %p\n",__FUNCTION__,(void*)xref_stuff);

    printf("%s: Patching \"Local Signing Public Key\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff + 0x4));
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0xD503201F;
    
    return 0;
}

int get_amfi_out_of_my_way_patch(void* kernel_buf,size_t kernel_len) {
    
    printf("%s: Entering ...\n",__FUNCTION__);
    
    void* xnu = memmem(kernel_buf,kernel_len,"root:xnu-",9);
    int kernel_vers = atoi(xnu+9);
    printf("%s: Kernel-%d inputted\n",__FUNCTION__, kernel_vers);
    char amfiString[33] = "entitlements too small";
    int stringLen = 22;
    if (kernel_vers >= 7938) { // Using "entitlements too small" fails on iOS 15 Kernels
        strncpy(amfiString, "Internal Error: No cdhash found.", 33);
        stringLen = 32;
    }
    void* ent_loc = memmem(kernel_buf,kernel_len,amfiString,stringLen);
    if(!ent_loc) {
        printf("%s: Could not find %s string\n",__FUNCTION__, amfiString);
        return -1;
    }
    printf("%s: Found %s str loc at %p\n",__FUNCTION__,amfiString,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!ent_ref) {
        printf("%s: Could not find %s xref\n",__FUNCTION__,amfiString);
        return -1;
    }
    printf("%s: Found %s str ref at %p\n",__FUNCTION__,amfiString,(void*)ent_ref);
    addr_t next_bl = step64(kernel_buf, ent_ref, 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64(kernel_buf, next_bl+0x4, 200, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    if(kernel_vers>3789) { 
        next_bl = step64(kernel_buf, next_bl+0x4, 200, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    }
    addr_t function = follow_call64(kernel_buf, next_bl);
    if(!function) {
        printf("%s: Could not find function bl\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching AMFI at %p\n",__FUNCTION__,(void*)function);
    *(uint32_t *)(kernel_buf + function) = 0x320003E0;
    *(uint32_t *)(kernel_buf + function + 0x4) = 0xD65F03C0;
    return 0;
}

int main(int argc, char **argv) {
    
    printf("%s: Starting...\n", __FUNCTION__);
    
    FILE* fp = NULL;
    
    if(argc < 4){
        printf("Usage: %s <kernel_in> <kernel_out> <args>\n",argv[0]);
        printf("\t-a\t\tPatch AMFI\n");
        printf("\t-s\t\tPatch SPUFirmwareValidation (iOS 15 Only)\n");
        printf("\t-r\t\tPatch RootVPNotAuthenticatedAfterMounting (iOS 15 Only)\n");
        printf("\t-p\t\tPatch AMFIInitializeLocalSigningPublicKey (iOS 15 Only)\n");
        return 0;
    }
    
    void* kernel_buf;
    size_t kernel_len;
    
    fp = fopen(argv[1], "rb");
    if(!fp) {
        printf("%s: Error opening %s!\n", __FUNCTION__, argv[1]);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    kernel_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    kernel_buf = (void*)malloc(kernel_len);
    if(!kernel_buf) {
        printf("%s: Out of memory!\n", __FUNCTION__);
        fclose(fp);
        return -1;
    }
    
    fread(kernel_buf, 1, kernel_len, fp);
    fclose(fp);
    
    if(memmem(kernel_buf,kernel_len,"KernelCacheBuilder",18)) {
        printf("%s: Detected IMG4/IM4P, you have to unpack and decompress it!\n",__FUNCTION__);
        return -1;
    }
    
    if (*(uint32_t*)kernel_buf == 0xbebafeca) {
        printf("%s: Detected fat macho kernel\n",__FUNCTION__);
        memmove(kernel_buf,kernel_buf+28,kernel_len);
    }
    
    for(int i=0;i<argc;i++) {
        if(strcmp(argv[i], "-a") == 0) {
            printf("Kernel: Adding AMFI_get_out_of_my_way patch...\n");
            get_amfi_out_of_my_way_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-s") == 0) {
            printf("Kernel: Adding SPUFirmwareValidation patch...\n");
            get_SPUFirmwareValidation_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-p") == 0) {
            printf("Kernel: Adding AMFIInitializeLocalSigningPublicKey patch...\n");
            get_AMFIInitializeLocalSigningPublicKey_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-r") == 0) {
            printf("Kernel: Adding RootVPNotAuthenticatedAfterMounting patch...\n");
            get_RootVPNotAuthenticatedAfterMounting_patch(kernel_buf,kernel_len);
        }
    }
    
    /* Write patched kernel */
    printf("%s: Writing out patched file to %s...\n", __FUNCTION__, argv[2]);
    
    fp = fopen(argv[2], "wb+");
    if(!fp) {
        printf("%s: Unable to open %s!\n", __FUNCTION__, argv[2]);
        free(kernel_buf);
        return -1;
    }
    
    fwrite(kernel_buf, 1, kernel_len, fp);
    fflush(fp);
    fclose(fp);
    
    free(kernel_buf);
    
    printf("%s: Quitting...\n", __FUNCTION__);
    
    return 0;
}
