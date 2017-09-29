/*
*   CMTSMIC cracker. Cracks CMTS mics. Uses a wordlist
*   Compile with: gcc -Wall cmtscrack.c -o cmtscrack -lcrypto -lpthread
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>

int DEBUG = 0;
int found = 0;
int threads = 4;
unsigned char OriginalCmMic[17];
unsigned char OriginalCmtsMic[17];
unsigned char *cmts_tlvs;
int cmtstlvsSize;
unsigned long attempts;

struct bruteforcer_args {
    size_t start;
    size_t end;
    char * filename;
};

void md5_print_digest(unsigned char * digest){
    int i;

    for (i=0; i<16 ; i++){
        printf ("%02x", digest[i] );
    }
    printf("\n");
}

int crack(char * key){
    int key_len = strlen(key);
    unsigned char k_ipad[65];    // inner padding 
    unsigned char k_opad[65];    // outer padding 
    unsigned char tmpdigest[16];
    unsigned char zedigest[17];
    MD5_CTX tctx;
    MD5_CTX context;
    size_t i = 0;

    memset (k_ipad, 0x36, sizeof(k_ipad));
    memset (k_opad, 0x5c, sizeof(k_opad));
    
    MD5_Init(&tctx);
    MD5_Update(&tctx, key, key_len);
    MD5_Final(tmpdigest,&tctx);

    if(DEBUG){
        printf("Current string: '"); 
        for (i = 0; i < key_len; i++){
            printf("%c", key[i]);
        }
        printf("'\n");
    }

    for (i = 0; i<key_len; i++){
        k_ipad[i] = key[i] ^ 0x36;
        k_opad[i] = key[i] ^ 0x5c;
    }   

    MD5_Init(&context);                   
    MD5_Update(&context, k_ipad, 64);     
    MD5_Update(&context, cmts_tlvs, cmtstlvsSize); 
    MD5_Final(zedigest, &context);          

    MD5_Init(&context);                   
    MD5_Update(&context, k_opad, 64);     
    MD5_Update(&context, zedigest, 16);                                      
    MD5_Final(zedigest,&context);          

    attempts++;
    return memcmp(zedigest, OriginalCmtsMic, 16 );
}

void * bruteforcer(void * ptr){
    struct bruteforcer_args *args = (struct bruteforcer_args *)ptr;
    size_t start = args->start;
    size_t end = args->end;
    char * line;
    size_t len = 0;
    ssize_t read;

    FILE * fp = fopen(args->filename, "rb");
    if(!fp){
        printf("[!] Could not open %s!\n", args->filename);
        exit(1);
    }
    fseek(fp, start, SEEK_SET);

    while ((read = getline(&line, &len, fp)) != -1) {
        if(ftell(fp) >= end){
        //  printf("[.] Thread completed");
            break;
        }

        line[strcspn(line, "\n")] = 0;
        if(strlen(line)>64){
            continue;
        }
    //  printf("%s", line);

        if(crack(line) == 0){
            printf("\n[+] Found key: %s\n", line);
            found = 1;
            break;
            //exit(0);
        }
    }

    fclose(fp);
    threads--;
    pthread_exit(NULL);
}

int main(int argc, char ** argv){
    FILE *fp;
    unsigned char *FileBuffer;
    unsigned char cm_mic[17];
    size_t result;
    MD5_CTX mdContext; 
    unsigned char digest[17];
    register unsigned char *cp, *dp; 
    size_t i = 0;
    int offsetEnd = 1;

    if (argc <3) 
    {
        printf("USAGE: cmtscrack config.cm wordlist\n\n");
        exit (2);
    }

    fp = fopen(argv[1], "rb"); // open Cable modem Configuration file
    if(!fp){
         printf("[!] Could not open %s!\n", argv[1]);
         exit(1);
    }

    fseek(fp, 0, SEEK_END);
    int FileSize = ftell(fp);
    rewind(fp);

    FileBuffer = (unsigned char*) malloc((sizeof(char)*FileSize));
    if (FileBuffer == NULL) {printf ("Error allocating memory!\n"); exit (2);}

    result = fread (FileBuffer, 1, FileSize, fp);
    if (result != FileSize) { printf("Error reading file\n"); exit(2);}

    fclose(fp);

    //Copy CmMic from file
    memcpy(cm_mic, FileBuffer+(FileSize - 34 - offsetEnd), 16);

    //Copy CmtsMic from file
    memcpy(OriginalCmtsMic, FileBuffer+(FileSize - 16 - offsetEnd ), 16);   

    //Calculate CmMic for file
    MD5_Init (&mdContext); 
    MD5_Update (&mdContext, FileBuffer, FileSize - 36 - offsetEnd); 
    MD5_Final (digest, &mdContext); 

    printf("[.] CmtsMic: ");
    md5_print_digest (OriginalCmtsMic);

    if ( memcmp(digest, cm_mic,16 ) !=0 )
    {
        printf("Error bad CmMic !!!\n");
        printf("Calculate CmMic: ");
        md5_print_digest (digest);
        exit(1);
    }

    #define NR_CMTS_MIC_TLVS 21 
    unsigned char digest_order[NR_CMTS_MIC_TLVS] = { 1, 2, 3, 4, 17, 43, 6, 18, 19, 20, 22, 23, 24, 25, 28, 29, 26, 35, 36, 37, 40 }; 

    cmts_tlvs = (unsigned char *) malloc (FileSize - 22); 
    dp = cmts_tlvs; 

    for (i = 0; i < NR_CMTS_MIC_TLVS; i++)
    {
        cp = FileBuffer;
        while ((unsigned int) (cp - FileBuffer) < (FileSize - 23 ))
        {
            if (cp[0] == digest_order[i])
            {
                memcpy (dp, cp, cp[1] + 2);
                dp = dp + cp[1] + 2;
                cp = cp + cp[1] + 2;
            }
            else { 

                if ( cp[0] == 64 ) 
                { 
                    printf("warning: TLV64 (length > 255) not allowed in DOCSIS config files\n");
                    cp = cp + (size_t) ntohs(*((unsigned short *)(cp+1))) + 3;
                } else {
                    cp = cp + cp[1] + 2;
                }
            }
        }
    }  

    free(FileBuffer);

    cmtstlvsSize = dp - cmts_tlvs;

    // load the wordlist.
    fp = fopen(argv[2], "rb");
    if(!fp){
        printf("[!] Could not open %s!\n", argv[2]);
        exit(1);
    }

    fseek(fp, 0, 2);
    size_t size = ftell(fp);
    size_t end;
    size_t start = 0;
    char c;
    printf("[.] Wordlist size : %ld\n", size);
    //rewind(fp);


    for(i = 0; i < threads; i++){

        // trim the file:
        end = size / threads * (i+1);
        fseek(fp, end, SEEK_SET);
        if(threads > 1){
            while((c = fgetc(fp))){
                end++;
                if(c == 0x0a)
                    break;
            } 
        }
        printf("[.] Thread: %ld, Wordlist Start: %ld, Wordlist End: %ld\n", i, start, end);
        
        struct bruteforcer_args args;
        args.filename = argv[2];
        args.start = start;
        args.end = end;

        pthread_t thread;
        int rc = pthread_create(&thread, NULL, bruteforcer, &args);
        if(rc > 0){
            printf("[!] Could not spawn thread!\n");
            return 1;
        }
        
        start = end + 1;
    }

    char spinner[4] = "|/-\\";
    int si = 0;

    while(1){
        usleep(5000);
        if(found == 1){
            printf("\n");
            break;
        }
        else if(threads == 0){
            printf("[.] Threads completed, password not found\n");
            break;
        }
  
        printf("[%c] attempts: %lu\r", spinner[si],  attempts);
        si++;
        if(si == 4)
            si = 0;
    }

    printf("[.] Done\n");
    return 1;
}
