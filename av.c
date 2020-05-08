#ifndef AV_INCLUDE
#define AV_INCLUDE
#include "includes/av.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <openssl/md5.h>

#define HASH_SIZE 32
#define BUFFER_SIZE_TINY 64
#define BUFFER_SIZE_BIG 512

#ifndef DT_DIR
extern unsigned char DT_DIR;
#endif

char av_compFunc(void *left, void *right);

void av_Init(av *self, char *signaturesPath){
    self->signaturesPath = signaturesPath;
    self->threatsFound = 0;
    self->sigLoad = 0;
    self->maliciousFileNames = (char **)malloc(10 * sizeof(char *));
    self->maliciousFileNamesCapacity = 0;

    self->hashTree = calloc(1, sizeof(sortedTree));
    sortedTree_Init(self->hashTree, av_compFunc);
}

int av_LoadSignatures(av *self){
    FILE *fp = fopen(self->signaturesPath, "r");
    char *ioBuffer = alloca(BUFFER_SIZE_BIG);
    if(ioBuffer == NULL){
        exit(1);
    }
    setvbuf(fp, ioBuffer, _IOFBF, BUFFER_SIZE_BIG);

    char line[BUFFER_SIZE_TINY];
    int added = 0;
    while (fgets(line, BUFFER_SIZE_TINY, fp))
    {
        char *currentHash = malloc(HASH_SIZE);
        strncpy(currentHash, line, HASH_SIZE);

        sortedTree_Add(self->hashTree, currentHash);
        added++;
    }

    self->sigLoad = 1;
    return added;
}

int av_UnloadSignatures(av *self){
    int res = sortedTree_Release(self->hashTree);

    free(self->hashTree);
    self->hashTree = calloc(1, sizeof(sortedTree));
    sortedTree_Init(self->hashTree, av_compFunc);

    return res;
}

// recives two md5 hashes, strings must be md5 hashes in the same format
// Returns: -1 if left hash is lower than right hash, 1 if vice versa, 0 if they equal
char av_compFunc(void *left, void *right){
    char *sLeft = (char *)left;
    char *sRight = (char *)right;

    char result = 0;

    while (!(*sLeft == '\00' || *sRight == '\00') && result == 0)
    {
        if(*sLeft > *sRight){
            result = -1;
        }
        else if(*sLeft < *sRight){
            result = 1;
        }

        sRight++;
        sLeft++;
    }

    return result;
}

void av_AddMalware(av *self, char *path){
    // if no threts found
    if(self->threatsFound == 0){
        // initialize list
        self->maliciousFileNamesCapacity = 10;
        self->maliciousFileNames = (char **)malloc(self->maliciousFileNamesCapacity * sizeof(char *));
    }
    // TODO: check
    // if we need to reallocate
    else if(self->threatsFound + 1 > self->maliciousFileNamesCapacity){
        self->maliciousFileNamesCapacity += 10;
        self->maliciousFileNames = (char **)realloc(self->maliciousFileNames, self->maliciousFileNamesCapacity);
    }

    self->maliciousFileNames[self->threatsFound] = (char *)malloc(strlen(path));
    strncpy(self->maliciousFileNames[self->threatsFound], path, strlen(path));

    self->threatsFound++;
}

// TODO: if can't read file, skip (signal?)
void av_checksum(char *filename, char *dest, int size){
    unsigned char c[MD5_DIGEST_LENGTH];
    char hexBuffer[1 + MD5_DIGEST_LENGTH*2];
    char *bufferPtr = hexBuffer;
    memset(hexBuffer, 0, sizeof(hexBuffer));
    int i;
    FILE *inFile = fopen (filename, "rb");
    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];

    if (inFile == NULL) {
        fprintf (stderr, "%s can't be opened.\n", filename);
        return;
    }

    MD5_Init (&mdContext);
    while ((bytes = fread (data, 1, 1024, inFile)) != 0)
    MD5_Update (&mdContext, data, bytes);
    MD5_Final (c,&mdContext);
    int wrote = 0;
    int written = 0;
    for(i = 0; i < MD5_DIGEST_LENGTH; i++){
        wrote = sprintf(bufferPtr, "%02x", c[i]);
        bufferPtr += wrote;
        written += wrote;
        if(written > MD5_DIGEST_LENGTH * 2){
            exit(1);
        }
    }
    strncat(bufferPtr, "\00", 1);
    fclose (inFile);

    strncpy(dest, hexBuffer, size);
}

// returns 0 if ok 1 if malicious
int av_CheckFile(sortedTree *hashTree, char *path){
    const int bufSize = 1 + MD5_DIGEST_LENGTH*2;
    char hexBuffer[bufSize];

    av_checksum(path, hexBuffer, bufSize);
    binode *instance = sortedTree_Find(hashTree, hexBuffer);

    return instance == NULL ? 0 : 1;
}

// Searches recursivly in dirPath for viruses, updates self  with any threats
// dirPath: path to directory to search for viruses
void av_SearchViruses_searchDirectory(av *self, char *dirPath){
    DIR *dp = opendir(dirPath);
    struct dirent *ent;

    while((ent = readdir(dp)) != NULL){
        // TODO: change logic
        // directory
        if(ent->d_type == DT_DIR){
            // if . or .. skip
            if( strncmp(ent->d_name, ".", strlen(ent->d_name)) == 0 ||
                strncmp(ent->d_name, "..", strlen(ent->d_name)) == 0){
                continue;
            }
            else{
                // Build New directory path in stack frame
                char *newDirPath = alloca(strlen(dirPath) + 2 + strlen(ent->d_name));
                strcpy(newDirPath, dirPath);
                strcat(newDirPath, "/");
                strcat(newDirPath, ent->d_name);

                av_SearchViruses_searchDirectory(self, newDirPath);
            }
        }
        // regulur file
        else{
            // Build absoulote file name in stack frame
            char *malwarePath = alloca(strlen(dirPath) + 2 + strlen(ent->d_name));
            strcpy(malwarePath, dirPath);
            strcat(malwarePath, "/");
            strcat(malwarePath, ent->d_name);
            char isVirus = av_CheckFile(self->hashTree, malwarePath);
            
            if(isVirus == 1){
                av_AddMalware(self, malwarePath);
            }
        }
    }
}

void av_SearchViruses(av *self, char *path){
    av_SearchViruses_searchDirectory(self, path);
}

#endif