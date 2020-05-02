#ifndef AV_INCLUDE
#define AV_INCLUDE
#include "includes/av.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define HASH_SIZE 32
#define BUFFER_SIZE_TINY 64
#define BUFFER_SIZE_BIG 512

char av_compFunc(void *left, void *right);

void av_Init(av *self, char *signaturesPath){
    self->signaturesPath = signaturesPath;
    self->threatsFound = 0;
    self->sigLoad = 0;
    self->maliciousFileNames = (char **)malloc(10 * sizeof(char *));

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
    sortedTree_Release(self->hashTree);
    self->sigLoad = 0;
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

#endif