#include "sortedTree.h"
#include <stdio.h>

#ifndef INCLUDE_AV_H
#define INCLUDE_AV_H

struct av
{
    sortedTree *hashTree;
    char **maliciousFileNames;
    int threatsFound;
    int maliciousFileNamesCapacity;
    char *signaturesPath;
    char sigLoad;
}typedef av;

enum FILETYPE{
    FILETYPE_ERR,
    FILETYPE_REG,
    FILETYPE_DIR,
};

struct scanResults
{
    int   success;
    int   threatsFound;
    int   filetype;
    char* pathScanned;
}typedef scanResults;

void av_Init(av *self, char *signaturesPath);

int av_LoadSignatures(av *self);

int av_UnloadSignatures(av *self);

void av_SearchViruses(av *self, char *path);

// TODO: remove
int av_CheckFile(sortedTree *hashTree, char *path);

void av_AddMalware(av *self, char *path);

scanResults av_SearchViruses_S(av *self, char *filePath);

void av_saveToFile(av *self);

#endif