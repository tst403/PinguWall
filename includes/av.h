#include "sortedTree.h"

#ifndef INCLUDE_AV_H
#define INCLUDE_AV_H

struct av
{
    sortedTree *hashTree;
    char **maliciousFileNames;
    int threatsFound;
    char *signaturesPath;
    char sigLoad;
}typedef av;

void av_Init(av *self, char *signaturesPath);

int av_LoadSignatures(av *self);

int av_UnloadSignatures(av *self);

#endif