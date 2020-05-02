#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "includes/binode.h"
#include "includes/sortedTree.h"
#include "includes/av.h"

#define NewType(TYPE, NAME) TYPE *NAME = malloc(sizeof(TYPE));

#define STDERR_WRITE(STRING) write(2, STRING, strlen(STRING))

#define NewTypeValue(TYPE, NAME, VALUE) TYPE *NAME = malloc(sizeof(TYPE));\
*NAME=VALUE;\

#define HASH_SIZE 32

#define BUFFER_SIZE_TINY 64
#define BUFFER_SIZE_SMALL 128
#define BUFFER_SIZE_MEDIUM 256
#define BUFFER_SIZE_BIG 512

const char *STRING_LOAD_SIGS = "[+] Signatures loaded\n";

char sortedTree_tree_funcCompare(void *left, void *right){
    int *nLeft = (int *)left;
    int *nRight = (int *)right;

    return *nLeft > *nRight ? -1 : *nRight > *nLeft ? 1 : 0;
}

void search_file(char *path);

int main(){
    NewType(av, AV)
    av_Init(AV, "../../../av-test/sigs/SIG");

    av_LoadSignatures(AV);
    fprintf(stderr, "[+] %d Signatures loaded\n", AV->hashTree->count);

    char path[256];
    getcwd(path, 256);

    printf("Starting scan at %s ...\n", path);    
    av_SearchViruses(AV, path);

    printf("Scan complete.\nFound %d Threats!\n", AV->threatsFound);


    // TODO: child search for viruses

    return 0;
}