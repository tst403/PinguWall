#include "includes/binode.h"
#include "includes/sortedTree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

int main(){
    NewType(av, AV)
    av_Init(AV, "/home/dindibo4/av-test/sigs/SIG");

    int a = av_LoadSignatures(AV);
    fprintf(stderr, "[+] %d Signatures loaded\n", AV->hashTree->count);
    
    fprintf(stderr, "[+] %d\n", av_UnloadSignatures(AV));
    fprintf(stderr, "tree = %p\n", AV);
    fprintf(stderr, "[+] %d Signatures unloaded\n", AV->hashTree->count);

    /*char smallBuffer[BUFFER_SIZE_SMALL];
    getcwd(smallBuffer, BUFFER_SIZE_SMALL);
    fprintf(stderr, "[*] Searching in folder: %s\n", smallBuffer);*/

    // TODO: child search for viruses

    return 0;
}