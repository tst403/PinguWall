#include "includes/binode.h"
#include "includes/sortedTree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <alloca.h>

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

//#define DEMO

char sortedTree_tree_funcCompare(void *left, void *right){
    int *nLeft = (int *)left;
    int *nRight = (int *)right;

    return *nLeft > *nRight ? -1 : *nRight > *nLeft ? 1 : 0;
}

void sortedTree_tree_funcIter(void *val){
    int *ptr = (int *)val;
    printf("%d\n", *ptr);
}

// recives two md5 hashes, strings must be md5 hashes in the same format
// Returns: -1 if left hash is lower than right hash, 1 if vice versa, 0 if they equal
char sortedTree_md5HashTree_compFunc(void *left, void *right){
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

void sortedTree_md5HashTree_iterFunc(void *val){
    printf("%s\n", (char*)val);
}

void load_sigs(sortedTree *tree, char *signaturesPath){
    FILE *fp = fopen(signaturesPath, "r");
    char *ioBuffer = alloca(BUFFER_SIZE_BIG);
    if(ioBuffer == NULL){
        exit(1);
    }
    setvbuf(fp, ioBuffer, _IOFBF, BUFFER_SIZE_BIG);

    char line[BUFFER_SIZE_TINY];
    while (fgets(line, BUFFER_SIZE_TINY, fp))
    {
        char *currentHash = malloc(HASH_SIZE);
        strncpy(currentHash, line, HASH_SIZE);

        sortedTree_Add(tree, currentHash);
    }
}

int main(){
    #pragma region demo
    #ifdef DEMO

    // valtype: int
    NewType(sortedTree, tree)
    sortedTree_Init(tree, sortedTree_tree_funcCompare);

    NewType (binode, sortedTree_tree_root)
    tree->root = sortedTree_tree_root;

    NewType (binode, binodeL)
    tree->root->left = binodeL;

    NewType (binode, binodeR)
    tree->root->right = binodeR;

    NewTypeValue(int, intL, 50);
    NewTypeValue(int, intM, 100);
    NewTypeValue(int, intR, 150);

    tree->root->value = intL;
    tree->root->left->value = intM;
    tree->root->right->value = intR;

    NewTypeValue(int, intBig, 2048)
    NewTypeValue(int, intSmall, -2048)

    sortedTree_Add(tree, intBig);
    sortedTree_Add(tree, intSmall);

    sortedTree_Iter(tree->root, sortedTree_tree_funcIter);

    #endif
    #pragma endregion

    NewType(sortedTree, md5HashTree)
    sortedTree_Init(md5HashTree, sortedTree_md5HashTree_compFunc);

    load_sigs(md5HashTree, "/home/dindibo4/av-test/sigs/SIG");
    fprintf(stderr, "[+] %d Signatures loaded\n", md5HashTree->count);

    char smallBuffer[BUFFER_SIZE_SMALL];
    getcwd(smallBuffer, BUFFER_SIZE_SMALL);
    fprintf(stderr, "Searching in folder: %s\n", smallBuffer);

    return 0;
}