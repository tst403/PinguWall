#include "binode.h"

struct sortedTree
{
    binode *root;
    unsigned int count;
    // returns -1 if left is "higher" than right, 1 if right is Higher than left. 0 if equal
    char (*funcCompare)(void *left, void *right);
} typedef sortedTree;

void sortedTree_Init(sortedTree *self,  char(*funcCompare)(void *left, void *right));

void sortedTree_Add(sortedTree *self, void *val);

// TODO: Change to self
void sortedTree_Iter(binode *node, void(*iterFunc)(void *val));

binode *sortedTree_Find(sortedTree *self, void *search);