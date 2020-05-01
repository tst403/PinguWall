#ifndef INCLUDE_BINNODE_H
#define INCLUDE_BINNODE_H

#define Binode_Init(NAME) binode *NAME = malloc(sizeof(binode));\
NAME->value = NULL;\
NAME->left = NULL;\
NAME->right = NULL;\

#define Binode_FREE(NAME) Binode_free(NAME);\
if (NAME != (void *)0){\
    free(NAME);\
}\

struct binode
{
    void *value;
    struct binode *left;
    struct binode *right;
} typedef binode;

void Binode_free(binode *self);
#endif