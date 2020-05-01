#include <stdlib.h>

#ifndef INCLUDE_SORTED_TREE
#define INCLUDE_SORTED_TREE
#include "includes/sortedTree.h"

int sortedTree___Add(binode *node, void *val, char(*funcCompare)(void *left, void *right) ){
    // compare us to target
    char cmp = (*funcCompare)(val, node->value);

    // if target is higher than us
    if(cmp == 1){
        // append to left
        if(node->left == NULL){
            // create the new node on heap
            binode *newNode = calloc(1, sizeof(binode));
            newNode->value = val;
            newNode->left = NULL;
            newNode->right = NULL;

            node->left = newNode;
            return 0;
        }
        else{
            return sortedTree___Add(node->left, val, funcCompare);
        }
    }
    // if we are higher than target
    else if(cmp == -1) {
        // append to right
        if(node->right == NULL){
            // create the new node on heap
            binode *newNode = calloc(1, sizeof(binode));
            newNode->value = val;
            newNode->left = NULL;
            newNode->right = NULL;

            node->right = newNode;
            return 0;
        }
        else{
            return sortedTree___Add(node->right, val, funcCompare);
        }
    }
    // on equal
    else if(cmp == 0){
        return 0;
    }

    return 1;
}

void sortedTree_Add(sortedTree *self, void *val){
    // if first
    if(self->root == NULL){
        self->root = calloc(1, sizeof(binode));

        self->root->value = val;
        self->root->left = NULL;
        self->root->right = NULL;

        self->count++;
    }
    else{
        if(sortedTree___Add(self->root, val, self->funcCompare) != 0){
            exit(1);
        }
        else{
            self->count++;
        }
    }
}

void sortedTree_Init(sortedTree *self,  char(*funcCompare)(void *left, void *right)){
    self->count = 0;
    self->funcCompare = funcCompare;
    self->root = NULL;
}

void sortedTree_Iter(binode *node, void(*iterFunc)(void *val)){

    if(node->left != NULL){
        sortedTree_Iter(node->left, iterFunc);
    }

    (*iterFunc)(node->value);

    if(node->right != NULL){
        sortedTree_Iter(node->right, iterFunc);
    }

}

binode *sortedTree___Find(binode *node, void *search, char(*funcCompare)(void *left, void *right)){
    
    binode *ptr = node;
    char cmp;

    while(ptr->value != search && ptr != NULL){
        cmp = (*funcCompare)(ptr->value, search);

        // if current value is lower, search right
        if(cmp == 1){
            if(ptr->right != NULL){
                ptr = ptr->right;
            }
            else{
                ptr = NULL;
            }
        }
        // if current value is higher, search left
        else if(cmp == -1){
            if(ptr->left != NULL){
                ptr = ptr->left;
            }
            else{
                ptr = NULL;
            }
        }
        else if(cmp == 0){
            return ptr;
        }
        else{
            ptr = NULL;
        }
    }

    return ptr;
}

binode *sortedTree_Find(sortedTree *self, void *search){
    binode *ptr = sortedTree___Find(self->root, search, self->funcCompare);
    return ptr;
}


#endif