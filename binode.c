#ifndef INCLUDE_BINODE
#define INCLUDE_BINODE

#include "includes/binode.h"

void free(binode *self){
    if(self->value != (void *)0){
        free(self->value);
    }
    if(self->left != (void *)0){
        free(self->left);
    }
    if(self->right != (void *)0){
        free(self->right);
    }
}
#endif