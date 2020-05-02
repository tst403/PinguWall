#ifndef INCLUDE_BINODE
#define INCLUDE_BINODE

#define DONT_USE_FREE

#include "includes/binode.h"

#ifndef DONT_USE_FREE
// TODO: make use
void __free(binode *self){
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
#endif