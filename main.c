#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <wait.h>
#include <time.h>


#include "includes/binode.h"
#include "includes/sortedTree.h"
#include "includes/av.h"

#define NewType(TYPE, NAME) TYPE *NAME = malloc(sizeof(TYPE));

#define STDERR_WRITE(STRING) write(2, STRING, strlen(STRING))

#define NewTypeValue(TYPE, NAME, VALUE) TYPE *NAME = malloc(sizeof(TYPE));\
*NAME=VALUE;\

#define PRINT_HEADERS(START, END, HEADERS) for(int i = START; i<=END;i++){\
printf("[%d] - %s\n", i + 1, HEADERS[i]);\
}

#define PROMPT_HEADERS(DEST, START, END, HEADERS)\
PRINT_HEADERS(START, END, HEADERS)\
do{\
write(1, "Selection> ", sizeof("Selection> "));\
scanf("%d", &DEST);\
DEST--;\
}\
while (!(DEST >= START && DEST <= END));

#define PRINT_RED     printf("\033[0;31m"); 
#define PRINT_RED_B   printf("\033[1;31m"); 
#define PRINT_GREEN   printf("\033[0;32m"); 
#define PRINT_GREEN_B printf("\033[1;32m");
#define PRINT_RESET   printf("\033[0m");
#define PRINT_BLUE    printf("\033[0;34m"); 

#define HASH_SIZE 32

#define BUFFER_SIZE_TINY 64
#define BUFFER_SIZE_SMALL 128
#define BUFFER_SIZE_MEDIUM 256
#define BUFFER_SIZE_BIG 512


// Enums

enum SELECTION{
    SCAN,
    EXIT,
} typedef SELECTION;

enum SELECTION_SCAN{
    SCAN_DIRECTORY,
    SCAN_FILE,
    SCAN_EXIT,
} typedef SELECTION_SCAN;


// Structs

struct lastResult
{
    scanResults result;
    char        canOverride;
}typedef lastResult;

// Globals

void show_menu();
int fds[2];
lastResult lResult;
pid_t pid;
av *AV;
const char *SELECTION_HEADERS[] = {"Scan a file or directory", "Exit"};
const char *SELECTION_SCAN_HEADERS[] = {"Directory (recursively)", "File", "Exit"};
pid_t option_scan();
void option_exit();
void sigHandler(int signo);
const void(*SELECTION_HANDLERS[])() = {option_scan, option_exit};

static void initLastResult(){
    lResult.canOverride = 1;
    memset(&(lResult.result), 0, sizeof(lResult.result));
}

static void updateLastResult(scanResults res){
    volatile int a = 0;

    while(lResult.canOverride != 1){
        a++;
        a--;
    }

    lResult.canOverride = 0;
    memcpy(&(lResult.result), &res, sizeof(res));
}

static void releaseLastResult(){
    free(lResult.result.pathScanned);
    lResult.canOverride = 1;
}

char sortedTree_tree_funcCompare(void *left, void *right){
    int *nLeft = (int *)left;
    int *nRight = (int *)right;

    return *nLeft > *nRight ? -1 : *nRight > *nLeft ? 1 : 0;
}

void init(){
    // if no signatures file, exit
    if(access("./sigs", F_OK) == -1){
        puts("Missing signatures file, run setup.sh");
        exit(1);
    }

    initLastResult();

    AV = (av *)malloc(sizeof(av));
    av_Init(AV, "./sigs");

    if(av_LoadSignatures(AV) > 0){
        PRINT_GREEN
        fprintf(stdout, "[+] %d Signatures loaded\n", AV->hashTree->count);
        PRINT_RESET
    }
    else{
        puts("LoadSignatures: Unable to load signatures");
        exit(1);
    }
    if(AV == NULL){
        puts("av: Unable to initialize antivirus");
        exit(1);
    }
}

void show_help(){
    puts("Usage: PinguAV [Options] {file or directory}");
    puts("Scan options:");
    puts("\t-f: scan file instead of directory");
    puts("MISC:");
    puts("\t--help: this screen");
}

void prompt_delete(char *path){
    printf("Deleting the file %s might resolve the problem\nDo you wish to delete it now?\n", path);
    char choise;
    choise = getc(stdin);
    getc(stdin);
    while (choise != 'y' && choise != 'n' &&
    choise != 'Y' &&  choise != 'N')
    {
        puts("Enter [y/n]");
        choise = getc(stdin);
        getc(stdin);
    }
    if(choise == 'y' || choise == 'Y'){
        if(remove(path)){
            puts("Malicious file removed");
        }
        else{
            printf("can't remove %s\n", path);
        }
    }
}

void start_scan(char *path, SELECTION_SCAN type, int fileIndex, int argc){
    if(type == SCAN_DIRECTORY){
        av_SearchViruses(AV, path);
        printf("Scan complete.\nFound %d Threats!\n", AV->threatsFound);
    }
    else{
        // if no file provided
        if(argc -1 == fileIndex){
            puts("No file provided");
            exit(1);
        }
        else{
            char isVirus = av_CheckFile(AV->hashTree, path);
            if(isVirus == 1){
                printf("%s is malicious!\n", path);
                prompt_delete(path);
            }
            else{
                printf("%s is OK\n", path);
            }
        }
    }
}

pid_t option_scan(){
    /*int  select;
    char filePath[BUFFER_SIZE_SMALL];
    char absoluteFilePath[BUFFER_SIZE_SMALL];

    PROMPT_HEADERS(select, SCAN_DIRECTORY, SCAN_EXIT, SELECTION_SCAN_HEADERS)

    switch(select){
        case SCAN_DIRECTORY:
        {
            puts("Enter directory path:");

            break;
        }
        case SCAN_FILE:
        {
            puts("Enter file path:");
        }
        default:
        {
            return;
        }
    }

    getc(stdin);
    fgets(filePath, BUFFER_SIZE_SMALL, stdin);
    realpath(filePath, absoluteFilePath); 
    removeLastCharecter(absoluteFilePath, '/');

    // If file exists
    if(1==2 && access(absoluteFilePath, F_OK) == -1){
        puts("No such file or directory");
    }
    // TODO: Check what happens if file is dir
    else{
        
        if(select == SCAN_FILE){
            char isVirus = av_CheckFile(AV->hashTree, absoluteFilePath);
            
            if(isVirus == 1){
                av_AddMalware(AV, absoluteFilePath);
            }
        }
        else{
            av_SearchViruses(AV, absoluteFilePath);
        }

    }*/

    pid_t scanPID;
    scanResults result;
    char fileName[BUFFER_SIZE_SMALL];
    show_menu();
    fgets(fileName, BUFFER_SIZE_SMALL, stdin);
    printf("Starting scan at %s", fileName);

    pipe(fds);
    scanPID = fork();

    if(scanPID == 0){
        result = av_SearchViruses_S(AV, fileName);
        int  pathLength = strlen(result.pathScanned);
        av_saveToFile(AV);

        write(fds[1], &result, sizeof(result));
        write(fds[1], &pathLength, sizeof(pathLength));
        write(fds[1], result.pathScanned, pathLength);
        fflush(NULL);

        free(result.pathScanned);
        exit(result.success == 1 ? 0 : 1);
    }
    else{
        return scanPID;
    }

}

void option_exit(){
    exit(0);
}

void show_menu(){
    PRINT_BLUE
    putc(10, stdout);
    printf("scan>\nEnter file or directory : \n");
    PRINT_RESET
}

int main(int argc, char *argv[]){
    init();
    /*pid_t pid;

    int select;
    do
    {
        PROMPT_HEADERS(select, SCAN, EXIT, SELECTION_HEADERS)
        //SELECTION_HANDLERS[select]();
        int result = -1;
        pid = fork();

        // If child
        if(pid == 0){
            result = fake();
            exit(0);
        }
        else{
            printf("%d\n", result);
        }
    }
    while(select != EXIT);*/

    while(1){
        pid = option_scan();
        signal(SIGCHLD, sigHandler);
    }

    return 0;
}

void sigHandler(int signo){
    if(signo == SIGCHLD){
        scanResults result;
        int  a;
        int  pathLength;
        char *pathStr;

        pid_t finished = wait(&a);

        read(fds[0],&result, sizeof(result));
        read(fds[0],&pathLength, sizeof(pathLength) + 1);

        if(!(pathLength > 0 && pathLength < 129)){
            exit(1);
        }
        
        pathStr = (char*)malloc(pathLength + 1);
        read(fds[0],pathStr, pathLength);
        pathStr[pathLength] = '\x00';
        
        result.pathScanned = pathStr;

        updateLastResult(result);
        printf("finished scan from: %s\n", lResult.result.pathScanned);
        printf("threats found: %d\n", lResult.result.threatsFound);
        releaseLastResult();

        // Problematic!
        if(finished == pid){
            if(a == 0){
                puts("Scan complete");
            }
            else{
                puts("Scan failed");
            }
        }

        show_menu();
        printf("%d\n", AV->threatsFound);
    }
}

// https://stackoverflow.com/questions/49581349/how-to-get-return-value-from-child-process-to-parent