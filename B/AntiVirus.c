#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
} virus;

typedef struct link {
    struct link *nextVirus;
    virus *vir;
} link;

void PrintHex(unsigned char* buffer, size_t length, FILE* output){
    for (size_t i = 0; i < length; i++) {
        fprintf(output, "%02X ", buffer[i]);
  }
}


virus* readVirus(FILE* infile){
    virus* v = malloc(sizeof(virus));
    if (v == NULL) {
        printf("could not allocate memory for virus");
        return NULL;
    }
    if (fread(&(v->SigSize) , 1, 18, infile) != 18) {
        free(v);
        return NULL;
    } 
    v->sig = malloc(v->SigSize);
    if(fread(v->sig,1,v->SigSize,infile) != (size_t)v->SigSize) {
        free(v->sig);
        free(v);
        return NULL;
    }
    return v;
}

void printVirus(virus* virus, FILE* output){
    fprintf(output,"Virus name: %s\n", virus->virusName);
    fprintf(output,"Virus size: %u\nSignature:\n", virus->SigSize);
    PrintHex(virus->sig,virus->SigSize,output);
    fprintf(output,"\n\n");   
}

void list_print(link *virus_list, FILE* output){
    if(virus_list->nextVirus!= NULL) 
        list_print(virus_list->nextVirus,output);
    if(virus_list->vir != NULL) 
        printVirus(virus_list->vir,output);
}

link* list_append(link* virus_list, virus* data){
    link *newLink=malloc(sizeof(link));
    newLink->vir=data;
    newLink->nextVirus = virus_list;
    return newLink;
}

void list_free(link *virus_list) {
    if(virus_list->nextVirus)
        list_free(virus_list->nextVirus);
    free(virus_list->vir->sig);
    free(virus_list->vir);
    free(virus_list);
}

link* virus_list = NULL;

void loadSignatures() {
    char input [100];
    printf("enter a file name: ");
    if (fgets(input , 100 , stdin) == NULL){
        printf("\ncouldn't get file's name");
        exit(1);
    }
    input[strcspn(input, "\n")] = '\0';
    FILE* signatures=fopen(input, "rb");
    if( signatures== NULL){
        printf("\ncouldn't load the file");
        exit(1);
    }
    char magicNumber[5];
    fread(magicNumber , 1 , 4 , signatures);
    magicNumber[4] = '\0';
    if(strcmp(magicNumber, "VISL") != 0) {
        printf("wrong magic number\n");
        exit(1);
    }
    virus* v= readVirus(signatures);
    while(v!=NULL){
        virus_list=list_append(virus_list,v);
        v=readVirus(signatures);
    }
    fclose(signatures);
    free(v);
}

void printSignatures(){
    if(virus_list!=NULL){
        list_print(virus_list, stdout);
    }
}

void detect_virus(char *buffer, unsigned int size, link *virus_list){
    link *curr=virus_list;
    while(curr !=  NULL){
        unsigned short sigSize= curr->vir->SigSize;
        for(int i=0; i<size-sigSize; i++){
            if(memcmp(buffer+i,curr->vir->sig,sigSize) == 0){
                printf("Starting byte location: %d\nVirus name: %s\nVirus signature size: %d\n\n", i, curr->vir->virusName, sigSize);
            }
        }
        curr = curr->nextVirus;
    }
}

void detectViruses(char* fileName){
    FILE* file=fopen(fileName, "rb");
    if(file == NULL){
        printf("couldn't open file");
        exit(1);
    }
    char buffer[10000];
    unsigned int bytesRead = fread(buffer,1,10000,file);
    detect_virus(buffer, bytesRead,virus_list);
    fclose(file);
}


void neutralize_virus(char *fileName , int signatureOffset) {
    char action = '\xC3';
    FILE* file = fopen(fileName , "r+b");
    if(file == NULL) 
        exit(1);
    fseek(file , signatureOffset , SEEK_SET);
    fwrite(&action, sizeof(action) , 1 , file);
    fclose(file);
}

void fixFile(char *fileName){
    FILE* file=fopen(fileName, "rb");
    if(file == NULL){
        printf("couldn't open file");
        exit(1);
    }
    char buffer[10000];
    unsigned int bytesRead = fread(buffer,1,10000,file);
    link *curr = virus_list;
    while(curr !=  NULL){
        unsigned short sigSize= curr->vir->SigSize;
        for(int i=0; i<bytesRead-sigSize; i++){
            if(memcmp(buffer+i,curr->vir->sig,sigSize) == 0){
                neutralize_virus(fileName , i);
            }
        }
        curr = curr->nextVirus;
    }
    fclose(file);
}



void quit(){
    if(virus_list != NULL){
        list_free(virus_list);
    }
    exit(0);
}



struct fun_desc {
char *name;
void (*fun)(char*);
};   

struct fun_desc menu[] =  {
    {NULL , NULL},
    {"Load Signatures" , loadSignatures} ,
    {"Print Signatures" , printSignatures} ,
    {"Detect Viruses" , detectViruses} ,
    {"Fix File" , fixFile} ,
    {"Quit" , quit} 
};


int main(int argc , char **argv) {
    char *file = argv[1];
    char input[100];
    int len = sizeof(menu) / sizeof(menu[1]);
    while(1) {
        printf("Select operation from the following menu:\n");
        for(int i = 1 ; i < len ; i++) {
            printf("%d",i);
            printf(")");
            printf("%s\n" , menu[i].name);
        }
        printf("Please choose a function by its number\nOption: ");
        if (fgets(input , 100 , stdin) == NULL)
            exit(1);
        int user_choice = atoi(input);
        if (1 <= user_choice && user_choice < len)
            menu[user_choice].fun(file);
        else
            printf("Not within bounds");
    }
    list_free(virus_list);
    return 0;
}
