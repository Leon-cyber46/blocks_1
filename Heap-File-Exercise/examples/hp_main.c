#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "bf.h"
#include "hp_file_structs.h"
#include "hp_file_funcs.h"

#define RECORDS_NUM 10000 // you can change it if you want
#define FILE_NAME "data.db"

#define CALL_OR_DIE(call)     \
  {                           \
    BF_ErrorCode code = call; \
    if (code != BF_OK) {      \
      BF_PrintError(code);    \
      exit(code);             \
    }                         \
  }


void insert_records(){

  int file_handle;
  HeapFileHeader* header_info=NULL;
  HeapFile_Open(FILE_NAME, &file_handle,&header_info);
  srand(12569874);
  printf("Insert records\n");
  for (int id = 0; id < RECORDS_NUM; ++id) {
    HeapFile_InsertRecord(file_handle,header_info, randomRecord());
  }
  HeapFile_Close(file_handle,header_info);
}

void search_records(){
  int file_handle;
  HeapFileHeader* header_info=NULL;
  HeapFile_Open(FILE_NAME, &file_handle,&header_info);
  int id = 168;
  printf("Print records with id=%d\n",id);
  HeapFileIterator iterator = HeapFile_CreateIterator(file_handle,header_info,168);
  Record ans;
  Record* answer = &ans;

  do {
    HeapFile_GetNextRecord(&iterator, &answer);
    if (answer != NULL) {
      printRecord(*answer);
    }
  } while (answer != NULL);

  HeapFile_Close(file_handle,header_info);
  free(answer);
}


int main() {
  BF_Init(LRU);
  HeapFile_Create(FILE_NAME);
  insert_records();
  search_records();

  BF_Close();
}
