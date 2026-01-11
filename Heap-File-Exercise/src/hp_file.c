#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bf.h"
#include "hp_file_structs.h"
#include "record.h"

#define CALL_BF(call)         \
  {                           \
    BF_ErrorCode code = call; \
    if (code != BF_OK)        \
    {                         \
      BF_PrintError(code);    \
      return 0;        \
    }                         \
  }

int HeapFile_Create(const char* fileName)
{
  int fd;
  BF_Block *block;
  char *data;
  HeapFileHeader *hdr;

  CALL_BF(BF_CreateFile(fileName));                      

  CALL_BF(BF_OpenFile(fileName, &fd));                     

  BF_Block_Init(&block);                                   

  CALL_BF(BF_AllocateBlock(fd, block));                    

  data=BF_Block_GetData(block);                           
  memset(data, 0, BF_BLOCK_SIZE);                          

  hdr=(HeapFileHeader*) data;
  hdr->magic[0]='H'; hdr->magic[1]='P'; hdr->magic[2]='F'; hdr->magic[3]='1';   // file tag
  hdr->version=1;
  hdr->record_size= (int)sizeof(Record);
  hdr->total_blocks=1;      // μόνο block 0 υπάρχει
  hdr->last_data_block=0;      

  BF_Block_SetDirty(block);       // τροποποιημένο block 0 άρα dirty

  CALL_BF(BF_UnpinBlock(block));    // unpin block 0
                                                    
  BF_Block_Destroy(&block);                                                           

  CALL_BF(BF_CloseFile(fd));                                                           

  return 1;
}

int HeapFile_Open(const char *fileName, int *file_handle, HeapFileHeader **header_info)
{
  if (!fileName || !file_handle || !header_info) return 0;

  CALL_BF(BF_OpenFile(fileName, file_handle));

  BF_Block *block;
  BF_Block_Init(&block);

  if (BF_GetBlock(*file_handle, 0, block) != BF_OK) // pin για ανάγνωση
  {   
    BF_Block_Destroy(&block);
    BF_CloseFile(*file_handle);
    return 0;
  }

  char *data=BF_Block_GetData(block);
  HeapFileHeader *on_disk=(HeapFileHeader *)data;

 
  const char expected_magic[4]={'H','P','F','1'};
  if (memcmp(on_disk->magic, expected_magic, 4) != 0 ||
      on_disk->record_size != (int)sizeof(Record) ||
      on_disk->total_blocks < 1 ||                
      on_disk->last_data_block < 0 ||             
      on_disk->last_data_block >= on_disk->total_blocks) 
  {

    BF_UnpinBlock(block);
    BF_Block_Destroy(&block);
    BF_CloseFile(*file_handle);
    return 0;
  }

  HeapFileHeader *hdr=malloc(sizeof(*hdr));
  if (!hdr) 
  {
    BF_UnpinBlock(block);
    BF_Block_Destroy(&block);
    BF_CloseFile(*file_handle);
    return 0;
  }
  memcpy(hdr, on_disk, sizeof(*hdr));   // copy στη ram
  *header_info=hdr;

  CALL_BF(BF_UnpinBlock(block));        // unpin αφού διαβάσαμε
  BF_Block_Destroy(&block);

  
  return 1;
}

int HeapFile_Close(int file_handle, HeapFileHeader *hp_info)
{
  BF_Block *block;
  BF_Block_Init(&block);

  if (BF_GetBlock(file_handle, 0, block) != BF_OK)  // pin για update
  { 
    BF_Block_Destroy(&block);
    return 0;
  }

  char *data=BF_Block_GetData(block);
  memcpy(data, hp_info, sizeof(HeapFileHeader));    // ενημέρωση του header
  BF_Block_SetDirty(block);        // τροποποιημένο block

  if (BF_UnpinBlock(block) != BF_OK) // unpin του block 0
  {    
    BF_Block_Destroy(&block);
    return 0;
  }

  BF_Block_Destroy(&block);

  if (BF_CloseFile(file_handle) != BF_OK) {
    return 0;
  }

  free(hp_info);
  return 1;
}

int HeapFile_InsertRecord(int file_handle, HeapFileHeader *hp_info, const Record record)
{
  BF_Block *block;
  BF_Block_Init(&block);

  int target_block=hp_info->last_data_block;
  if (target_block == 0) 
  {
    if (BF_AllocateBlock(file_handle, block) != BF_OK) 
    {
      BF_Block_Destroy(&block);
      return 0;
    }
    char *data=BF_Block_GetData(block);
    memset(data, 0, BF_BLOCK_SIZE);
    int *count=(int *)data;
    *count=0;
    BF_Block_SetDirty(block);
    if (BF_UnpinBlock(block) != BF_OK)
    {
      BF_Block_Destroy(&block);
      return 0;
    }

    // ενημέρωση του header
    target_block=1;   // το νέο block είναι το block 1 (block 0 είναι το header)
    hp_info->last_data_block=1;
    hp_info->total_blocks++;

    if (BF_GetBlock(file_handle, 0, block) != BF_OK)
    {
      BF_Block_Destroy(&block);
      return 0;
    }
    char *hdata=BF_Block_GetData(block);
    memcpy(hdata, hp_info, sizeof(HeapFileHeader));
    BF_Block_SetDirty(block);
    if (BF_UnpinBlock(block) != BF_OK) {
      BF_Block_Destroy(&block);
      return 0;
    }
  }

  if (BF_GetBlock(file_handle, target_block, block) != BF_OK) {
    BF_Block_Destroy(&block);
    return 0;
  }

  char *data=BF_Block_GetData(block);    // pointer στο block 
  int *count=(int *)data;                // αριθμός των records στο block
  int max_records=(BF_BLOCK_SIZE - (int)sizeof(int)) / hp_info->record_size;

  if (*count >= max_records) {   // αν δεν χωράει άλλο record
    if (BF_UnpinBlock(block) != BF_OK)
    {
      BF_Block_Destroy(&block);
      return 0;
    }

    if (BF_AllocateBlock(file_handle, block) != BF_OK) 
    {   // δεσμευουμε νέο block
      BF_Block_Destroy(&block);
      return 0;
    }
    char *ndata=BF_Block_GetData(block);
    memset(ndata, 0, BF_BLOCK_SIZE);
    int *ncount=(int *)ndata;
    *ncount=0;
    BF_Block_SetDirty(block);
    if (BF_UnpinBlock(block) != BF_OK) 
    {
      BF_Block_Destroy(&block);
      return 0;
    }

    hp_info->last_data_block=hp_info->total_blocks;
    hp_info->total_blocks++;

    if (BF_GetBlock(file_handle, 0, block) != BF_OK)
    {
      BF_Block_Destroy(&block);
      return 0;
    }
    char *hdata=BF_Block_GetData(block);
    memcpy(hdata, hp_info, sizeof(HeapFileHeader));
    BF_Block_SetDirty(block);
    if (BF_UnpinBlock(block) != BF_OK) {
      BF_Block_Destroy(&block);
      return 0;
    }

    if (BF_GetBlock(file_handle, hp_info->last_data_block, block) != BF_OK)  // pin το νεο data block
    { 
      BF_Block_Destroy(&block);
      return 0;
    }
    data=BF_Block_GetData(block);
    count=(int *)data;
  }

  char *rec_pos=data + sizeof(int) + (*count) * hp_info->record_size;   // που θα μπει το νέο record
  memcpy(rec_pos, &record, sizeof(Record));     // εγγραφή του record στο block
  (*count)++;                             // αύξηση του αριθμού των records στο block
  BF_Block_SetDirty(block);               // τροποποιημένο το block

  if (BF_UnpinBlock(block) != BF_OK) // unpin του block
  {   
    BF_Block_Destroy(&block);
    return 0;
  }

  BF_Block_Destroy(&block);
  return 1;
}

HeapFileIterator HeapFile_CreateIterator(int file_handle, HeapFileHeader* header_info, int id)
{
  HeapFileIterator it;
  it.file_handle=file_handle;
  it.header=header_info;
  it.target_id=id;   // target id 
  it.current_block=1;   // πρώτο data block
  it.current_index=0;   // πρώτο record
  return it;
}

int HeapFile_GetNextRecord(HeapFileIterator* heap_iterator, Record** record)
{
  BF_Block *block;
  BF_Block_Init(&block);

  while (heap_iterator->current_block <= heap_iterator->header->last_data_block) // όσο υπάρχουν data blocks
    {  
    if (BF_GetBlock(heap_iterator->file_handle, heap_iterator->current_block, block) != BF_OK) 
    {
      BF_Block_Destroy(&block);
      *record=NULL;
      return 0;
    }

    char *data=BF_Block_GetData(block);
    int *count=(int *)data;
    int max=*count;

    for (int i=heap_iterator->current_index; i < max; i++)   // σκανάρει όλα τα records
    { 
      char *rec_pos=data + sizeof(int) + i * heap_iterator->header->record_size;
      Record *r=(Record *)rec_pos;
      if (r->id == heap_iterator->target_id)  // έλεγχος για το target id 
      { 
        memcpy(*record, r, sizeof(Record));
        heap_iterator->current_block=heap_iterator->current_block;
        heap_iterator->current_index=i + 1;
        BF_UnpinBlock(block);
        BF_Block_Destroy(&block);
        return 1;
      }
    }

    BF_UnpinBlock(block);    // τελος του block
    heap_iterator->current_block+=1;
    heap_iterator->current_index=0;
  }

  BF_Block_Destroy(&block);
  *record=NULL;
  return 0;
}

