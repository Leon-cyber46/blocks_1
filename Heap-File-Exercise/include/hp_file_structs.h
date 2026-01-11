#ifndef HP_FILE_STRUCTS_H
#define HP_FILE_STRUCTS_H

#include <record.h>

/**
 * @file hp_file_structs.h
 * @brief Data structures for heap file management
 */

/* -------------------------------------------------------------------------- */
/*                              Data Structures                               */
/* -------------------------------------------------------------------------- */

/**
 * @brief Heap file header containing metadata about the file organization
 */
typedef struct {
  char magic[4];
  int  version;
  int  record_size;
  int  total_blocks;
  int  last_data_block;
} HeapFileHeader;

/**
 * @brief Iterator for scanning through records in a heap file
 */

typedef struct {
  int file_handle;
  HeapFileHeader *header;
  int target_id;
  int current_block;
  int current_index;
} HeapFileIterator;

#endif /* HP_FILE_STRUCTS_H */

