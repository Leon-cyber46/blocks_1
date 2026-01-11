#ifndef HP_FILE_FUNCS_H
#define HP_FILE_FUNCS_H

#include "hp_file_structs.h"

/**
 * @file hp_file_funcs.h
 * @brief Heap File API functions for creation, access, and record management
 */

/* -------------------------------------------------------------------------- */
/*                              API Functions                                 */
/* -------------------------------------------------------------------------- */

/**
 * @brief Creates a new heap file with initialized header
 *
 * @param fileName Name of the file to create
 * @return 1 on success, 0 on failure
 */
int HeapFile_Create(const char *fileName);

/**
 * @brief Opens an existing heap file and loads its header
 *
 * @param fileName Name of the file to open
 * @param file_handle Output parameter for the file handle
 * @param header_info Output parameter for the heap file header
 * @return 1 on success, 0 on failure
 */
int HeapFile_Open(const char *fileName, int *file_handle, HeapFileHeader** header_info);

/**
 * @brief Closes a heap file and releases associated resources
 *
 * @param file_handle Handle of the heap file to close
 * @param header_info Pointer to the heap file header structure
 * @return 1 on success, 0 on failure
 */
int HeapFile_Close(int file_handle, HeapFileHeader* header_info);

/**
 * @brief Inserts a new record into the heap file
 *
 * Automatically allocates a new block if the current insertion block is full
 *
 * @param file_handle Handle of the heap file
 * @param header_info Pointer to heap file metadata
 * @param record Record structure to insert
 * @return 1 on success, 0 on failure
 */
int HeapFile_InsertRecord(int file_handle, HeapFileHeader* header_info, Record record);

/**
 * @brief Retrieves the next matching record using an iterator
 *
 * @param heap_iterator Initialized iterator for record traversal
 * @param record Output parameter that receives a pointer to the found record
 * @return 1 if a record was found, 0 if no more records match
 */
int HeapFile_GetNextRecord(HeapFileIterator* heap_iterator, Record** record);

/**
 * @brief Creates and initializes a new iterator for heap file scanning
 *
 * @param file_handle Handle of the heap file to iterate over
 * @param header_info Pointer to heap file metadata
 * @param search_id Record ID to filter during iteration
 * @return Initialized HeapFileIterator structure
 */
HeapFileIterator HeapFile_CreateIterator(int file_handle, HeapFileHeader* header_info, int search_id);

#endif /* HP_FILE_FUNCS_H */
