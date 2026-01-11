#ifndef BF_H
#define BF_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file bf.h
 * @brief Block File (BF) Management Library
 *
 * This library provides low-level block-based file management functionality.
 * It allows users to create, open, close, and manipulate files organized
 * into fixed-size blocks, while maintaining a buffer of blocks in memory.
 */

#define BF_BLOCK_SIZE 512      /**< Size of each block in bytes */
#define BF_BUFFER_SIZE 100     /**< Maximum number of blocks held in memory */
#define BF_MAX_OPEN_FILES 100  /**< Maximum number of open files */

/* -------------------------------------------------------------------------- */
/*                                 Error Codes                                */
/* -------------------------------------------------------------------------- */

/**
 * @enum BF_ErrorCode
 * @brief Error codes returned by BF functions
 */
typedef enum BF_ErrorCode {
  BF_OK,                         /**< Operation completed successfully */
  BF_OPEN_FILES_LIMIT_ERROR,     /**< Maximum number of open files reached */
  BF_INVALID_FILE_ERROR,         /**< Invalid or closed file handle */
  BF_ACTIVE_ERROR,               /**< BF layer already active and cannot be reinitialized */
  BF_FILE_ALREADY_EXISTS,        /**< File creation failed because file already exists */
  BF_FULL_MEMORY_ERROR,          /**< Memory buffer is full (no free block slots) */
  BF_INVALID_BLOCK_NUMBER_ERROR, /**< Requested block number does not exist */
  BF_AVAILABLE_PIN_BLOCKS_ERROR, /**< File cannot be closed because some blocks are still pinned */
  BF_ERROR                       /**< General error */
} BF_ErrorCode;

/* -------------------------------------------------------------------------- */
/*                            Replacement Algorithms                          */
/* -------------------------------------------------------------------------- */

/**
 * @enum ReplacementAlgorithm
 * @brief Defines the cache replacement policy used by the BF layer
 */
typedef enum ReplacementAlgorithm {
  LRU, /**< Least Recently Used replacement algorithm */
  MRU  /**< Most Recently Used replacement algorithm */
} ReplacementAlgorithm;

/* -------------------------------------------------------------------------- */
/*                                   Types                                    */
/* -------------------------------------------------------------------------- */

/**
 * @brief Opaque structure representing a single block in memory
 */
typedef struct BF_Block BF_Block;

/* -------------------------------------------------------------------------- */
/*                                API Functions                               */
/* -------------------------------------------------------------------------- */

/**
 * @brief Initializes and allocates memory for a BF_Block structure
 *
 * @param block Double pointer to a BF_Block that will be allocated
 */
void BF_Block_Init(BF_Block **block);

/**
 * @brief Shuts down the BF layer
 *
 * Writes all dirty blocks to disk and releases any allocated resources.
 *
 * @return BF_OK on success, or an appropriate error code
 */
BF_ErrorCode BF_Close();

/**
 * @brief Frees the memory occupied by a BF_Block structure
 *
 * @param block Double pointer to a BF_Block to be destroyed
 */
void BF_Block_Destroy(BF_Block **block);

/**
 * @brief Marks a block as "dirty"
 *
 * A dirty block indicates that its data has been modified and must be
 * written back to disk before being evicted from memory.
 *
 * @param block Pointer to the block to mark as dirty
 */
void BF_Block_SetDirty(BF_Block *block);

/**
 * @brief Returns a pointer to the data stored in the given block
 *
 * If the data is modified, the block should be marked as dirty using
 * BF_Block_SetDirty().
 *
 * @param block Pointer to the block
 * @return Pointer to the block's data buffer
 */
char* BF_Block_GetData(const BF_Block *block);

/**
 * @brief Initializes the BF layer
 *
 * This function must be called before any other BF operation.
 * It sets up the block buffer and chooses a replacement algorithm.
 *
 * @param repl_alg Replacement policy to use (LRU or MRU)
 * @return BF_OK on success, or an appropriate error code
 */
BF_ErrorCode BF_Init(ReplacementAlgorithm repl_alg);

/**
 * @brief Creates a new block-based file
 *
 * If the file already exists, the function returns an error.
 *
 * @param filename Name of the file to create
 * @return BF_OK on success, or an appropriate error code
 */
BF_ErrorCode BF_CreateFile(const char* filename);

/**
 * @brief Opens an existing block-based file
 *
 * This function opens a block-based file and creates a new open instance
 * that can be used to access its contents. Each call to this function,
 * even with the same filename, returns a distinct handle referring
 * to that specific open instance.
 *
 * @param filename Name of the file to open.
 * @param file_handle Pointer to an integer that receives a handle identifying
 *        this specific open instance of the file.
 * @return BF_OK on success, or an appropriate error code.
 */
BF_ErrorCode BF_OpenFile(const char* filename, int *file_handle);

/**
 * @brief Closes an open block-based file
 *
 * All pinned blocks must be unpinned before closing.
 *
 * @param file_handle Handle of the file to close
 * @return BF_OK on success, or an appropriate error code
 */
BF_ErrorCode BF_CloseFile(int file_handle);

/**
 * @brief Returns the total number of blocks in an open file
 *
 * @param file_handle Handle of the file
 * @param blocks_num Pointer to an integer to store the block count
 * @return BF_OK on success, or an appropriate error code
 */
BF_ErrorCode BF_GetBlockCounter(int file_handle, int *blocks_num);

/**
 * @brief Allocates a new block at the end of the file
 *
 * The newly allocated block is automatically pinned in memory.
 *
 * @param file_handle Handle of the open file
 * @param block Pointer to a BF_Block structure to receive the new block
 * @return BF_OK on success, or an appropriate error code
 */
BF_ErrorCode BF_AllocateBlock(int file_handle, BF_Block *block);

/**
 * @brief Reads a specific block from a file
 *
 * The requested block is pinned in memory until BF_UnpinBlock() is called.
 *
 * @param file_handle Handle of the open file
 * @param block_num Block number to retrieve (0-based)
 * @param block Pointer to a BF_Block structure to receive the block data
 * @return BF_OK on success, or an appropriate error code
 */
BF_ErrorCode BF_GetBlock(int file_handle, int block_num, BF_Block *block);

/**
 * @brief Unpins a block from memory
 *
 * This function releases a previously pinned block, allowing it to be
 * replaced in the buffer if necessary.
 *
 * @param block Pointer to the block to unpin
 * @return BF_OK on success, or an appropriate error code
 */
BF_ErrorCode BF_UnpinBlock(BF_Block *block);

/**
 * @brief Prints a human-readable description of a BF error
 *
 * @param err The error code to describe
 */
void BF_PrintError(BF_ErrorCode err);

#ifdef __cplusplus
}
#endif
#endif /* BF_H */
