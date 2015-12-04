#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCKS 4
#define INDIRECT_BLOCKS 9
#define DOUBLE_INDIRECT_BLOCKS 1

#define DIRECT_INDEX 0
#define INDIRECT_INDEX 4
#define DOUBLE_INDIRECT_INDEX 13

#define INDIRECT_BLOCK_PTRS 128
#define INODE_BLOCK_PTRS 14

#define MAX_FILE_SIZE 8980480

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;
    unsigned magic;                     /* Magic number. */
    uint32_t direct_index;
    uint32_t indirect_index;
    uint32_t double_indirect_index;
    bool is_dir;
    block_sector_t parent;
    uint32_t unused[107];
    uint32_t ptr[INODE_BLOCK_PTRS];
  };

struct indirect_block
{
  block_sector_t ptr[INDIRECT_BLOCK_PTRS];
};

bool inode_alloc(struct inode_disk *disk_inode);
off_t inode_expand(struct inode *inode, off_t new_length);
size_t inode_expand_indirect_block(struct inode *inode, size_t new_data_sectors);
size_t inode_expand_double_indirect_block(struct inode *inode, size_t new_data_sectors);
size_t inode_expand_double_indirect_block_level_two(struct inode *inode, size_t new_data_sectors, struct indirect_block *outer_block);
void inode_dealloc(struct inode *inode);
void inode_dealloc_indirect_block(block_sector_t *ptr, size_t data_ptrs);
void inode_dealloc_double_indirect_block(block_sector_t *ptr, size_t indirect_ptrs, size_t data_ptrs);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_data_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

static size_t
bytes_to_indirect_sectors(off_t size) {
  if(size <= (BLOCK_SECTOR_SIZE * DIRECT_BLOCKS)) {
    return 0;
  }
  size -= BLOCK_SECTOR_SIZE * DIRECT_BLOCKS;
  return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE * INDIRECT_BLOCK_PTRS);
}

static size_t
bytes_to_double_indirect_sector(off_t size) {
  if(size <= (BLOCK_SECTOR_SIZE * (DIRECT_BLOCKS + (INDIRECT_BLOCKS * INDIRECT_BLOCK_PTRS)))) {
    return 0;
  }
  return DOUBLE_INDIRECT_BLOCKS;
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    block_sector_t start;
    off_t length;
    size_t direct_index;
    size_t indirect_index;
    size_t double_indirect_index;
    bool is_dir;
    block_sector_t parent;
    struct lock lock;
    block_sector_t ptr[INODE_BLOCK_PTRS];
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t length, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < length) {
    uint32_t idx;
    uint32_t indirect_block[INDIRECT_BLOCK_PTRS];
    if(pos < (BLOCK_SECTOR_SIZE * DIRECT_BLOCKS)) {
      return inode->ptr[pos / BLOCK_SECTOR_SIZE];
    }
    else if(pos < (BLOCK_SECTOR_SIZE * (DIRECT_BLOCKS + (INDIRECT_BLOCKS * INDIRECT_BLOCK_PTRS)))) {
      pos -= BLOCK_SECTOR_SIZE * DIRECT_BLOCKS;
      idx = pos / (BLOCK_SECTOR_SIZE * INDIRECT_BLOCK_PTRS) + DIRECT_BLOCKS;
      block_read(fs_device, inode->ptr[idx], &indirect_block);
      pos %= BLOCK_SECTOR_SIZE * INDIRECT_BLOCK_PTRS;
      return indirect_block[pos / BLOCK_SECTOR_SIZE];
    }
    else {
      block_read(fs_device, inode->ptr[DOUBLE_INDIRECT_INDEX], &indirect_block);
      pos -= BLOCK_SECTOR_SIZE * (DIRECT_BLOCKS + (INDIRECT_BLOCKS * INDIRECT_BLOCK_PTRS));
      idx = pos / (BLOCK_SECTOR_SIZE * INDIRECT_BLOCK_PTRS);
      block_read(fs_device, indirect_block[idx], &indirect_block);
      pos %= BLOCK_SECTOR_SIZE * INDIRECT_BLOCK_PTRS;
      return indirect_block[pos / BLOCK_SECTOR_SIZE];
    }
  }
  else {
    return -1;
  }  
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      if(disk_inode->length > MAX_FILE_SIZE) {
	disk_inode->length = MAX_FILE_SIZE;
      }
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = is_dir;
      disk_inode->parent = ROOT_DIR_SECTOR;
      if (inode_alloc(disk_inode)) 
        {
          block_write (fs_device, sector, disk_inode);
	  success = true;
        } 
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;
  struct inode_disk data;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->lock);
  block_read (fs_device, inode->sector, &data);
  inode->length = data.length;
  inode->direct_index = data.direct_index;
  inode->indirect_index = data.indirect_index;
  inode->double_indirect_index = data.double_indirect_index;
  inode->is_dir = data.is_dir;
  inode->parent = data.parent;
  memcpy(&inode->ptr, &data.ptr, INODE_BLOCK_PTRS * sizeof(block_sector_t));
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          inode_dealloc(inode);
        }
      else {
	struct inode_disk disk_inode;
	disk_inode.length = inode->length;
	disk_inode.magic = INODE_MAGIC;
	disk_inode.direct_index = inode->direct_index;
	disk_inode.indirect_index = inode->indirect_index;
	disk_inode.double_indirect_index = inode->double_indirect_index;
	disk_inode.is_dir = inode->is_dir;
	disk_inode.parent = inode->parent;
	memcpy(&disk_inode.ptr, &inode->ptr, INODE_BLOCK_PTRS * sizeof(block_sector_t));
	block_write(fs_device, inode->sector, &disk_inode);
      }
      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  off_t length = inode_length(inode);

  if(offset >= length) {
    return bytes_read;
  }

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, length, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      
      struct cache_info *info = get_or_evict_cache_block(sector_idx, false);
      memcpy(buffer + bytes_read, (uint8_t*) &info->block + sector_ofs, chunk_size);
      info->is_accessed = true;
      info->open_cnt--;
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  off_t length;

  if (inode->deny_write_cnt)
    return 0;

  length = inode_length(inode);
  if((offset + size) > length) {
    if(!inode->is_dir) {
      inode_lock(inode);
    }
    length = inode_expand(inode, offset + size);
    if(!inode->is_dir) {
      inode_unlock(inode);
    }
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, length, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      struct cache_info *info = get_or_evict_cache_block(sector_idx, false);
      memcpy((uint8_t*) &info->block + sector_ofs, buffer + bytes_written, chunk_size);
      info->is_accessed = true;
      info->is_dirty = true;
      info->open_cnt--;

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  inode->length = length;
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (struct inode *inode)
{
  return inode->length;
}

bool inode_alloc(struct inode_disk *disk_inode) {
  struct inode inode;
  
  inode.length = 0;
  inode.direct_index = 0;
  inode.indirect_index = 0;
  inode.double_indirect_index = 0;
  inode_expand(&inode, disk_inode->length);
  disk_inode->direct_index = inode.direct_index;
  disk_inode->indirect_index = inode.indirect_index;
  disk_inode->double_indirect_index = inode.double_indirect_index;
  memcpy(&disk_inode->ptr, &inode.ptr, INODE_BLOCK_PTRS * sizeof(block_sector_t));
  return true;
}

off_t inode_expand(struct inode *inode, off_t new_length) {
  static char zeroes[BLOCK_SECTOR_SIZE];
  size_t new_data_sectors = bytes_to_data_sectors(new_length) - bytes_to_data_sectors(inode->length);
  
  if(new_data_sectors == 0) {
    inode->length = new_length;
    return new_length;
  }
  while(inode->direct_index < INDIRECT_INDEX) {
    free_map_allocate(1, &inode->ptr[inode->direct_index]);
    block_write(fs_device, inode->ptr[inode->direct_index], zeroes);
    inode->direct_index++;
    new_data_sectors--;
    if(new_data_sectors == 0) {
      inode->length = new_length;
      return new_length;
    }
  }
  while(inode->direct_index < DOUBLE_INDIRECT_INDEX) {
    new_data_sectors = inode_expand_indirect_block(inode, new_data_sectors);
    if(new_data_sectors == 0) {
      inode->length = new_length;
      return new_length;
    }
  }
  if(inode->direct_index == DOUBLE_INDIRECT_INDEX) {
    new_data_sectors = inode_expand_double_indirect_block(inode, new_data_sectors);
  }
  return new_length - new_data_sectors * BLOCK_SECTOR_SIZE;
}

size_t inode_expand_indirect_block(struct inode *inode, size_t new_data_sectors) {
  static char zeroes[BLOCK_SECTOR_SIZE];
  struct indirect_block block;

  if(inode->indirect_index == 0) {
    free_map_allocate(1, &inode->ptr[inode->direct_index]);
  }
  else {
    block_read(fs_device, inode->ptr[inode->direct_index], &block);
  }
  while(inode->indirect_index < INDIRECT_BLOCK_PTRS) {
    free_map_allocate(1, &block.ptr[inode->indirect_index]);
    block_write(fs_device, block.ptr[inode->indirect_index], zeroes);
    inode->indirect_index++;
    new_data_sectors--;
    if(new_data_sectors == 0) {
      break;
    }
  }
  block_write(fs_device, inode->ptr[inode->direct_index], &block);
  if(inode->indirect_index == INDIRECT_BLOCK_PTRS) {
    inode->indirect_index = 0;
    inode->direct_index++;
  }
  return new_data_sectors;
}

size_t inode_expand_double_indirect_block(struct inode *inode, size_t new_data_sectors) {
  struct indirect_block block;
  
  if(inode->double_indirect_index == 0 && inode->indirect_index == 0) {
    free_map_allocate(1, &inode->ptr[inode->direct_index]);
  }
  else {
    block_read(fs_device, inode->ptr[inode->direct_index], &block);
  }
  while(inode->indirect_index < INDIRECT_BLOCK_PTRS) {
    new_data_sectors = inode_expand_double_indirect_block_level_two(inode, new_data_sectors, &block);
    if(new_data_sectors == 0) {
      break;
    }
  }
  block_write(fs_device, inode->ptr[inode->direct_index], &block);
  return new_data_sectors;
}

size_t inode_expand_double_indirect_block_level_two(struct inode *inode, size_t new_data_sectors, struct indirect_block *outer_block) {
  static char zeroes[BLOCK_SECTOR_SIZE];
  struct indirect_block inner_block;

  if(inode->double_indirect_index == 0) {
    free_map_allocate(1, &outer_block->ptr[inode->indirect_index]);
  }
  else {
    block_read(fs_device, outer_block->ptr[inode->indirect_index], &inner_block);
  }
  while(inode->double_indirect_index < INDIRECT_BLOCK_PTRS) {
    free_map_allocate(1, &inner_block.ptr[inode->double_indirect_index]);
    block_write(fs_device, inner_block.ptr[inode->double_indirect_index], zeroes);
    inode->double_indirect_index++;
    new_data_sectors--;
    if(new_data_sectors == 0) {
      break;
    }
  }
  block_write(fs_device, outer_block->ptr[inode->indirect_index], &inner_block);
  if(inode->double_indirect_index == INDIRECT_BLOCK_PTRS) {
    inode->double_indirect_index = 0;
    inode->indirect_index++;
  }
  return new_data_sectors;
}

void inode_dealloc(struct inode *inode) {
  size_t data_sectors = bytes_to_data_sectors(inode->length);
  size_t indirect_sectors = bytes_to_indirect_sectors(inode->length);
  size_t double_indirect_sector = bytes_to_double_indirect_sector(inode->length);
  unsigned int idx = 0;
  
  while(data_sectors && idx < INDIRECT_INDEX) {
    free_map_release(inode->ptr[idx], 1);
    data_sectors--;
    idx--;
  }
  while(indirect_sectors && idx < DOUBLE_INDIRECT_INDEX) {
    size_t data_ptrs = data_sectors < INDIRECT_BLOCK_PTRS ? data_sectors : INDIRECT_BLOCK_PTRS;
    inode_dealloc_indirect_block(&inode->ptr[idx], data_ptrs);
    data_sectors -= data_ptrs;
    indirect_sectors--;
    idx++;
  }
  if(double_indirect_sector) {
    inode_dealloc_double_indirect_block(&inode->ptr[idx], indirect_sectors, data_sectors);
  }
}

void inode_dealloc_indirect_block(block_sector_t *ptr, size_t data_ptrs) {
  unsigned int i;
  struct indirect_block block;

  block_read(fs_device, *ptr, &block);
  for(i = 0; i < data_ptrs; i++) {
    free_map_release(block.ptr[i], 1);
  }
  free_map_release(*ptr, 1);
}

void inode_dealloc_double_indirect_block(block_sector_t *ptr, size_t indirect_ptrs, size_t data_ptrs) {
  unsigned int i;
  struct indirect_block block;

  block_read(fs_device, *ptr, &block);
  for(i = 0; i < indirect_ptrs; i++) {
    size_t data_per_block = data_ptrs < INDIRECT_BLOCK_PTRS ? data_ptrs : INDIRECT_BLOCK_PTRS;
    inode_dealloc_indirect_block(&block.ptr[i], data_per_block);
    data_ptrs -= data_per_block;
  }
  free_map_release(*ptr, 1);
}

bool inode_is_dir(const struct inode *inode) {
  return inode->is_dir;
}

int inode_get_open_cnt(const struct inode *inode) {
  return inode->open_cnt;
}

block_sector_t inode_get_parent(const struct inode *inode) {
  return inode->parent;
}

bool inode_add_parent(block_sector_t parent_sector, block_sector_t child_sector) {
  struct inode *inode = inode_open(child_sector);
  if(!inode) {
    return false;
  }
  inode->parent = parent_sector;
  inode_close(inode);
  return true;
}

void inode_lock(struct inode *inode) {
  lock_acquire(&inode->lock);
}

void inode_unlock(struct inode *inode) {
  lock_release(&inode->lock);
}
