/*
   AFLSmart - chunks handler exported API
   --------------------------------------

   Copyright 2018 National University of Singapore

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef __SMART_CHUNKS_H
#define __SMART_CHUNKS_H 1

#define NO_REFERRER -1
#define has_referrer(chunk) (chunk->referrer != NO_REFERRER)

#define NO_ENTRY_COUNT -1
#define has_entry_count(chunk) (chunk->entry_count != NO_ENTRY_COUNT)

/* Endianness values */

enum {
  /* 00 */ AFL_UNKNOWN_ENDIAN,
  /* 01 */ AFL_LITTLE_ENDIAN,
  /* 02 */ AFL_BIG_ENDIAN
};

struct chunk {
  unsigned long
      id; /* The id of the chunk, which either equals its pointer value or, when
             loaded from chunks file, equals to the hashcode of its chunk
             identifer string casted to unsigned long. */
  int type;                /* The hashcode of the chunk type. */
  int start_byte;          /* The start byte, negative if unknown. */
  int end_byte;            /* The last byte, negative if unknown. */
  int referrer;            /* The byte offset of a pointer to this chunk. */
  int entry_count;         /* The number of directory entries. If set, this
                              chunk represents that number in the file */
  char modifiable;         /* The modifiable flag. */
  struct chunk *next;      /* The next sibling child. */
  struct chunk *children;  /* The children chunks linked list. */
};

extern void get_chunks(char *filespec, struct chunk **data_chunks);

extern void print_tree(struct chunk *root);

extern void print_tree_with_data(struct chunk *root, const char *data);

/* Note that for this to work smart_log_init() must have been called. */
extern void smart_log_tree(struct chunk *root);

/* Note that for this to work smart_log_init() must have been called. */
extern void smart_log_tree_with_data(struct chunk *root, const char *data);

extern void delete_chunks(struct chunk *node);

extern struct chunk *copy_chunks(struct chunk *node);

extern struct chunk *get_parent(struct chunk *c, struct chunk *target);

extern void adjust_entry_count(struct chunk *c, struct chunk *parent,
                               struct chunk *target, int amount, char *out_buf,
                               char endian);

extern void remove_referrers(struct chunk *c, int start, int end);

extern void increase_byte_positions_except_target_children(struct chunk *c,
                                     struct chunk *target, int start_byte,
                                     unsigned size, char *out_buf, char endian);

extern void reduce_byte_positions(struct chunk *c, int start_byte,
                                  unsigned size, char *out_buf, char endian);

extern struct chunk *search_and_destroy_chunk(struct chunk *c,
                                              struct chunk *target_chunk,
                                              int start_byte, unsigned size,
                                              char *out_buf, char endian);

/* Note that for this to work smart_log_init() must have been called. */
extern void smart_log_tree_hex(struct chunk *root);

/* Note that for this to work smart_log_init() must have been called. */
extern void smart_log_tree_with_data_hex(struct chunk *root, const char *data);

#endif /* __SMART_CHUNKS_H */
