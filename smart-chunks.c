/*
   AFLSmart - chunks handler
   -------------------------

   Copyright 2018 National University of Singapore

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This implements loading of "chunks" information of a formatted
   file. A chunk is an identifiable section of a formatted file
   amenable to crossover mutation.

 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smart-chunks.h"
#include "smart-utils.h"

#define READ_LINE_BUFFER_SIZE 1024

enum {
  /* 00 */ READ_LINE_OK,
  /* 01 */ READ_LINE_FILE_ERROR,
  /* 02 */ READ_LINE_TOO_LONG
};

/*
 * Returns a hash code for this string, similar to Java's
 * java.lang.String.hashCode().  See:
 * http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/8u40-b25/java/lang/String.java?av=f#1453
 */
int hash_code(char *str) {
  int h = 0;
  char c;
  
  while ((c = *(str++)) != '\0')
    h = 31 * h + c;
  return h;
}

int next_lower_chunk(char *path, int *length, int *hash, int *type_hash) {
  char c;
  char *s = path;
  char *tmp;
  char *last_underscore;

  if (path == NULL) {
    *length = 0;
    return 0;
  }
  
  c = *s;
  while (c != '~' && c != '\n' && c != '\0' && c != ',') {
    c = *++s;
  }

  *length = s - path;

  if ((tmp = (char *) malloc(*length + 1)) == NULL) {
    *length = 0;
    return 0;
  }
    
  strncpy(tmp, path, *length);
  tmp[*length] = '\0';
  *hash = hash_code(tmp);

  last_underscore = tmp + *length - 1;
  while (last_underscore >= tmp) {
    if (*last_underscore == '_') {
      *last_underscore = '\0';
      break;
    } else if (!isdigit(*last_underscore)) {
      break;
    }
    last_underscore--;
  }

  *type_hash = hash_code(tmp);
  free(tmp);
  
  if (c == '~')
    return -1;

  return 0;  
}

int split_line_on_comma(char *line, int *start_byte, int *end_byte,
            char **path, char *modifiable, int *referrer, int *entry_count) {
  char *start, *end = line;
  char *str = (char *) malloc(READ_LINE_BUFFER_SIZE);

  if (str == NULL)
    return -1;
  
  start = end;
  while (isdigit(*end++));
  strncpy(str, start, end - start - 1);
  str[end - start - 1] = '\0';
  *start_byte = atoi(str);

  start = end;
  while (isdigit(*end++));
  strncpy(str, start, end - start - 1);
  str[end - start - 1] = '\0';
  *end_byte = atoi(str);

  start = end;
  char c;
  do {
    c = *end;
    end++;
  } while (c != '\n' && c != '\0' && c != ',');
  *(end - 1) = '\0';
  *path = start;

  *modifiable = 0;
  if (c == ',') {
    start = end;
    if (!strncmp(start, "Enabled", 7))
      *modifiable = 1;
  }

  do {
    c = *end;
    end++;
  } while (c != '\n' && c != '\0' && c != ',');
  start = end;

  *referrer = NO_REFERRER;
  if (c == ',' && !strncmp(start, "Referrer=", 9)) {
    start = end = start + 9;
    do {
      c = *end;
      end++;
    } while (isdigit(c));
    strncpy(str, start, end - start - 1);
    str[end - start - 1] = '\0';
    *referrer = atoi(str);
    start = end;
  }

  *entry_count = NO_ENTRY_COUNT;
  if (c == ',' && !strncmp(start, "Entries=", 8)) {
    start = end = start + 8;
    do {
      c = *end;
      end++;
    } while (isdigit(c));
    strncpy(str, start, end - start - 1);
    str[end - start - 1] = '\0';
    *entry_count = atoi(str);
    start = end;
  }

  free(str);

  return 0;
}

void add_path(struct chunk **tree, char *line) {
  char *next;
  struct chunk *current_chunk = *tree;
  int non_last = -1;
  
  int start_byte, end_byte, referrer, entry_count;
  char modifiable;

  if (split_line_on_comma(line, &start_byte, &end_byte, &next, &modifiable,
                          &referrer, &entry_count))
    return;

  if (*tree == NULL) {
    int length;
    int h;
    int t;

    non_last = next_lower_chunk(next, &length, &h, &t);

    if (length == 0)
      return;

    next = next + length + 1;

    if ((current_chunk = (struct chunk *) malloc(sizeof(struct chunk))) == NULL)
      return;

    current_chunk->id = h;
    current_chunk->type = t;
    current_chunk->start_byte = -1; /* Unknown */
    current_chunk->end_byte = -1;   /* Unknown */
    current_chunk->referrer = NO_REFERRER;
    current_chunk->entry_count = NO_ENTRY_COUNT;
    current_chunk->modifiable = modifiable;
    current_chunk->next = NULL;
    current_chunk->children = NULL;
  
    *tree = current_chunk;
  } else {
    int length;
    int h;
    int t;

    non_last = next_lower_chunk(next, &length, &h, &t);

    if (length == 0)
      return;

    next = next + length + 1;

    if (current_chunk->id != h) {
      struct chunk *new = (struct chunk *) malloc(sizeof(struct chunk));

      if (new == NULL)
	return;
      
      new->next = current_chunk->next;
      current_chunk->next = new;

      current_chunk = new;
      current_chunk->id = h;
      current_chunk->type = t;
      current_chunk->start_byte = -1; /* Unknown */
      current_chunk->end_byte = -1;   /* Unknown */
      current_chunk->referrer = NO_REFERRER;
      current_chunk->entry_count = NO_ENTRY_COUNT;
      current_chunk->modifiable = modifiable;
      current_chunk->children = NULL;      
    }

    if (!current_chunk->modifiable)
      current_chunk->modifiable = modifiable;
  }

  while (non_last) {
    int length;
    int h;
    int t;

    non_last = next_lower_chunk(next, &length, &h, &t);

    if (length == 0)
      return;

    next = next + length + 1;

    struct chunk *c = current_chunk->children;

    if (c == NULL) {
      if ((c = (struct chunk *) malloc(sizeof(struct chunk))) == NULL) 
	return;
      
      current_chunk->children = c;
      current_chunk = c;
      current_chunk->id = h;
      current_chunk->type = t;
      current_chunk->start_byte = -1; /* Unknown */
      current_chunk->end_byte = -1;   /* Unknown */
      current_chunk->referrer = NO_REFERRER;
      current_chunk->entry_count = NO_ENTRY_COUNT;
      current_chunk->modifiable = modifiable;
      current_chunk->next = NULL;
      current_chunk->children = NULL;
    } else {
      int chunk_found = 0;
      
      do {
        if (c->id == h) {
          current_chunk = c;
          chunk_found = 1;
          break;
        }
        c = c->next;
      } while (c);

      if (!chunk_found) {
	if ((c = (struct chunk *) malloc(sizeof(struct chunk))) == NULL) 
	  return;

	c->next = current_chunk->children;
	current_chunk->children = c;
	current_chunk = c;
        current_chunk->id = h;
	current_chunk->type = t;
        current_chunk->start_byte = -1; /* Unknown */
        current_chunk->end_byte = -1;   /* Unknown */
        current_chunk->referrer = NO_REFERRER;
        current_chunk->entry_count = NO_ENTRY_COUNT;
        current_chunk->modifiable = modifiable;
        current_chunk->children = NULL;
      }
    }

    if (!current_chunk->modifiable)
      current_chunk->modifiable = modifiable;
  }

  current_chunk->start_byte = start_byte;
  current_chunk->end_byte = end_byte;
  current_chunk->referrer = referrer;
  current_chunk->entry_count = entry_count;
}

void get_chunks(char *filespec, struct chunk **data_chunks) {
  FILE *chunk_file;
  char *line;
  size_t n;
  
  *data_chunks = NULL;

  if ((chunk_file = fopen(filespec, "r")) == NULL)
    return;

  do {
    line = NULL;
    n = 0;
    if (getline(&line, &n, chunk_file) == -1) {
      free(line);
      line = NULL;
    } else {
      add_path(data_chunks, line);
      if (line != NULL) {
        free(line);
      }
    }
  } while (line != NULL);

  fclose(chunk_file);
}

void delete_chunks(struct chunk *node) {
  struct chunk *sibling = node;

  while (sibling) {
    struct chunk *tmp = sibling->next;

    delete_chunks(sibling->children);
    free(sibling);

    sibling = tmp;
  }
}

struct chunk *copy_chunks(struct chunk *node) {
  if (node == NULL)
    return NULL;

  struct chunk *new_node = (struct chunk *)malloc(sizeof(struct chunk));
  new_node = memcpy(new_node, node, sizeof(struct chunk));
  new_node->next = copy_chunks(node->next);
  new_node->children = copy_chunks(node->children);

  return new_node;
}

// write num into mem at corresponding address with correct endianness
void write_int_to_mem(int num, char *mem, int addr, char endian, int bytes) {
  /*
  // check system's endianness
  char system_endian;
  unsigned int one = 1;
  if (*(unsigned char *)&one)
    system_endian = AFL_LITTLE_ENDIAN;
  else
    system_endian = AFL_BIG_ENDIAN;

  // swap the endianness if it's not the one we want
  if (endian != system_endian)
    num = (num << 24 & 0xff000000) | (num << 8 & 0x00ff0000)
           | (num >> 8 & 0x0000ff00) | (num >> 24 & 0x000000ff);
  */
  if (endian == AFL_UNKNOWN_ENDIAN || (bytes != 2 && bytes != 4))
    return;

  if (bytes == 4) {
    if (endian == AFL_LITTLE_ENDIAN)
      num = htole32(num);
    else
      num = htobe32(num);
  } else {
    if (endian == AFL_LITTLE_ENDIAN)
      num = htole16(num);
    else
      num = htobe16(num);
  }

  // write the number to memory
  memcpy(mem + addr, &num, bytes);
}

struct chunk *get_parent(struct chunk *c, struct chunk *target) {
  struct chunk *sibling = c->children;

  while (sibling) {
    if (sibling == target)
      return c;

    if (sibling->start_byte <= target->end_byte
        && target->start_byte <= sibling->end_byte)
      return get_parent(sibling, target);

    sibling = sibling->next;
  }

  return NULL;
}

/* TIFF-specific function */
void adjust_entry_count(struct chunk *c, struct chunk *parent,
                        struct chunk *target, int amount, char *out_buf,
                        char endian) {
  if (target->type != hash_code("DirEntry"))
    return;

  struct chunk *ec_chunk = NULL;
  struct chunk *sibling = parent->children;

  while (sibling) {
    if (has_entry_count(sibling)) {
      ec_chunk = sibling;
      break;
    }

    sibling = sibling->next;
  };

  if (ec_chunk) {
    /*
    fprintf("Adjusting entry_count by %d!\n", amount);
    fprintf("BEFORE 1\n");
    print_tree(parent);
    fprintf("AFTER 1\n");
    fprintf("BEFORE 2\n");
    print_tree(parent);
    fprintf("AFTER 2\n");
    print_tree(target);
    */
    ec_chunk->entry_count += amount;
    write_int_to_mem(ec_chunk->entry_count, out_buf,
                     ec_chunk->start_byte, endian, 2);
  }
}

void remove_referrers(struct chunk *c, int start, int end) {
  //smart_log("Called remove_referrers from %d to %d\n", start, end);
  struct chunk *sibling = c;

  while (sibling) {
    if (sibling->referrer >= start && sibling->referrer < end)
      sibling->referrer = NO_REFERRER;

    remove_referrers(sibling->children, start, end);
    sibling = sibling->next;
  }
}

void reduce_byte_positions(struct chunk *c, int start_byte,
                           unsigned size, char *out_buf, char endian) {
  //smart_log("Called reduce_byte_positions from %d to %d\n", start_byte, start_byte + size);
  struct chunk *sibling = c;

  while (sibling) {

    if (has_referrer(sibling) && sibling->referrer >= start_byte) {
      sibling->referrer -= size;
    }

    if (sibling->start_byte >= 0 && sibling->start_byte > start_byte) {
      (sibling->start_byte) -= size;
      //smart_log("rbp start from %d to %d\n", sibling->start_byte + size, sibling->start_byte);
      if (has_referrer(sibling)) {
        write_int_to_mem(sibling->start_byte, out_buf,
                         sibling->referrer, endian, 4);
      }
    }

    if (sibling->end_byte >= 0 && sibling->end_byte >= start_byte)
      (sibling->end_byte) -= size;

    reduce_byte_positions(sibling->children, start_byte, size, out_buf, endian);

    sibling = sibling->next;
  }
}

void increase_byte_positions_except_target_children(struct chunk *c,
                                    struct chunk *target, int start_byte,
                                    unsigned size, char *out_buf, char endian) {
  //smart_log("Called increase_byte_positions_except_target_children from %d to %d\n", start_byte, start_byte + size);
  struct chunk *sibling = c;

  while (sibling) {

    if (has_referrer(sibling) && sibling->referrer >= start_byte) {
      sibling->referrer += size;
    }

    if (sibling->start_byte >= 0 && sibling->start_byte > start_byte) {
      (sibling->start_byte) += size;
      //smart_log("ibpetc start from %d to %d\n", sibling->start_byte - size, sibling->start_byte);
      if (has_referrer(sibling)) {
        write_int_to_mem(sibling->start_byte, out_buf,
                         sibling->referrer, endian, 4);
      }
    }

    if (sibling->end_byte >= 0 && sibling->end_byte >= start_byte)
      (sibling->end_byte) += size;

    if (sibling != target) {
      increase_byte_positions_except_target_children(sibling->children, target,
                                                     start_byte, size, out_buf,
                                                     endian);
    }

    sibling = sibling->next;
  }
}

struct chunk *search_and_destroy_chunk(struct chunk *c,
                                       struct chunk *target_chunk,
                                       int start_byte, unsigned size,
                                       char *out_buf, char endian) {
  //smart_log("Called search_and_destroy_chunk from %d to %d\n", start_byte, start_byte + size);
  struct chunk *sibling = c;
  struct chunk *ret = c;
  struct chunk *prev = NULL;

  while (sibling) {

    if (sibling == target_chunk) {
      //smart_log("got sibling == target_chunk == %p\n", sibling);
      struct chunk *tmp = sibling->next;

      if (ret == sibling)
        ret = tmp;
      else
        prev->next = tmp;

      delete_chunks(sibling->children);
      free(sibling);

      //smart_log("doing rbp from %d to %d\n", start_byte, start_byte + size);
      //reduce_byte_positions(tmp, start_byte, size, out_buf, endian);
      sibling = tmp;
      continue;
    }

    //if (sibling->start_byte > start_byte && sibling->start_byte < start_byte + size)
    //  smart_log_tree(c);

    if (has_referrer(sibling) && sibling->referrer >= start_byte) {
      sibling->referrer -= size;
    }

    if (sibling->start_byte >= 0 && sibling->start_byte > start_byte) {
      (sibling->start_byte) -= size;
      //smart_log("sadc start from %d to %d\n", sibling->start_byte + size, sibling->start_byte);
      if (has_referrer(sibling)) {
        write_int_to_mem(sibling->start_byte, out_buf,
                         sibling->referrer, endian, 4);
      }
    }

    if (sibling->end_byte >= 0 && sibling->end_byte >= start_byte)
      (sibling->end_byte) -= size;

    sibling->children = search_and_destroy_chunk(
        sibling->children, target_chunk, start_byte, size, out_buf, endian);

    prev = sibling;
    sibling = sibling->next;
  }

  return ret;
}

void print_whitespace(int smart_log_mode, int amount) {
  int i;
  for (i = 0; i < amount; ++i) {
    if (smart_log_mode) {
      smart_log(" ");
    } else {
      printf(" ");
    }
  }
}

void print_node(int smart_log_mode, int hex_mode, struct chunk *node,
                const char *data, int whitespace_amount) {
  while (node != NULL) {
    print_whitespace(smart_log_mode, whitespace_amount);
    char referrer_string[20], entries_string[20];
    if (!has_referrer(node))
      referrer_string[0] = '\0';
    else
      snprintf(referrer_string, sizeof(referrer_string),
                      " Referrer: %d", node->referrer);
    if (!has_entry_count(node))
      entries_string[0] = '\0';
    else
      snprintf(entries_string, sizeof(entries_string),
                      " Entries: %d", node->entry_count);
    if (smart_log_mode) {
      smart_log("Type: %d Start: %d End: %d Modifiable: %d%s%s\n", node->type,
                node->start_byte, node->end_byte, node->modifiable,
                referrer_string, entries_string);
    } else {
      printf("Type: %d Start: %d End: %d Modifiable: %d%s%s\n", node->type,
             node->start_byte, node->end_byte, node->modifiable,
             referrer_string, entries_string);
    }
    int chunk_size = node->end_byte - node->start_byte + 1;
    if (data != NULL && node->start_byte >= 0 && node->end_byte >= 0 &&
        chunk_size > 0) {
      if (smart_log_mode) {
        if (hex_mode) {
          smart_log("Data:\n");
          smart_log_n_hex(chunk_size, data + node->start_byte);
        } else {
          smart_log_n(chunk_size, "Data: %s\n", data + node->start_byte);
        }
      } else {
        char *print_data = (char *)malloc(chunk_size + 1);
        strncpy(print_data, data + node->start_byte, chunk_size);
        print_data[chunk_size] = '\0';
        print_whitespace(smart_log_mode, whitespace_amount);
        printf("Data: %s\n", print_data);
        free(print_data);
      }
    }
    if (node->children) {
      print_node(smart_log_mode, hex_mode, node->children, data,
                 whitespace_amount + 4);
    }
    node = node->next;
  }
}

void print_tree(struct chunk *root) { print_tree_with_data(root, NULL); }

void print_tree_with_data(struct chunk *root, const char *data) {
  print_node(0, 0, root, data, 0);
}

void smart_log_tree(struct chunk *root) {
  smart_log_tree_with_data(root, NULL);
}

void smart_log_tree_with_data(struct chunk *root, const char *data) {
  print_node(1, 0, root, data, 0);
}

void smart_log_tree_hex(struct chunk *root) {
  smart_log_tree_with_data_hex(root, NULL);
}

void smart_log_tree_with_data_hex(struct chunk *root, const char *data) {
  print_node(1, 1, root, data, 0);
}
