/*
 * imap_buffer.c
 * 
 * Copyright 2022 chehw <hongwei.che@gmail.com>
 * 
 * The MIT License (MIT)
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <ctype.h>

#include "imap_client.h"
#include "utils.h"

struct imap_buffer *imap_buffer_init(struct imap_buffer *_buffer, size_t size)
{
	struct imap_buffer *buffer = _buffer;
	
	if(NULL == buffer) buffer = calloc(1, sizeof(*buffer));
	else memset(buffer, 0, sizeof(*buffer));
	
	assert(buffer);
	if(0 != imap_buffer_resize(buffer, size)) {
		imap_buffer_clear(buffer);
		if(NULL == _buffer) free(buffer);
		return NULL;
	}
	
	++buffer->refs;
	return buffer;
}
int imap_buffer_resize(struct imap_buffer *buffer, size_t new_size)
{
	assert(buffer);
	static const size_t alloc_size = 4096;
	if(new_size == 0) new_size = alloc_size;
	else new_size = (new_size + alloc_size - 1) / alloc_size * alloc_size;
	
	if(new_size <= buffer->size) return 0;
	char *data = realloc(buffer->data, new_size);
	assert(data);
	memset(data + buffer->size, 0, new_size - buffer->size);
	buffer->data = data;
	buffer->size = new_size;
	return 0;
}
int imap_buffer_push_data(struct imap_buffer *buffer, char *data, size_t length)
{
	assert(buffer);
	if(NULL == data || length == 0) return -1;
	if(length == -1) length = strlen(data);
	if(length == 0) return 0;
	
	int rc = imap_buffer_resize(buffer, buffer->start_pos + buffer->length + length + 1);
	if(rc) return -1;
	
	char *dst = buffer->data + buffer->start_pos + buffer->length;
	memcpy(dst, data, length);
	dst[length] = '\0';
	buffer->length += length;
	
	return 0;
}
ssize_t imap_buffer_pop_data(struct imap_buffer *buffer, char **p_data, size_t size)
{
	assert(buffer);
	if(NULL == p_data) return -1;
	if(buffer->length == 0) return 0;
	
	const char *src = buffer->data + buffer->start_pos;
	char *dst = *p_data;
	size_t length = buffer->length;
	if(length > size) length = size;
	
	if(NULL == dst) {
		dst = calloc(length + 1, 1);
		assert(dst);
		*p_data = dst;
	}
	memcpy(dst, src, length);
	buffer->start_pos += length;
	buffer->length -= length;
	
	if(buffer->length == 0) buffer->start_pos = 0; // reset start pos
	return length;
}
void imap_buffer_clear(struct imap_buffer *buffer)
{
	if(NULL == buffer) return;
	if(buffer->data) free(buffer->data);
	memset(buffer, 0, sizeof(*buffer));
}

struct imap_buffer_array *imap_buffer_array_init(struct imap_buffer_array *array, size_t size)
{
	if(NULL == array) array = calloc(1, sizeof(*array));
	assert(array);
	memset(array, 0, sizeof(*array));
	
	int rc = imap_buffer_array_resize(array, size);
	assert(0 == rc);
	
	return array;
}
int imap_buffer_array_resize(struct imap_buffer_array *array, size_t new_size)
{
	static const size_t alloc_size = 1024;
	if(new_size == 0) new_size = alloc_size;
	else new_size = (new_size + alloc_size - 1) / alloc_size * alloc_size;
	
	if(new_size <= array->size) return 0;
	struct imap_buffer **items = realloc(array->items, new_size * sizeof(*items));
	assert(items);
	
	memset(items + array->size, 0, new_size - array->size);
	array->items = items;
	array->size = new_size;
	return 0;
}
int imap_buffer_array_append(struct imap_buffer_array *array, struct imap_buffer *buffer)
{
	int rc = imap_buffer_array_resize(array, array->length + 1);
	assert(0 == rc);
	
	array->items[array->length++] = buffer;
	return 0;
}
void imap_buffer_array_cleanup(struct imap_buffer_array *array)
{
	if(NULL == array) return;
	if(array->items) {
		for(size_t i = 0; i < array->length; ++i) {
			struct imap_buffer *buffer = array->items[i];
			if(buffer) {
				imap_buffer_unref(buffer);
				array->items[i] = NULL;
			}
		}
		free(array->items);
	}
	memset(array, 0, sizeof(*array));
}

int imap_buffer_to_lines_array(struct imap_buffer *buf, struct lines_array *array, const char *tag, size_t cb_tag)
{
	if(tag && cb_tag == -1) cb_tag = strlen(tag);
	
	const char *data = buf->data;
	size_t length = buf->length;
	if(NULL == data || length == -1) return -1;
	if(length == 0) return 1; // need more data
	
	const char *p = data;
	const char *p_end = data + length;
	char *p_nextline = NULL;
	
	debug_printf("%s(): buffer(cb=%ld): ", __FUNCTION__, (long)buf->length);
	dump_printable((char *)buf->data, buf->length, 1);
	
	int rc = 1;
	while(p < p_end) {
		p_nextline = strchr(p, '\n');
		if(NULL == p_nextline) break; 
		
		++p_nextline;
		size_t cb = p_nextline - p;
		
		char *line = lines_array_add(array, p, cb);
		assert(line);
		fprintf(stderr, "== %s(%d)::tag=%s: ", __FILE__, __LINE__, tag);
		dump_printable(line, cb, 1);
		
		p = p_nextline;
		if(tag && cb_tag > 0) {
			if(strncasecmp(line, tag, cb_tag) == 0) {
				rc = 0;
				break;
			}
		}
	}
	
	if(rc >= 0 && p > buf->data) {
		assert(p <= p_end);
		size_t bytes_left = p_end - p;
		if(bytes_left) {
			fprintf(stderr, "\e[31m[INFO]: memmove(): bytes=%ld, str=%s\e[39m\n",
				(long)bytes_left, p);
			memmove(buf->data, p, bytes_left);
		}
		buf->length = bytes_left;
		buf->data[buf->length] = '\0';
		
		if(p == p_end && NULL == tag) rc = 0;
	}
	return rc;
}
