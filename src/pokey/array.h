#ifndef __ARRAY_H__
#define __ARRAY_H__

typedef struct array_t {
  void **data;
  int allocated;
  int elements;
} array_t;

#define array_get_ptr(array)  ((array)->data)
#define array_get_nelts(array)  ((array)->elements)
#define array_get_element(array, index)  ((array)->data[(index)])

void *array_add(array_t *array, void *element);
array_t *array_create(void);
void array_free(array_t *array);

#endif /* __ARRAY_H__ */
