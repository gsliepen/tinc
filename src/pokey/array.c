#include <stdio.h>
#include <stdlib.h>

#include "myalloc.h"
#include "array.h"

void *array_add(array_t *array, void *element)
{
  if(!array)
    return NULL;

  if(array->allocated == 0)
    {
      array->allocated = 4;
      array->data = xcalloc(array->allocated, sizeof(void*));
      array->elements = 0;
    }

  if(array->elements >= array->allocated - 1)
    {
      int newalloc;

      newalloc = array->allocated << 1;
      array->data = xrealloc(array->data, newalloc * sizeof(void*));
      array->allocated = newalloc;
    }

  array->data[array->elements] = element;
  array->elements++;
  return element;
}

array_t *array_create(void)
{
  array_t *r;

  r = xcalloc(1, sizeof(*r));
  return r;
}

void array_free(array_t *array)
{
  free(array->data);
  free(array);
}
