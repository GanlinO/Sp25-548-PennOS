#include "./Vec.h"
#include "./panic.h"

#include <stdlib.h>

#define SIZE_T_MAX ((size_t)-1)

//////////////////////////////////////////////
// declaration of internal helper functions //
//////////////////////////////////////////////

/**
 * To ensure that the Vec has capacity of min_capacity; if min_capacity is set to 0,
 *  make sure it has enough capacity for the next push_back
 * If not enough capacity, double the capacity until it reaches min_capacity.
 */
static void vec_ensure_or_double_capacity(Vec* self, size_t min_capacity);

/**
 * Initialize unused capacity to NULL up to up_to_index
 */
static void vec_initialize_unused_capacity(Vec* self, size_t up_to_index);

/**
 * Helper for vec_set
 * Support force set index (over current size) option
 */
static void vec_set_helper(Vec* self, size_t index, ptr_t new_ele, bool force_set);

//////////////////////////////////////////////
// public functions                         //
//////////////////////////////////////////////

Vec vec_new(size_t initial_capacity, ptr_dtor_fn ele_dtor_fn) {
  // check valid initial_capacity
  if (initial_capacity < 0) {
    panic("Initial capacity should be non-negative in vec_new\n");
  }

  // allocate array if initial capacity is positive
  ptr_t* data = NULL;
  if (initial_capacity > 0) {
    data = malloc(initial_capacity * sizeof(ptr_t));
    if (data == NULL) {
      panic("Error with malloc in vec_new\n");
    }
  }

  return (Vec){.data = data,
               .length = 0,
               .capacity = initial_capacity,
               .ele_dtor_fn = ele_dtor_fn};
}

ptr_t vec_get(Vec* self, size_t index) {
  // validate index
  if (index >= self->length || index < 0) {
    panic("Index out of bound in vec_get\n");
  }

  return *(self->data + index);
}

void vec_set(Vec* self, size_t index, ptr_t new_ele) {
  vec_set_helper(self, index, new_ele, false);
}

void vec_set_force(Vec* self, size_t index, ptr_t new_ele) {
  vec_set_helper(self, index, new_ele, true);
}

void vec_push_back(Vec* self, ptr_t new_ele) {
  // double capacity if needed
  vec_ensure_or_double_capacity(self, 0);

  // append the new element
  *(self->data + self->length) = new_ele;
  ++(self->length);
}

bool vec_pop_back(Vec* self) {
  // check whether vector is empty
  if (self->length == 0) {
    return false;
  }

  --(self->length);
  return true;
}

void vec_insert(Vec* self, size_t index, ptr_t new_ele) {
  size_t length = self->length;
  // validate index
  if (index > length || index < 0) {
    panic("Index out of bound in vec_insert\n");
  }

  if (index == length) {
    // if index == self->length, append to the end of the vec
    vec_push_back(self, new_ele);
  } else {
    // insert in between, need to move elements up

    // check for capacity
    vec_ensure_or_double_capacity(self, 0);

    // move elements
    ptr_t* data = self->data;
    for (size_t i = length; i >= index + 1; --i) {
      *(data + i) = *(data + i - 1);
    }

    *(data + index) = new_ele;
    ++(self->length);
  }
}

void vec_erase(Vec* self, size_t index) {
  size_t length = self->length;
  // validate index
  if (index >= length || index < 0) {
    panic("Index out of bound in vec_erase\n");
  }

  // call destructor if needed
  if (self->ele_dtor_fn != NULL) {
    self->ele_dtor_fn(*(self->data + index));
  }

  // move elements
  ptr_t* data = self->data;
  for (size_t i = index; i < length; ++i) {
    *(data + i) = *(data + i + 1);
  }
  --(self->length);
}

void vec_resize(Vec* self, size_t new_capacity) {
  // does nothing if new_capacity <= self->length
  // implicitly if new_capacity is 0, also does nothing
  if (new_capacity <= self->length) {
    return;
  }

  // no need to specially treat old capacity == 0 (i.e. self->data == NULL)
  // as realloc() will just do malloc()
  ptr_t* new_data = realloc(self->data, new_capacity * sizeof(ptr_t));
  if (new_data == NULL) {
    panic("Error with realloc when resizing vec\n");
  }

  self->data = new_data;
  self->capacity = new_capacity;
}

void vec_resize_and_clean(Vec* self, size_t new_capacity) {
  vec_resize(self, new_capacity);
  vec_initialize_unused_capacity(self, new_capacity - 1);
}

void vec_clear(Vec* self) {
  if (!self) {
    return;
  }

  // clean up the elements
  ptr_t* data = self->data;
  ptr_dtor_fn dtor_fn = self->ele_dtor_fn;
  if (dtor_fn != NULL) {
    for (size_t i = 0; i < self->length; ++i) {
      dtor_fn(*(data + i));
    }
  }

  // set length to 0
  self->length = 0;
}

void vec_destroy(Vec* self) {
  if (!self) {
    return;
  }

  vec_clear(self);

  // free the data field
  free(self->data);
  self->data = NULL;
  self->capacity = 0;

  // JLnote: need to clean up self->ele_dtor_fn?
}

//////////////////////////////////////////////
// helper functions                         //
//////////////////////////////////////////////

static void vec_ensure_or_double_capacity(Vec* self, size_t min_capacity) {
  size_t old_capacity = self->capacity;
  size_t min_new_capacity = (min_capacity == 0) ? (self->length + 1) : min_capacity;

  size_t new_capacity = (old_capacity == 0) ? 1 : old_capacity;

  while (new_capacity < min_new_capacity && new_capacity <= SIZE_T_MAX / 2) {
    new_capacity *= 2;
  }

  if (new_capacity < min_new_capacity) {
    new_capacity = min_new_capacity;
  }

  vec_resize(self, new_capacity);
}

static void vec_initialize_unused_capacity(Vec* self, size_t up_to_index) {
  ptr_t* data = self->data;
  size_t last_cleanup_idx = (up_to_index < vec_capacity(self) - 1) ? up_to_index : vec_capacity(self) - 1;

  for (size_t i = self->length; i <= last_cleanup_idx; ++i) {
    *(data + i) = NULL;
  }
}

static void vec_set_helper(Vec* self, size_t index, ptr_t new_ele, bool force_set) {
  // validate index
  if (index < 0) {
    panic("Negative index out of bound in vec_set\n");
  }

  if (index >= vec_len(self)) {
    if (!force_set) {
      panic("Index out of bound in vec_set\n");
      return;
    }

    vec_ensure_or_double_capacity(self, index + 1);
    vec_initialize_unused_capacity(self, index - 1);

    self->length = index + 1;

  } else {
    // call destructor if needed
    if (self->ele_dtor_fn != NULL) {
      self->ele_dtor_fn(*(self->data + index));
    }
  }

  *(self->data + index) = new_ele;
}