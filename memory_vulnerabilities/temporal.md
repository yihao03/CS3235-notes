# Temporal Memory Errors

## Use after free

![use-after-free](../assets/use-after-free.png =x400)

### Double free

![double free](../assets/double-free.png =500x)

1. write any value that gets copied into p by `strncpy()`
2. when the code attempt to free the memory pointed to by p again, the allocator code:
    ![c allocator](../assets/double-free-1.png =400x)
    1. the value you specify `(p->next)` is written to the address you specified `(p->previous)`

## Mitigations

### Nullify pointers

`free(p)` where p is NULL is a no-op

However if we alias p

```c
r = (char *) p;
```

free(r) will free the memory pointed to by p, nulling p only does not work

### Lock and key mechanism

Ensures deallocated memory are not accessed

> Lock & Key values match if and only if memory object is temporally safe to access via this pointer

- Pointer: gets a key and the lock address
- Object: gets a lock

1. When accessing the object via the pointer, the lock and key values are compared. If they match, the access is allowed.
2. New pointers inherit values
3. on deallocation, update lock values
4. When the object is freed, the lock is invalidated, and the pointer's key will not match anymore.

> Original lock/key figure is missing (`lock-and-key.png`). See the [CETS lock/key notes](full-safety-5.md).
