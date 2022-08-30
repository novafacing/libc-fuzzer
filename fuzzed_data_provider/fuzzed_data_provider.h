#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#define INITIAL_SIZE (64 * 1024)

typedef struct FuzzedDataBroker {
    size_t size;
    size_t capacity;
    uint8_t * buf;
    void (*consume_stdin)(struct FuzzedDataBroker *);
    void (*delete)(struct FuzzedDataBroker *);
} FuzzedDataBroker;

void FuzzedDataBroker_consume_stdin(FuzzedDataBroker * f) {
    while (true) {
        ssize_t rd = read(0, f->buf + f->size, f->capacity - f->size);
        if (rd <= 0) {
            break;
        } else {
            f->capacity *= 2;
            f->buf = (uint8_t *)realloc(f->buf, f->capacity);
        }
    }
}

void FuzzedDataBroker_delete(FuzzedDataBroker * f) {
    free(f->buf);
    f->buf = NULL;
    free(f);
    f = NULL;
}

FuzzedDataBroker * FuzzedDataBroker_new(void) {
    FuzzedDataBroker * f = (FuzzedDataBroker *)calloc(1, sizeof(FuzzedDataBroker));
    f->size = 0;
    f->capacity = INITIAL_SIZE;
    f->buf = (uint8_t *)calloc(f->capacity, sizeof(uint8_t));
    f->consume_stdin = FuzzedDataBroker_consume_stdin;
    f->delete = FuzzedDataBroker_delete;
    return f;
}

