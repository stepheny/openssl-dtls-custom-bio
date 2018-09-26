#include <arpa/inet.h>
#include <sys/socket.h>

#ifndef UTIL_H
#define UTIL_H

typedef struct deque_item_s deque_item_t;

struct deque_item_s {
    void *p;
    deque_item_t *prev;
    deque_item_t *next;
};

typedef struct deque_s {
    deque_item_t *head;
    deque_item_t *tail;
} deque_t;

#define DEQUE_FOREACH(i, dq) \
for (deque_item_t *i=(dq)->head; i!=NULL; i=i->next)

typedef struct buffer_s {
    int cap;
    int len;
//     unsigned char *buf;
    unsigned char buf[];
} buffer_t;

typedef struct hashtable_s {
    int (*hash)(buffer_t *bp);
    int nbucket;
    deque_t bucket[];
} hashtable_t;

typedef struct ht_node_s {
    buffer_t *key;
    void *value;
} ht_node_t;

#define HT_FOREACH(htnp, htp) \
for (int _tmp_index=0; _tmp_index<(htp)->nbucket; ++_tmp_index) \
    for (deque_item_t *_tmp_item=((htp)->bucket[_tmp_index].head); _tmp_item; _tmp_item=_tmp_item->next) \
        for (ht_node_t *(htnp)=(ht_node_t *)_tmp_item->p; htnp; htnp=NULL)

deque_t *deque_new(void);
void deque_init(deque_t *dp);
void deque_deinit(deque_t *dp);
void deque_free(deque_t *dp);
size_t deque_count(deque_t *dp);
void deque_append(deque_t *dp, void *p);
void *deque_pop(deque_t *dp);
void *deque_peek(deque_t *dp);
void deque_appendleft(deque_t *dp, void *p);
void *deque_popleft(deque_t *dp);
void *deque_peekleft(deque_t *dp);
void deque_remove(deque_t *dp, deque_item_t *dip);


buffer_t *buffer_new(int cap);
void buffer_init(buffer_t *bp, int cap);
void buffer_free(buffer_t *bp);
int buffer_eq(buffer_t *a, buffer_t *b);

hashtable_t *ht256_new(void);
hashtable_t *ht16_new(void);
void ht_deinit(hashtable_t *htp);
void ht_free(hashtable_t *htp);
void *ht_search(hashtable_t *htp, buffer_t *key);
void *ht_insert(hashtable_t *htp, buffer_t *key, void *value);
int ht_delete(hashtable_t *htp, buffer_t *key);

void dump_hex(const unsigned char *buf, size_t len, const char *indent);
void dump_addr(struct sockaddr *sa, const char *indent);
const char *sdump_addr(struct sockaddr *sa);

#endif /* UTIL_H */
