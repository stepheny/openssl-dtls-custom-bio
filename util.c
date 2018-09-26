#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>

#include "util.h"

typedef union access_u
{
    uint_fast64_t u64;
    uint32_t u32[2];
    uint16_t u16[4];
    uint8_t u8[8];
} access_t;

deque_t *deque_new(void)
{
    deque_t *dp = (deque_t *)malloc(sizeof(deque_t));
    assert(dp);
    deque_init(dp);

    return dp;
}

void deque_init(deque_t *dp)
{
    dp->head = NULL;
    dp->tail = NULL;
}

void deque_deinit(deque_t *dp)
{
    assert(dp);
    while (dp->tail)
        deque_pop(dp);
}

void deque_free(deque_t *dp)
{
    assert(dp);
    deque_deinit(dp);
    free(dp);
}

size_t deque_count(deque_t *dp)
{
    assert(dp);
    size_t n = 0;

    for(deque_item_t *i=dp->head; i; i=i->next)
        ++n;

    return n;
}

void deque_append(deque_t *dp, void *p)
{
    assert(dp);
    deque_item_t *i = (deque_item_t *)malloc(sizeof(deque_item_t));
    assert(i);

    i->p = p;
    i->next = NULL;
    i->prev = dp->tail;

    if (dp->tail)
        dp->tail->next = i;
    else
        dp->head = i;
    dp->tail = i;
}

void *deque_pop(deque_t *dp)
{
    assert(dp);
    deque_item_t *i = dp->tail;
    assert(i);
    void *p = i->p;

    dp->tail = i->prev;
    if (i->prev)
        i->prev->next = NULL;
    else
        dp->head = NULL;
    free(i);

    return p;
}

void *deque_peek(deque_t *dp)
{
    assert(dp);
    deque_item_t *i = dp->tail;
    assert(i);
    void *p = i->p;

    return p;
}

void deque_appendleft(deque_t *dp, void *p)
{
    assert(dp);
    deque_item_t *i = (deque_item_t *)malloc(sizeof(deque_item_t));
    assert(i);

    i->p = p;
    i->next = dp->head;
    i->prev = NULL;

    if (dp->head)
        dp->head->prev = i;
    else
        dp->tail = i;
    dp->head = i;
}

void *deque_popleft(deque_t *dp)
{
    assert(dp);
    deque_item_t *i = dp->head;
    assert(i);
    void *p = i->p;

    dp->head = i->next;
    if (i->next)
        i->next->prev = NULL;
    else
        dp->tail = NULL;
    free(i);

    return p;
}

void *deque_peekleft(deque_t *dp)
{
    assert(dp);
    deque_item_t *i = dp->head;
    assert(i);
    void *p = i->p;

    return p;
}

void deque_remove(deque_t *dp, deque_item_t *dip)
{
    assert(dp);
    assert(dip);

    if (dip->prev)
    {
        assert(dip->prev->next == dip);
        dip->prev->next = dip->next;
    }
    else
    {
        assert(dp->head == dip);
        dp->head = dip->next;
    }
    if (dip->next)
    {
        assert(dip->next->prev == dip);
        dip->next->prev = dip->prev;
    }
    else
    {
        assert(dp->tail == dip);
        dp->tail = dip->prev;
    }

    free(dip);
}


buffer_t *buffer_new(int cap)
{
    assert(cap>0);
    buffer_t *bp = (buffer_t *)malloc(sizeof(buffer_t)+cap);
    assert(bp);

    buffer_init(bp, cap);

    return bp;
}

void buffer_init(buffer_t *bp, int cap)
{
    bp->cap = cap;
    bp->len = 0;
}

void buffer_free(buffer_t *bp)
{
    free(bp);
}

int buffer_eq(buffer_t *a, buffer_t *b)
{
    if (a->len == b->len)
    {
        const int n = a->len;
        for (int i=0; i<n; ++i)
            if (a->buf[i] != b->buf[i])
                return 0;
        return 1;
    }
    return 0;
}


static int naive_hash(buffer_t *bp)
{
    uint8_t sum = 0;

    for(uint8_t *i=bp->buf; i<bp->buf+bp->len; ++i)
        sum ^= *i;

    return sum;
}

static int ht256_hash(buffer_t *bp)
{
    access_t sum = {0};
    uintptr_t p = (uintptr_t)bp->buf;
    int n = bp->len;

    if (p&0x01 && n>=1)
    {
        *sum.u8 ^= *(uint8_t *)p++;
        n -= 1;
    }
    if (p&0x02 && n>=2)
    {
        *sum.u16 ^= *(uint16_t *)p++;
        n -= 2;
    }
    if (p&0x04 && n>=4)
    {
        *sum.u32 ^= *(uint32_t *)p++;
        n -= 4;
    }
    while (n>=8)
    {
        sum.u64 ^= *(uint64_t *)p++;
        n -= 8;
    }
    sum.u32[0] ^= sum.u32[1];
    sum.u32[1] = 0;
    if (n>=4)
    {
        *sum.u32 ^= *(uint32_t *)p++;
        n -= 4;
    }
    sum.u16[0] ^= sum.u16[1];
    sum.u16[1] = 0;
    if (n>=2)
    {
        *sum.u16 ^= *(uint16_t *)p++;
        n -= 2;
    }
    sum.u8[0] ^= sum.u8[1];
    sum.u8[1] = 0;
    if (n>=1)
    {
        *sum.u8 ^= *(uint8_t *)p++;
        n -= 1;
    }


    return sum.u8[0];
}

static int ht16_hash(buffer_t *bp)
{
    uint8_t ret = ht256_hash(bp);

    ret ^= ret >> 4;

    return ret & 0x0F;
}

hashtable_t *ht256_new(void)
{
    hashtable_t *htp = (hashtable_t  *)malloc(sizeof(hashtable_t)+256*sizeof(deque_t));
    htp->hash = ht256_hash;
//     htp->hash = naive_hash;
    htp->nbucket = 256;

    for (int i=0; i<256; ++i)
        deque_init(htp->bucket+i);

    return htp;
}

hashtable_t *ht16_new(void)
{
    hashtable_t *htp = (hashtable_t  *)malloc(sizeof(hashtable_t)+16*sizeof(deque_t));
    htp->hash = ht16_hash;
    htp->nbucket = 16;

    for (int i=0; i<16; ++i)
        deque_init(htp->bucket+i);

    return htp;
}

void ht_deinit(hashtable_t *htp)
{
    assert(htp);

    for (int i=0; i<htp->nbucket; ++i)
//         deque_deinit(&htp->bucket[i]);
    {
        deque_t *dp = &htp->bucket[i];
        while (dp->head)
        {
            ht_node_t *hnp = (ht_node_t *)deque_popleft(dp);
//             buffer_free(hnp->key);
            free(hnp);
        }
    }
}

void ht_free(hashtable_t *htp)
{
    assert(htp);
    ht_deinit(htp);
    free(htp);
}

void *ht_search(hashtable_t *htp, buffer_t *key)
{
    assert(htp);
    assert(key);

    DEQUE_FOREACH(i, htp->bucket+htp->hash(key))
    {
        if (buffer_eq(key, ((ht_node_t *)i->p)->key))
            return ((ht_node_t *)i->p)->value;
    }

    return NULL;
}

void *ht_insert(hashtable_t *htp, buffer_t *key, void *value)
{
    assert(htp);
    assert(key);

    ht_node_t *node = (ht_node_t *)malloc(sizeof(ht_node_t));
    node->key = key;
    node->value = value;

    deque_appendleft(&htp->bucket[htp->hash(key)], (void *)node);
}

int ht_delete(hashtable_t *htp, buffer_t *key)
{
    assert(htp);
    assert(key);

    deque_t *dp = htp->bucket+htp->hash(key);
    DEQUE_FOREACH(i, dp)
    {
        if (buffer_eq(key, ((ht_node_t *)i->p)->key))
        {
            free((ht_node_t *)i->p);
            deque_remove(dp, i);
//             buffer_free(((ht_node_t *)i)->key);
//             free(i);
            return 1;
        }
    }

    return 0;
}


void dump_hex(const unsigned char *buf, size_t len, const char *indent)
{
    size_t i;

    for(i=0; i<len; ++i)
    {
        if (i%16==0)
            fputs(indent, stderr);
        fprintf(stderr, "%02X", buf[i]);
        switch (i%16)
        {
            case 7:
                fputs("   ", stderr);
                break;
            case 15:
                fputc('\n', stderr);
                break;
            default:
                fputc(' ', stderr);
                break;
        }
    }
    if (i%16)
        fputc('\n', stderr);
}

void dump_addr(struct sockaddr *sa, const char *indent)
{
    fprintf(stderr, "%s%s\n", indent, sdump_addr(sa));
}

const char *sdump_addr(struct sockaddr *sa)
{
    static char buf[1024];

    switch (sa->sa_family)
    {
        case AF_INET:
            memmove(buf, "INET: ", 6);
            inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, buf+6, sizeof(buf)-6);
            sprintf(buf+strlen(buf), ":%d", ntohs(((struct sockaddr_in *)sa)->sin_port));
            break;
        case AF_INET6:
            memmove(buf, "INET6: [", 8);
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, buf+8, sizeof(buf)-8);
            sprintf(buf+strlen(buf), "]:%d", ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
            break;
        default:
            memmove(buf, "unknown", 8);
            break;
    }

    return buf;
}
