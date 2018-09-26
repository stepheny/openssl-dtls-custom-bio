#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>

#include "util.h"
#include "cbio.h"

// #define fprintf(...)

int BIO_s_custom_write_ex(BIO *b, const char *data, size_t dlen, size_t *written)
{
    fprintf(stderr, "BIO_s_custom_write_ex(BIO[0x%016lX], data[0x%016lX], dlen[%ld], *written[%ld])\n", b, data, dlen, *written);
    fflush(stderr);

    return -1;
}

int BIO_s_custom_write(BIO *b, const char *data, int dlen)
{
    int ret;
    custom_bio_data_t *cdp;

    ret = -1;
    fprintf(stderr, "BIO_s_custom_write(BIO[0x%016lX], buf[0x%016lX], dlen[%ld])\n", b, data, dlen);
    fflush(stderr);
    cdp = (custom_bio_data_t *)BIO_get_data(b);

    dump_addr((struct sockaddr *)&cdp->txaddr, ">> ");
//     dump_hex((unsigned const char *)data, dlen, "    ");
    ret = sendto(cdp->txfd, data, dlen, 0, (struct sockaddr *)&cdp->txaddr, cdp->txaddr_buf.len);
    if (ret >= 0)
        fprintf(stderr, "  %d bytes sent\n", ret);
    else
        fprintf(stderr, "  ret: %d errno: [%d] %s\n", ret, errno, strerror(errno));

    return ret;
}

int BIO_s_custom_read_ex(BIO *b, char *data, size_t dlen, size_t *readbytes)
{
    fprintf(stderr, "BIO_s_custom_read_ex(BIO[0x%016lX], data[0x%016lX], dlen[%ld], *readbytes[%ld])\n", b, data, dlen, *readbytes);
    fflush(stderr);

    return -1;
}

int BIO_s_custom_read(BIO *b, char *data, int dlen)
{
    int ret;
    custom_bio_data_t *cdp;
    deque_t *dp;
    buffer_t *bp;

    ret = -1;
    fprintf(stderr, "BIO_s_custom_read(BIO[0x%016lX], data[0x%016lX], dlen[%ld])\n", b, data, dlen);
    fprintf(stderr, "  probe peekmode %d\n",
            ((custom_bio_data_t *)BIO_get_data(b))->peekmode);
    fflush(stderr);

    cdp = (custom_bio_data_t *)BIO_get_data(b);
    dp = &cdp->rxqueue;
    fprintf(stderr, "  data[0x%016lX] queue: %d\n", dp, deque_count(dp));
    if (dp->head)
    {
        if (((custom_bio_data_t *)BIO_get_data(b))->peekmode)
            bp = (buffer_t *)deque_peekleft(dp);
        else
            bp = (buffer_t *)deque_popleft(dp);
        fprintf(stderr, "  buf[0x%016lX]\n", bp);
        fflush(stderr);

        ret = (bp->len<=dlen) ? bp->len : dlen;
        memmove(data, bp->buf, ret);

        if (!((custom_bio_data_t *)BIO_get_data(b))->peekmode)
            buffer_free(bp);
    }

    return ret;
}

int BIO_s_custom_gets(BIO *b, char *data, int size);

int BIO_s_custom_puts(BIO *b, const char *data);


long BIO_s_custom_ctrl(BIO *b, int cmd, long larg, void *pargs)
{
    long ret = 0;

//     fprintf(stderr, "BIO_s_custom_ctrl(BIO[0x%016lX], cmd[%d], larg[%ld], pargs[0x%016lX])\n", b, cmd, larg, pargs);
    fflush(stderr);

    switch(cmd)
    {
        case BIO_CTRL_FLUSH: // 11
        case BIO_CTRL_DGRAM_SET_CONNECTED: // 32
        case BIO_CTRL_DGRAM_SET_PEER: // 44
        case BIO_CTRL_DGRAM_GET_PEER: // 46
            ret = 1;
            break;
        case BIO_CTRL_WPENDING: // 13
            ret = 0;
            break;
        case BIO_CTRL_DGRAM_QUERY_MTU: // 40
        case BIO_CTRL_DGRAM_GET_FALLBACK_MTU: // 47
            ret = 1500;
//             ret = 9000; // jumbo?
            break;
        case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD: // 49
            ret = 96; // random guess
            break;
        case BIO_CTRL_DGRAM_SET_PEEK_MODE: // 71
            ((custom_bio_data_t *)BIO_get_data(b))->peekmode = !!larg;
            ret = 1;
            break;
        case BIO_CTRL_PUSH: // 6
        case BIO_CTRL_POP: // 7
        case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT: // 45
            ret = 0;
            break;
        default:
            fprintf(stderr, "BIO_s_custom_ctrl(BIO[0x%016lX], cmd[%d], larg[%ld], pargs[0x%016lX])\n", b, cmd, larg, pargs);
            fprintf(stderr, "  unknown cmd: %d\n", cmd);
            fflush(stderr);
            ret = 0;
            raise(SIGTRAP);
            break;
    }

    return ret;
}

int BIO_s_custom_create(BIO *b)
{
    fprintf(stderr, "BIO_s_custom_create(BIO[0x%016lX])\n", b);
    fflush(stderr);

    return 1;
}

int BIO_s_custom_destroy(BIO *b)
{
    fprintf(stderr, "BIO_s_custom_destroy(BIO[0x%016lX])\n", b);
    fflush(stderr);

    return 1;
}

// long BIO_s_custom_callback_ctrl(BIO *, int, BIO_info_cb *);

BIO_METHOD *_BIO_s_custom = NULL;
BIO_METHOD *BIO_s_custom(void)
{
    if (_BIO_s_custom)
        return _BIO_s_custom;

    _BIO_s_custom = BIO_meth_new(BIO_get_new_index()|BIO_TYPE_SOURCE_SINK, "BIO_s_custom");

//     BIO_meth_set_write_ex(_BIO_s_custom, BIO_s_custom_write_ex);
    BIO_meth_set_write(_BIO_s_custom, BIO_s_custom_write);
//     BIO_meth_set_read_ex(_BIO_s_custom, BIO_s_custom_read_ex);
    BIO_meth_set_read(_BIO_s_custom, BIO_s_custom_read);
    BIO_meth_set_ctrl(_BIO_s_custom, BIO_s_custom_ctrl);
    BIO_meth_set_create(_BIO_s_custom, BIO_s_custom_create);
    BIO_meth_set_destroy(_BIO_s_custom, BIO_s_custom_destroy);
//     BIO_meth_set_callback_ctrl(_BIO_s_custom, BIO_s_custom_callback_ctrl);

    return _BIO_s_custom;
}

void BIO_s_custom_meth_free(void)
{
    if (_BIO_s_custom)
        BIO_meth_free(_BIO_s_custom);

    _BIO_s_custom = NULL;
}

#undef fprintf
