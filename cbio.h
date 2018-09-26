#ifndef CBIO_H
#define CBIO_H

typedef struct custom_bio_data_st {
    buffer_t txaddr_buf;
//     struct sockaddr txaddr;
    struct sockaddr_storage txaddr;
    deque_t rxqueue;
    int txfd;
    int peekmode;
} custom_bio_data_t;

int BIO_s_custom_write_ex(BIO *b, const char *data, size_t dlen, size_t *written);
int BIO_s_custom_write(BIO *b, const char *data, int dlen);
int BIO_s_custom_read_ex(BIO *b, char *data, size_t dlen, size_t *readbytes);
int BIO_s_custom_read(BIO *b, char *data, int dlen);
int BIO_s_custom_gets(BIO *b, char *data, int size);
int BIO_s_custom_puts(BIO *b, const char *data);
long BIO_s_custom_ctrl(BIO *b, int cmd, long larg, void *pargs);
int BIO_s_custom_create(BIO *b);
int BIO_s_custom_destroy(BIO *b);
// long BIO_s_custom_callback_ctrl(BIO *, int, BIO_info_cb *);

BIO_METHOD *BIO_s_custom(void);
void BIO_s_custom_meth_free(void);

#endif /* CBIO_H */
