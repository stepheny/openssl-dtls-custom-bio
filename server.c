#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>
#include <sys/epoll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "util.h"
#include "cbio.h"

enum
{
    TIME_OUT = 8000 // ms
};

hashtable_t *ht;

typedef struct client_s client_t;
struct client_s
{
    custom_bio_data_t data;
    SSL *ssl;
    void (*serve)(client_t *cli);
};

char cookie_str[] = "BISCUIT!";

void on_connect(client_t *cli);
void on_message(client_t *cli);

void on_connect(client_t *cli)
{
    int ret = SSL_accept(cli->ssl);
    fprintf(stderr, "SSL_accept -> %d\n", ret);
    int tmp;

    if (ret==1)
    {
        char buf[64];
        int n;

        dump_addr((struct sockaddr *)&cli->data.txaddr, "user connected: ");
        cli->serve = on_message;
        n = snprintf(buf, sizeof(buf), "hello, %s", sdump_addr((struct sockaddr *)&cli->data.txaddr));
        SSL_write(cli->ssl, buf, n);
    }
    else if ((tmp=SSL_get_error(cli->ssl, ret))==SSL_ERROR_SSL)
    {
        fprintf(stderr, "!!!! SSL_get_error -> %d\n", tmp);

        dump_addr((struct sockaddr *)&cli->data.txaddr, "ssl error: ");
        ERR_print_errors_fp(stderr);

        assert(ht_delete(ht, &cli->data.txaddr_buf));
        SSL_free(cli->ssl);
        free(cli);
    }
    else
    {
        fprintf(stderr, "!!!! SSL_get_error -> %d\n", tmp);
    }
}

void on_message(client_t *cli)
{
    char buf[2000];
    int n;

    n = SSL_read(cli->ssl, buf, sizeof(buf));

    fprintf(stderr, "SSL_read -> %d\n", n);
    fflush(stderr);

    if (n==0)
    {
        SSL_shutdown(cli->ssl);
        dump_addr((struct sockaddr *)&cli->data.txaddr, "|| ");
        assert(ht_delete(ht, &cli->data.txaddr_buf));
        SSL_free(cli->ssl);
        free(cli);
    }
    else if (n>0)
    {
        if (n==6 && strncmp(buf, "whoami", 6)==0)
        {
            const char *tmp = sdump_addr((struct sockaddr *)&cli->data.txaddr);
            SSL_write(cli->ssl, tmp, strlen(tmp));
        }
        else if (n==4 && strncmp(buf, "ping", 4)==0)
            SSL_write(cli->ssl, "pong", 4);
        else if (n>=5 && strncmp(buf, "echo ", 5)==0)
            SSL_write(cli->ssl, buf+5, n-5);
        else if (n==5 && strncmp(buf, "stats", 5)==0)
        {
            n = snprintf(buf, sizeof(buf), "users:");
            HT_FOREACH(i, ht)
            {
                n += snprintf(buf+n, sizeof(buf)-n, "\n%s", sdump_addr((struct sockaddr *)&((client_t *)i->value)->data.txaddr));
            }

            SSL_write(cli->ssl, buf, n);
        }
        else if (n>=3 && strncmp(buf, "bc ", 3)==0)
        {
            HT_FOREACH(i, ht)
            {
                SSL_write(((client_t *)i->value)->ssl, buf+3, n-3);
            }
        }
    }
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    memmove(cookie, cookie_str, sizeof(cookie_str)-1);
    *cookie_len = sizeof(cookie_str)-1;

    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    return sizeof(cookie_str)-1==cookie_len && memcmp(cookie, cookie_str, sizeof(cookie_str)-1)==0;
}

void signal_handler(int sig)
{
    if (sig==SIGINT)
        fprintf(stderr, "Interrupt from keyboard\n");
    else
        fprintf(stderr, "unknown signal[%d]\n", sig);
    fflush(stderr);
}

int main(int argc, char **argv)
{
    int ret;

    if (argc<=1)
    {
        fputs("usage:\n"
        "  server 127.0.0.1:1234\n"
        "  server 0.0.0.0:1234\n"
        "  server [::1]:1234\n"
        "  server [::]:1234\n"
        "  server [::]:1234 127.0.0.1:1234\n", stderr);

        exit(0);
    }

    deque_t *addrlist = deque_new();
    for (int i=1; i<argc; ++i)
    {
        fputs(argv[i], stderr);
        fputc('\n', stderr);

        buffer_t *bp;
        char *c;
        int p;

        if (argv[i][0]=='[')
        {
            c = strchr(argv[i], ']');
            if (!c)
                continue;
            p = atoi(c+2);
            if (p<1||p>65535)
                continue;
            *c = '\0';

            bp = buffer_new(sizeof(struct sockaddr_in6));
            bp->len = sizeof(struct sockaddr_in6);
            memset(bp->buf, 0, sizeof(struct sockaddr_in6));
            ((struct sockaddr_in6 *)bp->buf)->sin6_family = AF_INET6;

            ret = inet_pton(AF_INET6, argv[i]+1, &((struct sockaddr_in6 *)bp->buf)->sin6_addr);
            if (!ret)
            {
                buffer_free(bp);
                continue;
            }
            ((struct sockaddr_in6 *)bp->buf)->sin6_port = htons(p);
            deque_append(addrlist, bp);
        }
        else
        {
            c = strchr(argv[i], ':');
            if (!c)
                continue;
            p = atoi(c+1);
            if (p<1||p>65535)
                continue;
            *c = '\0';

            bp = buffer_new(sizeof(struct sockaddr_in));
            bp->len = sizeof(struct sockaddr_in);
            memset(bp->buf, 0, sizeof(struct sockaddr_in));
            ((struct sockaddr_in *)bp->buf)->sin_family = AF_INET;

            ret = inet_pton(AF_INET, argv[i], &((struct sockaddr_in *)bp->buf)->sin_addr);
            if (!ret)
            {
                buffer_free(bp);
                continue;
            }
            ((struct sockaddr_in *)bp->buf)->sin_port = htons(p);
            deque_append(addrlist, bp);
        }

    }

    SSL_load_error_strings();
    SSL_library_init();

    const SSL_METHOD *mtd = DTLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(mtd);
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_use_certificate_chain_file(ctx, "server-cert.pem");
    SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM);
    ret = SSL_CTX_load_verify_locations(ctx, "root-ca.pem", NULL);
    fprintf(stderr, "SSL_CTX_load_verify_locations -> %d\n", ret);
    ret = SSL_CTX_set_default_verify_file(ctx);
    fprintf(stderr, "SSL_CTX_set_default_verify_file -> %d\n", ret);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    int run = 0;
    struct epoll_event epe = {0};

    DEQUE_FOREACH(i, addrlist)
    {
        buffer_t *bp = (buffer_t *)i->p;
        assert(bp->len > 4);

        epe.data.fd = socket(((struct sockaddr *)bp->buf)->sa_family, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);

        fprintf(stderr, "new socket fd: %d\n", epe.data.fd);
        dump_addr((struct sockaddr *)bp->buf, "try bind: ");
        assert(bind(epe.data.fd, (struct sockaddr *)bp->buf, (socklen_t)bp->len) == 0);

        epe.events = EPOLLIN|EPOLLET;
        epoll_ctl(epfd, EPOLL_CTL_ADD, epe.data.fd, &epe);

        run = 1;
    }

    signal(SIGINT, signal_handler);

    ht = ht256_new();

    client_t *client = (client_t *)malloc(sizeof(client_t));
    client->ssl = SSL_new(ctx);
    deque_init(&client->data.rxqueue);
    client->data.txaddr_buf.cap = sizeof(struct sockaddr_storage);
    client->data.txaddr_buf.len = sizeof(struct sockaddr_storage);
    memset(&client->data.txaddr, 0, sizeof(struct sockaddr_storage));
    client->data.peekmode = 0;
    client->serve = on_connect;

                BIO *bio = BIO_new(BIO_s_custom());
                BIO_set_data(bio, (void *)&client->data);
                BIO_set_init(bio, 1);
                SSL_set_bio(client->ssl, bio, bio);

    buffer_t *packet;
    packet = buffer_new(2000);

    int new_line = 1;

    while (run)
    {
        ret = epoll_wait(epfd, &epe, 1, TIME_OUT);

        if (ret==-1)
            break;
        else if (ret==0)
        {
            time_t curtime;
            time(&curtime);
            char *tmp = ctime(&curtime);
            tmp[strlen(tmp)-1] = '\0';
            fprintf(stderr, "wall time: %s\r", tmp);
            new_line = 1;

//             HT_FOREACH(i, ht)
//             {
//                 SSL_write(((client_t *)i->value)->ssl, "tick", 4);
//             }

            continue;
        }

        if (new_line)
        {
            fputc('\n', stderr);
            new_line = 0;
        }

        while ((packet->len = recvfrom(epe.data.fd, packet->buf, packet->cap, 0, (struct sockaddr *)&client->data.txaddr, (socklen_t *)&client->data.txaddr_buf.len))>0)
        {
            dump_addr((struct sockaddr *)&client->data.txaddr, "<< ");

            client_t *cli = (client_t *)ht_search(ht, &client->data.txaddr_buf);
            if (cli)
            {
                deque_append(&cli->data.rxqueue, packet);
                cli->serve(cli);
            }
            else
            {
                    client->data.txfd = epe.data.fd;
                    deque_append(&client->data.rxqueue, packet);
                ret = DTLSv1_listen(client->ssl, NULL);
                fprintf(stderr, "DTLSv1_listen -> %d\n", ret);
                fflush(stderr);

                if (ret==1)
                {
                    buffer_t *key = &client->data.txaddr_buf;
                    ht_insert(ht, key, client);
                    dump_addr((struct sockaddr *)&client->data.txaddr, "++ ");
                    client->serve(client);


                    client = (client_t *)malloc(sizeof(client_t));
                    client->ssl = SSL_new(ctx);
                    deque_init(&client->data.rxqueue);
                    client->data.txaddr_buf.cap = sizeof(struct sockaddr_storage);
                    client->data.txaddr_buf.len = sizeof(struct sockaddr_storage);
                    memset(&client->data.txaddr, 0, sizeof(struct sockaddr_storage));
                    client->data.peekmode = 0;
                    client->serve = on_connect;

                    BIO *bio = BIO_new(BIO_s_custom());
                    BIO_set_data(bio, (void *)&client->data);
                    BIO_set_init(bio, 1);
                    SSL_set_bio(client->ssl, bio, bio);

                }
            }

            packet = buffer_new(2000);
        }
    }

    buffer_free(packet);

    SSL_free(client->ssl);
    free(client);

    HT_FOREACH(i, ht)
    {
        SSL_shutdown(((client_t *)i->value)->ssl);
        dump_addr((struct sockaddr *)&((client_t *)i->value)->data.txaddr, "|| ");
        SSL_free(((client_t *)i->value)->ssl);
        free((client_t *)i->value);
    }
    ht_free(ht);

    BIO_s_custom_meth_free();

    SSL_CTX_free(ctx);

    DEQUE_FOREACH(i, addrlist)
        buffer_free((buffer_t *)i->p);

    deque_free(addrlist);

    return 0;
}
