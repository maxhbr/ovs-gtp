#include <config.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DST_PORT  2152
#define SRC_PORT  2152


static int
charToHex(char ch)
{
        if (ch >= 'A' && ch <= 'F') {
                return 10 + (ch - 'A');
        }
        if (ch >= 'a' && ch <= 'f') {
                return 10 + (ch - 'a');
        }
        if (ch >= '0' && ch <= '9') {
                return ch - '0';
        }
        return -1;
}

int
main(int argc, char *argv[])
{
    struct sockaddr_in addr, srcaddr;
    int fd;
    unsigned char *msg;
    char *str_buf;
    char *dst_ip;
    int len, i, j;

    if (argc != 3) {
        printf("two param expected\n");
        exit(1);
    }

    dst_ip = argv[1];
    printf("dst IP %s\n", dst_ip);
    str_buf = argv[2];
    len = strlen(str_buf);

    if (len % 2) {
        printf("len should be multiple of 2\n");
        exit (1);
    }

    msg = calloc(1, len);
    if (!msg) {
        exit(1);
    }
    j = 0;
    for (i = 0; i < len; i+=2) {

        int d1 = charToHex(str_buf[i]);
        if (d1 < 0) {
                printf("buf parse error\n");
                exit (1);
        }
        int d2 = charToHex(str_buf[i+1]);
        if (d2 < 0) {
                printf("buf parse error\n");
                exit (1);
        }
        msg[j++] = (d1 << 4) | d2;
    }
    len = len / 2;

#if 0
    printf("%d: ", len);
    for (i = 0; i < len; i++) {
        printf("%x", (int)msg[i]);
    }
    printf("\n");
#endif

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(dst_ip);
    addr.sin_port = htons(DST_PORT);

    memset(&srcaddr, 0, sizeof(srcaddr));
    srcaddr.sin_family = AF_INET;
    srcaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srcaddr.sin_port = htons(SRC_PORT);

    if (bind(fd, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (sendto(fd, msg, len, 0, (struct sockaddr *) &addr,
                sizeof(addr)) < 0) {
        perror("sendto");
    }
    printf("done\n");
    close(fd);
    return 0;
}
