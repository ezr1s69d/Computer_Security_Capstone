#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc , char *argv[])
{
    if (argc != 2) {
        printf("Usage: ./attack_server <port>\n");
        exit(1);
    }
    char inputBuffer[256] = {};
    int PORT = atoi(argv[1]);
    int sockfd = 0,forClientSockfd = 0;
    sockfd = socket(AF_INET , SOCK_STREAM , 0);

    if (sockfd == -1){
        printf("Fail to create a socket.");
    }

    struct sockaddr_in serverInfo,clientInfo;
    int addrlen = sizeof(clientInfo);
    bzero(&serverInfo,sizeof(serverInfo));

    serverInfo.sin_family = PF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(PORT);
    bind(sockfd,(struct sockaddr *)&serverInfo,sizeof(serverInfo));
    listen(sockfd,5);


    FILE *fp = fopen("/home/csc2025/110550010-110550101/aes-tool", "rb");
    if (!fp) {
        perror("fopen");
        exit(1);
    }
    // 取得檔案大小
    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // 配置 memory 並讀入檔案
    unsigned char *buffer = malloc(filesize);
    if (!buffer) {
        perror("malloc");
        fclose(fp);
        exit(1);
    }

    size_t bytesRead = fread(buffer, 1, filesize, fp);
    if (bytesRead != filesize) {
        fprintf(stderr, "fread: only read %zu of %ld bytes\n", bytesRead, filesize);
        free(buffer);
        fclose(fp);
        exit(1);
    }

    forClientSockfd = accept(sockfd, (struct sockaddr*) &clientInfo, &addrlen);
    send(forClientSockfd, buffer, bytesRead, 0);
    
    fclose(fp);
    free(buffer);
    
    return 0;
}
