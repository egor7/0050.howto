typedef struct C9aux C9aux;

struct C9aux {
    int sock;

    uint8_t *send;
    int nsend;
    
    uint8_t *recv;
    int nrecv;

    pthread_mutex_t *lock;
};
