typedef struct C9aux C9aux;

struct C9aux {
    uint8_t *message;
    int msize;

    int sock;

    C9t *t;
};
