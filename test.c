#include <stdio.h>

void print1();

static void (*funcptr)() = &print1;

void print2() {
    printf("2\n");
}

int main() {
    funcptr();
    print2();
}

void print1() {
    printf("1\n");
}
