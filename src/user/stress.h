#ifndef STRESS_H_
#define STRESS_H_

void* hang(void*);
void* nohang(void*);
void* recur(void*);

// this one requires the fs to hold at least 5480 bytes for a file.
void* crash(void*);

#endif