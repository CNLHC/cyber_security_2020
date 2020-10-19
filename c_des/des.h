
#ifndef _DES_H_
#define _DES_H_

#define ENCRYPTION_MODE 1
#define DECRYPTION_MODE 0

typedef struct {
  unsigned char k[8];
  unsigned char c[4];
  unsigned char d[4];
} key_set;

void generate_key(unsigned char *key);
void generate_sub_keys(unsigned char *main_key, key_set *key_sets);
void process_message(unsigned char *message_piece,
                     unsigned char *processed_piece, key_set *key_sets,
                     int mode);

extern int initial_key_permutaion[];

extern int initial_message_permutation[];

extern int key_shift_sizes[];

extern int sub_key_permutation[];

extern int message_expansion[];

extern int S1[];

extern int S2[];

extern int S3[];

extern int S4[];

extern int S5[];

extern int S6[];

extern int S7[];

extern int S8[];

extern int right_sub_message_permutation[];

extern int final_message_permutation[];

#endif
