#include "des.h"
#include <stdlib.h>
#include <string.h>


void generate_key(unsigned char *key) {
  for (int i = 0; i < 8; i++)
    key[i] = rand() % 255;
}

void generate_sub_keys(unsigned char *main_key, key_set *key_sets) {
  int i, j;
  int shift_size;
  unsigned char shift_byte, first_shift_bits, second_shift_bits,
      third_shift_bits, fourth_shift_bits;

  for (i = 0; i < 8; i++)
    key_sets[0].k[i] = 0;

  for (i = 0; i < 56; i++) {
    shift_size = initial_key_permutaion[i];
    shift_byte = 0x80 >> ((shift_size - 1) % 8);
    shift_byte &= main_key[(shift_size - 1) / 8];
    shift_byte <<= ((shift_size - 1) % 8);

    key_sets[0].k[i / 8] |= (shift_byte >> i % 8);
  }

  for (i = 0; i < 3; i++) {
    key_sets[0].c[i] = key_sets[0].k[i];
  }

  key_sets[0].c[3] = key_sets[0].k[3] & 0xF0;

  for (i = 0; i < 3; i++) {
    key_sets[0].d[i] = (key_sets[0].k[i + 3] & 0x0F) << 4;
    key_sets[0].d[i] |= (key_sets[0].k[i + 4] & 0xF0) >> 4;
  }

  key_sets[0].d[3] = (key_sets[0].k[6] & 0x0F) << 4;

  for (i = 1; i < 17; i++) {
    for (j = 0; j < 4; j++) {
      key_sets[i].c[j] = key_sets[i - 1].c[j];
      key_sets[i].d[j] = key_sets[i - 1].d[j];
    }

    shift_size = key_shift_sizes[i];
    if (shift_size == 1) {
      shift_byte = 0x80;
    } else {
      shift_byte = 0xC0;
    }

    // Process C
    first_shift_bits = shift_byte & key_sets[i].c[0];
    second_shift_bits = shift_byte & key_sets[i].c[1];
    third_shift_bits = shift_byte & key_sets[i].c[2];
    fourth_shift_bits = shift_byte & key_sets[i].c[3];

    key_sets[i].c[0] <<= shift_size;
    key_sets[i].c[0] |= (second_shift_bits >> (8 - shift_size));

    key_sets[i].c[1] <<= shift_size;
    key_sets[i].c[1] |= (third_shift_bits >> (8 - shift_size));

    key_sets[i].c[2] <<= shift_size;
    key_sets[i].c[2] |= (fourth_shift_bits >> (8 - shift_size));

    key_sets[i].c[3] <<= shift_size;
    key_sets[i].c[3] |= (first_shift_bits >> (4 - shift_size));

    // Process D
    first_shift_bits = shift_byte & key_sets[i].d[0];
    second_shift_bits = shift_byte & key_sets[i].d[1];
    third_shift_bits = shift_byte & key_sets[i].d[2];
    fourth_shift_bits = shift_byte & key_sets[i].d[3];

    key_sets[i].d[0] <<= shift_size;
    key_sets[i].d[0] |= (second_shift_bits >> (8 - shift_size));

    key_sets[i].d[1] <<= shift_size;
    key_sets[i].d[1] |= (third_shift_bits >> (8 - shift_size));

    key_sets[i].d[2] <<= shift_size;
    key_sets[i].d[2] |= (fourth_shift_bits >> (8 - shift_size));

    key_sets[i].d[3] <<= shift_size;
    key_sets[i].d[3] |= (first_shift_bits >> (4 - shift_size));

    for (j = 0; j < 48; j++) {
      shift_size = sub_key_permutation[j];
      if (shift_size <= 28) {
        shift_byte = 0x80 >> ((shift_size - 1) % 8);
        shift_byte &= key_sets[i].c[(shift_size - 1) / 8];
        shift_byte <<= ((shift_size - 1) % 8);
      } else {
        shift_byte = 0x80 >> ((shift_size - 29) % 8);
        shift_byte &= key_sets[i].d[(shift_size - 29) / 8];
        shift_byte <<= ((shift_size - 29) % 8);
      }

      key_sets[i].k[j / 8] |= (shift_byte >> j % 8);
    }
  }
}

void process_message(unsigned char *message_piece,
                     unsigned char *processed_piece, key_set *key_sets,
                     int mode) {
  int i, k, shift_size, key_index;
  unsigned char shift_byte;
  unsigned char initial_permutation[8];
  unsigned char l[4], r[4];
  unsigned char ln[4], rn[4], er[6], ser[4];

  memset(initial_permutation, 0, 8);
  memset(processed_piece, 0, 8);
  for (i = 0; i < 64; i++) {
    shift_size = initial_message_permutation[i];
    shift_byte = 0x80 >> ((shift_size - 1) % 8);
    shift_byte &= message_piece[(shift_size - 1) / 8];
    shift_byte <<= ((shift_size - 1) % 8);
    initial_permutation[i / 8] |= (shift_byte >> i % 8);
  }

  for (i = 0; i < 4; i++) {
    l[i] = initial_permutation[i];
    r[i] = initial_permutation[i + 4];
  }

  for (k = 1; k <= 16; k++) {
    memcpy(ln, r, 4);
    memset(er, 0, 6);

    for (i = 0; i < 48; i++) {
      shift_size = message_expansion[i];
      shift_byte = 0x80 >> ((shift_size - 1) % 8);
      shift_byte &= r[(shift_size - 1) / 8];
      shift_byte <<= ((shift_size - 1) % 8);
      er[i / 8] |= (shift_byte >> i % 8);
    }

    if (mode == DECRYPTION_MODE) {
      key_index = 17 - k;
    } else {
      key_index = k;
    }

    for (i = 0; i < 6; i++)
      er[i] ^= key_sets[key_index].k[i];

    unsigned char row, column;

    for (i = 0; i < 4; i++)
      ser[i] = 0;

    // 0000 0000 0000 0000 0000 0000
    // rccc crrc cccr rccc crrc cccr

    // Byte 1
    row = 0;
    row |= ((er[0] & 0x80) >> 6);
    row |= ((er[0] & 0x04) >> 2);

    column = 0;
    column |= ((er[0] & 0x78) >> 3);

    ser[0] |= ((unsigned char)S1[row * 16 + column] << 4);

    row = 0;
    row |= (er[0] & 0x02);
    row |= ((er[1] & 0x10) >> 4);

    column = 0;
    column |= ((er[0] & 0x01) << 3);
    column |= ((er[1] & 0xE0) >> 5);

    ser[0] |= (unsigned char)S2[row * 16 + column];

    // Byte 2
    row = 0;
    row |= ((er[1] & 0x08) >> 2);
    row |= ((er[2] & 0x40) >> 6);

    column = 0;
    column |= ((er[1] & 0x07) << 1);
    column |= ((er[2] & 0x80) >> 7);
    ser[1] |= ((unsigned char)S3[row * 16 + column] << 4);
    row = 0;
    row |= ((er[2] & 0x20) >> 4);
    row |= (er[2] & 0x01);
    column = 0;
    column |= ((er[2] & 0x1E) >> 1);
    ser[1] |= (unsigned char)S4[row * 16 + column];
    row = 0;
    row |= ((er[3] & 0x80) >> 6);
    row |= ((er[3] & 0x04) >> 2);
    column = 0;
    column |= ((er[3] & 0x78) >> 3);
    ser[2] |= ((unsigned char)S5[row * 16 + column] << 4);
    row = 0;
    row |= (er[3] & 0x02);
    row |= ((er[4] & 0x10) >> 4);
    column = 0;
    column |= ((er[3] & 0x01) << 3);
    column |= ((er[4] & 0xE0) >> 5);
    ser[2] |= (unsigned char)S6[row * 16 + column];
    // Byte 4
    row = 0;
    row |= ((er[4] & 0x08) >> 2);
    row |= ((er[5] & 0x40) >> 6);
    column = 0;
    column |= ((er[4] & 0x07) << 1);
    column |= ((er[5] & 0x80) >> 7);
    ser[3] |= ((unsigned char)S7[row * 16 + column] << 4);
    row = 0;
    row |= ((er[5] & 0x20) >> 4);
    row |= (er[5] & 0x01);
    column = 0;
    column |= ((er[5] & 0x1E) >> 1);
    ser[3] |= (unsigned char)S8[row * 16 + column];

    for (i = 0; i < 4; i++)
      rn[i] = 0;

    for (i = 0; i < 32; i++) {
      shift_size = right_sub_message_permutation[i];
      shift_byte = 0x80 >> ((shift_size - 1) % 8);
      shift_byte &= ser[(shift_size - 1) / 8];
      shift_byte <<= ((shift_size - 1) % 8);

      rn[i / 8] |= (shift_byte >> i % 8);
    }

    for (i = 0; i < 4; i++)
      rn[i] ^= l[i];

    for (i = 0; i < 4; i++) {
      l[i] = ln[i];
      r[i] = rn[i];
    }
  }

  unsigned char pre_end_permutation[8];
  for (i = 0; i < 4; i++) {
    pre_end_permutation[i] = r[i];
    pre_end_permutation[4 + i] = l[i];
  }

  for (i = 0; i < 64; i++) {
    shift_size = final_message_permutation[i];
    shift_byte = 0x80 >> ((shift_size - 1) % 8);
    shift_byte &= pre_end_permutation[(shift_size - 1) / 8];
    shift_byte <<= ((shift_size - 1) % 8);

    processed_piece[i / 8] |= (shift_byte >> i % 8);
  }
}
