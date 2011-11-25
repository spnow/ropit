#ifndef _BYTE_ORDER_H_
#define _BYTE_ORDER_H_

#include <stdint.h>

#define endian_swap(x)              endian_swap_by_size(x, sizeof(x))

#define check_size(sz)              (((sz % 2) == 0 && sz <= 8) ? sz : 2)
#define host_to_file_order(x)       (arch_is_big_endian() ? x : endian_swap(x))
#define file_to_host_order(x)       (arch_is_big_endian() ? x : endian_swap(x))

#define host_to_file_order_by_size(x, sz)       (arch_is_big_endian() ? x : endian_swap_by_size(x, sz))
#define file_to_host_order_by_size(x, sz)       (arch_is_big_endian() ? x : endian_swap_by_size(x, sz))

int arch_is_big_endian();
uint64_t endian_swap_by_size (uint64_t x, int sz);
uint16_t endian_swap_16(uint16_t x);
uint32_t endian_swap_32(uint32_t x);
uint64_t endian_swap_64(uint64_t x);

#endif /* _BYTE_ORDER_H_ */
