#ifndef XHW3_K_H_
#define XHW3_K_H_

#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include "xhw3.h"

void test(void);

int write_to_file(struct file *, char *, int);
int read_from_file(struct file *, char *, int);
int get_file_handle(struct file **, const char *, int, umode_t);
char *get_output_file(char *, char *);

/* Checksum related methods */
int basic_validations(struct enc_struct *);
int compute_md5_checksum(unsigned char *, int, unsigned char *);
int compute_sha1_checksum(unsigned char *, int, unsigned char *);
int compute_sha512_checksum(unsigned char *, int, unsigned char *);
char *do_checksum(struct comp_struct *);

/* Concat related methods */
int validate_concat_files(struct concat_struct *);
int concat_files(struct file *, struct file *);
int concatenation(struct concat_struct *);


/* Encryption Decryption related methods */
int handle_enc_dec(struct file *, unsigned char*, int, char*, int);
int do_encryption(struct enc_struct *);
int do_decryption(struct enc_struct *);

/* Compression related methods */
int do_compression(struct comp_struct *);
int compress_file(char*, char*, int, char*, char*);

/* Decompression related methods */
int do_decompression(struct comp_struct *);
int decompress_file(char*, char*, int, char*, char*);

#define AES_KEY_SIZE 16
#define BUF_SIZE 4096
#endif
