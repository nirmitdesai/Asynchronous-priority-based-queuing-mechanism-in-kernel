#ifndef XHW3_H_
#define XHW3_H_

#define ENCRYPT         1
#define DECRYPT         2
#define CONCAT          3

#define CHECKSUM        4
#define MD5           41
#define SHA1          42
#define SHA512        43

#define COMPRESS        5
#define DEFLATE       51
#define LZ4           52
#define LZ4HC         53

#define DECOMPRESS	6

#define LIST		7
#define CHANGE_PRIORITY	8
#define REMOVE		9
#define REMOVE_ALL	10
#define EXIT		11

/* maximum payload size*/
#define MAX_PAYLOAD   1024

/* Port number */
#define CALLER_NETLINK 	20

struct job_info {
	int job_type;
	int job_id;
	int priority;
	long long pid;
	void *job_struct;
};

struct enc_struct {
	char input_file[256];
	unsigned char enc_key[16];
};

struct comp_struct {
	char input_file[256];
	int comp_type;
	int digest_len;
};

struct concat_struct {
	char **input_files;
	char *out;
	int no_of_infiles;
};

struct op_struct {
	int id;
	int priority;
};
#endif
