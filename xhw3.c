#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include "xhw3.h"
#define __NR_submitjob 359

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

/* Global counter for jobs */
static int job_id;

pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
/**
 * generate_key
 * @password: password from which key has to be generated
 *
 * A key is generated from password entered by user. It is directly stored in enc_key array in user_args_t struct instance
 *
 * Returns 0 on success; non-zero otherwise
 */
int generate_key(char *password, struct enc_struct *e1)
{
	int iterations = 10000;
	int err;

	err = PKCS5_PBKDF2_HMAC_SHA1(password,
			       strlen(password),
			       NULL,
			       0,
			       iterations, 16, e1->enc_key);

	return err;
}

/**
 * has_non_ascii_char
 * @str: string to check if it has non-ASCII character/s
 *
 * Determines if str has any non-ASCII character
 *
 * Returns 1 if any non-ASCII character found; else returns 0
 */
int has_non_ascii_char(const char *str)
{
	int i;

	for (i = 0; str[i]; i++)
		if (!isascii(str[i]))
			return 1;
	return 0;
}
/**
 * basic_validation
 * @str: string to validate
 *
 * Ensures string has length > 0 and has only ascii characters
 * Returns -2 on error, 0 otherwise
 */
int basic_validation(char *str)
{
	int err = 0;

	if (strlen(str) == 0) {
		fprintf(stderr, "Invalid string of length 0\n");
		err = -2;
		goto out;
	}
	if (has_non_ascii_char(str)) {
		fprintf(stderr, "non-ascii character\n");
		err = -2;
		goto out;
	}

out:
	return err;
}
/**
 * comp_display()
 *
 * Displays option for compression
 */
inline void comp_display(void)
{
	printf("Enter type:\n"
		"1. deflate\n"
		"2. lz4\n"
		"3. lz4hc\n"
		"Choice:");
}
/**
 * clear_buf
 *
 * Clears stale characters from stdin
 */
inline void clear_buf(void)
{
	while (getchar() != '\n')
	;
}
/**
 * init_comp_file
 * @c1: pointer to struct of type comp_struct
 *
 * Handles data to be input for  compression option
 * Returns 0 on success;-1 if user typed ctrl+D, -2 on error
 */
int init_comp_file(struct comp_struct *c1)
{
	int type;
	char in[256], *res, d, c;
	int err = 0;
	struct stat sb_in;

	printf("Enter filename: ");
	if (scanf(" %255[^\n]", in) == EOF) {
		err = -1;
		goto out;
	}

	comp_display();
	while ((err = scanf("%d%c", &type, &c)) != 2  || c != '\n' ||  type <= 0 || type > 3) {
		if (err == EOF)
			goto out;
		printf("Incorrect choice\n");
		clearerr(stdin);
		comp_display();
		while (err != 2 && (d = getchar()) != '\n') {
			if (d == -1)
				goto out;
		}

	}

	res = realpath(in, c1->input_file);
	if (!res) {
		perror("error: ");
		return -2;
	}

	err = basic_validation(in);
	if (err)
		return err;
	c1->comp_type = COMPRESS * 10 + type;
	if (stat(c1->input_file, &sb_in) == -1) {
		printf("file does not exist");
		return -2;
	}
	if (sb_in.st_size >= 4095) {
		printf("file size cannot be greater than 4095\n");
		return -2;
	}
	return 0;

out:
	return err;
}
/**
 * chksum_display
 *
 * Displays options related to checksum
 */
inline void chksum_display(void)
{
	printf("Enter type:\n"
		"1. MD5\n"
		"2. SHA1\n"
		"3. SHA512\n"
		"Choice:");
}
/**
 * init_chksum_file
 * @c1: pointer to struct of type comp_struct
 *
 * Handles data to be input for checksum option
 * Returns 0 on success, -1 if user typed ctrl+D, -2 on error
 */
int init_chksum_file(struct comp_struct *c1)
{
	int type;
	char in[256], *res, d, c;
	int err = 0;
	int dlen[4] = {0, 16, 20, 64};

	printf("Enter filename: ");
	if (scanf(" %255[^\n]", in) == EOF) {
		err = -1;
		goto out;
	}

	chksum_display();
	while ((err = scanf("%d%c", &type, &c)) != 2  || c != '\n' ||  type <= 0 || type > 3) {
		if (err == EOF) {
			err = -1;
			goto out;
		}
		printf("Incorrect choice\n");
		clearerr(stdin);
		chksum_display();
		while (err != 2 && (d = getchar()) != '\n') {
			if (d == -1) {
				err = -1;
				goto out;
			}
		}
	}

	c1->digest_len = dlen[type];
	res = realpath(in, c1->input_file);
	if (!res) {
		perror("error: ");
		return -2;
	}

	err = basic_validation(in);
	if (err)
		return err;
	c1->comp_type = CHECKSUM*10 + type;
	return 0;

out:
	return err;
}

/*
 * init_job_id_to_be_removed
*/
int init_job_id_to_be_removed(struct op_struct *r1)
{
	int err = 0, job_id = 0;

	printf("Enter job id to be removed: ");
	while ((err = scanf("%d", &job_id)) != 1) {
		if (err == EOF) {
			err = -1;
			goto out;
		}
		printf("error: invalid id!\nEnter job id to be removed: ");
		while (getchar() != '\n')
		;
	}
	err = 0;

out:
	r1->id = job_id;
	r1->priority = 1;
	return err;
}


int init_change_priority_param(struct op_struct *p1)
{
	int err = 0, job_id = 0, priority = 0;

	printf("Enter job id: ");
	while ((err = scanf("%d", &job_id)) != 1) {
		if (err == EOF) {
			err = -1;
			goto exit;
		}

		printf("error: invalid id!\nenter job id: ");
		while (getchar() != '\n')
		;
	}

	printf("Enter new priority: ");
	while ((err = scanf("%d", &priority)) != 1) {
		if (err == EOF) {
			err = -1;
			goto exit;
		}
retry_p:
		printf("error: invalid priority\nEnter new priority: ");
		while (getchar() != '\n')
		;
	}

	if ((priority < 1) || (priority > 256))
		goto retry_p;
	err = 0;

exit:
	p1->id = job_id;
	p1->priority = priority;

	return err;
}

int set_priority(struct job_info *my_job)
{
	char c, s1 = 'N';
	int err = 0, priority = 1, d = 0;

	printf("Set priority[y\\N]:");
	while ((err = scanf("%c%c", &s1, &c)) != 2  || c != '\n' || (s1 != 'y' && s1 != 'Y' && s1 != 'N' && s1 != 'n')) {
		if (err == EOF) {
			return -1;
		}
		printf("error: invalid choice\nSet priority[y\\N]:");
		clearerr(stdin);
		while (c != '\n' && (d = getchar()) != '\n') {
			if (d == -1) {
				return -1;
			}
		}

	}
	if (s1 == 'y' || s1 == 'Y') {
		printf("Enter priority:");
		while ((err = scanf("%d%c", &priority, &c)) != 2  || c != '\n' ||  priority < 1 || priority > 256) {
			if (err == EOF) {
				return -1;
			}
			printf("error: invalid priority\nEnter priority:");
			clearerr(stdin);
			while (err != 2 && (d = getchar()) != '\n') {
				if (d == -1) {
					return -1;
				}
			}
		}
	}
	my_job->priority = priority;
	return 0;
}

int init_input_file(struct enc_struct *e1)
{
	char in[256], *res;
	char password[256] = {0};
	int err;

	printf("Enter filename: ");
	if (scanf(" %255[^\n]", in) == EOF) {
		err = -1;
		goto out;
	}

	printf("Enter password (minimum 6 characters) :");
	if (scanf(" %255[^\n]", password) == EOF) {
		err = -1;
		goto out;
	}

	password[strcspn(password, "\n")] = 0;
	if (strlen(password) < 6) {
		puts("password length too short");
		return -2;
	}
	res = realpath(in, e1->input_file);
	if (!res) {
		perror("error: ");
		return -2;
	}

	err = basic_validation(in);
	if (err)
		return err;

	err = basic_validation(password);
	if (err)
		return err;
	err = generate_key(password, e1);
	return 0;

out:
	return err;
}

int init_concat(struct concat_struct *c1)
{
	char con_ip[1024];
	char *token, *end, *tmp_con_ip, *res;
	int i, err, k, count_files = 0;

	printf("Enter files for concat.\nFormat: infile1 [infile2] [infile3] .... outputfile\n");
	err = scanf(" %[^\n]", con_ip);
	if (err == EOF) {
		free(c1);
		goto unlock;
	}
	tmp_con_ip = strdup(con_ip);
	token = con_ip;
	end = con_ip;

	while ((token = strsep(&end, " "))) {
		if (!*token)
			continue;
		if (strlen(token) > 256) {
			printf("Filename can't exceed 256 characters\n");
			goto length_error;
		}
		count_files++;
	}
	if (count_files < 2) {
		printf("Number of files should be atleast two\n");
		goto less_files;
	}
	c1->no_of_infiles = (count_files - 1);
	c1->input_files = malloc(sizeof(char *) * (count_files - 1));

	token = tmp_con_ip;
	end = tmp_con_ip;
	i = 0;
	while ((token = strsep(&end, " "))) {
		if (!*token)
			continue;
		if (i == count_files - 1) {
			c1->out = malloc(sizeof(char *) * 256);
			realpath(token, c1->out);
			break;
		}
		c1->input_files[i] = (char *) malloc(sizeof(char *) * 256);
		res = realpath(token, c1->input_files[i++]);
		if (!res) {
			perror("error ");
			goto free_file;
		}
	}
	return count_files;

free_file:
	for (k = 0; k < i; k++)
		if (c1->input_files[k])
			free(c1->input_files[k]);
	if (c1->input_files)
		free(c1->input_files);
	if (c1->out)
		free(c1->out);
	c1->input_files = NULL;
	printf("Invalid arguments. Ignoring this job\n");

length_error:
	if (c1)
		free(c1);
	c1 = NULL;
less_files:
	return -2;
unlock:
	return -1;
}

/**
 * thread_function
 *
 * Calls system call for each job and requests for callback
 *
 */
void *thread_function(void *arg)
{
	int i, l = 0, rc = 0;
	int dlen[4] = {0, 16, 20, 64};
	char job_type_str[11][14] = {"", "ENCRYPT", "DECRYPT", "CONCAT", "CHECKSUM", "COMPRESS", "DECOMPRESS", "LIST", "CHNG PRIORITY", "REMOVE", "REMOVE ALL"};
	char time_st[30] = {0};
	char time_et[30] = {0};
	double s_time, cpu_time;
	struct sockaddr_nl src_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	int sock_fd;
	struct msghdr msg;
	struct job_info *my_job = (struct job_info *)arg;
	FILE *f;
	time_t stime, etime;
	char status[8];

retry:
	sock_fd = socket(PF_NETLINK, SOCK_RAW, CALLER_NETLINK);
	if (sock_fd < 0) {
		rc++;
		if (rc == 2) {
			perror("error: ");
			pthread_exit(NULL);
		}
		goto retry;
	}
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = pthread_self();
	bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	my_job->pid = pthread_self();

	/* assign job id before submitting job */
	job_id++;
	my_job->job_id = job_id;
	s_time = (double)(clock());

	rc = syscall(__NR_submitjob, my_job, 42);
	stime = time(NULL);
	snprintf(time_st, 29, "%s", ctime(&stime));
	time_st[strcspn(time_st, "\n")] = 0;
	time_st[29] = 0;

	if (rc == 0) {
		recvmsg(sock_fd, &msg, 0);
		etime = time(NULL);
		snprintf(time_et, 29, "%s", ctime(&etime));
		if (my_job->job_type == CHECKSUM) {
			struct comp_struct *c1 = (struct comp_struct *)my_job->job_struct;

			l = c1->comp_type;
			printf("Checksum for file %s:\n", c1->input_file);
			for (i = 0; i < dlen[l % 4]; i++)
				printf("%02x", ((char *)NLMSG_DATA(nlh))[i] & 0xFF);
			puts("");
			if (c1) {
				free(c1);
				c1 = NULL;
			}
		} else
			printf("%s\n", (char *)NLMSG_DATA(nlh));

		if (strstr((char *)NLMSG_DATA(nlh), "fail"))
			strcat(status, "Failure");
		else
			strcat(status, "Success");

	} else {
		printf("\nsyscall failed with errno[%d] for job: id[%d] type[%d]\n", errno, my_job->job_id, my_job->job_type);
		perror("error");
	}

	cpu_time = (((double) (clock()) - s_time) * 1000.0) / CLOCKS_PER_SEC;
	f = fopen("log.txt", "a+");
	fprintf(f, "%5d|%8d|%13s|%8s|%9f|%25s|%26s",
		   my_job->job_id, my_job->job_type, job_type_str[my_job->job_type], status, (double)(etime - stime), time_st, time_et);

	fclose(f);


	if (sock_fd)
		close(sock_fd);

	if (my_job->job_type == CONCAT) {

		struct concat_struct *c1 = my_job->job_struct;

		if (c1->no_of_infiles > 0) {
			for (i = 0; i < c1->no_of_infiles - 1; i++)
				if (c1 != NULL && c1->input_files[i] != NULL)
					free(c1->input_files[i]);
		}

		if (c1 != NULL && c1->out != NULL)
			free(c1->out);

		if (c1 != NULL && c1->input_files != NULL)
			free(c1->input_files);

		if (c1 != NULL)
			free(c1);
	}

	if (my_job->job_type == LIST
			|| my_job->job_type == REMOVE
			|| my_job->job_type == REMOVE_ALL
			|| my_job->job_type == CHANGE_PRIORITY) {
		if (arg)
			free(arg);
		return NULL;
	} else {
		if (arg)
			free(arg);
		pthread_exit(NULL);
	}
}

inline void menu_display(void)
{
	printf("Enter job type:\n"
		"1. Encrypt\n"
		"2. Decrypt\n"
		"3. Concat\n"
		"4. Checksum\n"
		"5. Compress\n"
		"6. Decompress\n"
		"7. List pending jobs\n"
		"8. Change priority\n"
		"9. Remove job by id\n"
		"10. Remove all jobs\n"
		"11. Exit\n"
		"Choice: ");
}

int main(int argc, const char *argv[])
{
	int type = 0, file_count = 0, err = 0;
	const char *header = "JOBID| JOBTYPE|      JOBNAME|  STATUS| RUN TIME|               START TIME|                 END TIME|";
	char c, d;

	FILE *f = fopen("log.txt", "w+");

	if (f == NULL) {
		printf("Error opening file!\n");
		exit(1);
	}

	fprintf(f, "%s\n", header);
	fprintf(f, "%s\n", "----------------------------------------------------------------------------------------------------");
	fclose(f);

	while (1) {
		menu_display();
		while ((err = scanf("%d%c", &type, &c)) != 2  || c != '\n' ||  type <= 0 || type > 11) {
			if (err == EOF)
				goto out;
			printf("Incorrect choice\n");
			clearerr(stdin);
			menu_display();
			while (err != 2 && (d = getchar()) != '\n') {
				if (d == -1)
					goto out;
			}
		}
		switch (type) {
		case ENCRYPT:
		{
			struct enc_struct e1;
			struct job_info *my_job;
			pthread_t thread_id;

			my_job = malloc(sizeof(*my_job));
			my_job->job_type = ENCRYPT;
			err = init_input_file(&e1);
			if (err == -1)
				goto out;
			if (err < 0)
				break;
			clear_buf();
			err = set_priority(my_job);
			if (err < 0)
				goto out;
			my_job->job_struct = &e1;
			pthread_create(&thread_id, NULL, &thread_function, my_job);
			break;
		}
		case CONCAT:
		{
			struct concat_struct *c1 = NULL;
			struct job_info *my_job;
			pthread_t thread_id;

			my_job = malloc(sizeof(*my_job));
			my_job->job_type = CONCAT;
			c1 = malloc(sizeof(struct concat_struct));
			if (!c1) {
				printf("Couldn't allocate memory for struct concat_struct.Ignoring this job\n");
				break;
			}

			file_count = init_concat(c1);
			if (file_count == -1)
				goto out;
			if (file_count <= 0)
				break;
			clear_buf();
			err = set_priority(my_job);
			if (err < 0)
				goto out;
			my_job->job_struct = (void *)c1;
			pthread_create(&thread_id, NULL, &thread_function, my_job);
			break;
		}
		case DECRYPT:
		{
			struct enc_struct e1;
			struct job_info *my_job;
			pthread_t thread_id;

			my_job = malloc(sizeof(*my_job));
			my_job->job_type = DECRYPT;
			err = init_input_file(&e1);
			if (err == -1)
				goto out;
			if (err < 0)
				break;
			clear_buf();
			err = set_priority(my_job);
			if (err < 0)
				goto out;
			my_job->job_struct = &e1;
			pthread_create(&thread_id, NULL, &thread_function, my_job);
			break;
		}
		case CHECKSUM:
		{
			struct comp_struct *c1;
			struct job_info *my_job;
			pthread_t thread_id;

			c1 = malloc(sizeof(struct comp_struct));
			my_job = malloc(sizeof(*my_job));
			my_job->job_type = CHECKSUM;
			err = init_chksum_file(c1);
			if (err)
				break;
			err = set_priority(my_job);
			if (err < 0)
				goto out;
			my_job->job_struct = c1;
			pthread_create(&thread_id, NULL, &thread_function, my_job);
			break;
		}
		case COMPRESS:
		{
			struct comp_struct c1;
			struct job_info *my_job;
			pthread_t thread_id;

			my_job = malloc(sizeof(*my_job));
			my_job->job_type = COMPRESS;
			err = init_comp_file(&c1);
			if (err == -1)
				goto out;
			if (err < 0)
				break;
			err = set_priority(my_job);
			if (err < 0)
				goto out;
			my_job->job_struct = &c1;
			pthread_create(&thread_id, NULL, &thread_function, my_job);
			break;
		}
		case DECOMPRESS:
		{
			struct comp_struct c1;
			struct job_info *my_job;
			pthread_t thread_id;

			my_job = malloc(sizeof(*my_job));
			my_job->job_type = DECOMPRESS;
			err = init_comp_file(&c1);
			if (err == -1)
				goto out;
			if (err < 0)
				break;
			err = set_priority(my_job);
			if (err < 0)
				goto out;
			my_job->job_struct = &c1;
			pthread_create(&thread_id, NULL, &thread_function, my_job);
			break;

		}
		case LIST:
		{
			struct job_info *my_job;

			my_job = malloc(sizeof(*my_job));
			my_job->job_type = LIST;
			my_job->job_struct = NULL;

			thread_function(my_job);
			break;
		}
		case CHANGE_PRIORITY:
		{
			struct job_info *my_job;
			struct op_struct p1;

			my_job = malloc(sizeof(*my_job));
			my_job->job_type = CHANGE_PRIORITY;
			err = init_change_priority_param(&p1);
			if (err)
				goto out;
			my_job->job_struct = &p1;
			thread_function(my_job);
			break;
		}
		case REMOVE:
		{
			struct job_info *my_job;
			struct op_struct r1;

			my_job = malloc(sizeof(*my_job));
			my_job->job_type = REMOVE;
			err = init_job_id_to_be_removed(&r1);
			if (err)
				goto out;

			my_job->job_struct = &r1;
			thread_function(my_job);
			break;
		}
		case REMOVE_ALL:
		{
			struct job_info *my_job;

			my_job = malloc(sizeof(*my_job));
			my_job->job_type = REMOVE_ALL;
			my_job->job_struct = NULL;
			thread_function(my_job);
			break;
		}
		case EXIT:
			goto out;
		default:
			printf("Incorrect choice\n");
		}
	}
out:
	printf("exiting main thread\n");
	pthread_exit(NULL);
}
