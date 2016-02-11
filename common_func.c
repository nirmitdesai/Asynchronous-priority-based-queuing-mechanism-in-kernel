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


/**
 * write_from_file
 * @filp_out: pointer to out file to which data must be written
 * @buf: The buffer to read data into
 * @len: Length in bytes of data to be read into buf
 *
 * Writes len bytes of data from buffer to the file pointed by filp_out. Expects filp_out to be opened.
 * Responsibility of closing it lies with the caller who requested the handle to filp_out
 *
 * Returns number of bytes written to the file
 */
int write_to_file(struct file *filp_out, char *buf, int len)
{
	int bytes_written;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	bytes_written = vfs_write(filp_out, buf, len, &(filp_out->f_pos));
	set_fs(old_fs);
	return bytes_written;
}

/**
 * read_from_file
 * @filp_in: pointer to input file from which data must be read
 * @buf: The buffer to read data into
 * @len: Length in bytes of data to be read into buf
 *
 * Reads len bytes of data from in buffer. Expects input file to be opened. Responsibility of closing
 * the input file lies with the caller who requested the handle
 *
 * Returns number of bytes read
 */
int read_from_file(struct file *filp_in, char *buf, int len)
{
	int bytes_read;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	bytes_read = vfs_read(filp_in, buf, len, &(filp_in->f_pos));

	set_fs(old_fs);
	return bytes_read;
}

/**
 * get_file_handle
 * @f: pointer to struct which contains information about input,temporary and output files
 * @file_name: file name to be opened
 * @flags: access mode of file (e.g O_RDONLY,O_WRONLY) and file creation flags (O_CREAT etc)
 * @mode: mode of file incase it has to be created. Is used when O_CREAT is specified in flags
 *
 * Opens the file as per flags and mode given. Responsibility of closing the file lies with the caller who invoked this function
 *
 * Returns zero on success; non-zero otherwise
 */
int get_file_handle(struct file **f, const char *file_name, int flags, umode_t mode)
{
	pr_info("file %s  will be opened with mode %o\n", file_name, mode);
	*f  = filp_open(file_name, flags, mode);
	if (!(*f) || IS_ERR(*f)) {
		pr_info("Files %s does not exist\n", file_name);
		return PTR_ERR(*f);
	}
	pr_info("opened file %s\n", file_name);
	return 0;
}

/**
 * gte_output_file
 * @inp_file: input file in question
 * @extn: extension for output file
 *
 * This function creates output file with specific extension as per requirement. This is
 * useful because output file is generated with specific extension based on operation performed
 * algorithm used.
 *
 * Returns pointer to output filename.
 */
char *get_output_file(char *inp_file, char *extn)
{

	int in_len, extn_len;
	char *output_file;

	in_len = strlen(inp_file);
	extn_len = strlen(extn);

	output_file = kmalloc(in_len + extn_len + 1, GFP_KERNEL);
	if (!output_file) {
		pr_info("Error allocating space for output file\n");
		return output_file;
	}

	strncpy(output_file, inp_file, in_len);
	output_file[in_len] = 0;

	strcat(output_file, extn);
	output_file[in_len + extn_len] = 0;
	return output_file;
}
