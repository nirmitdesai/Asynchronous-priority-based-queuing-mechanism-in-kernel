#include "xhw3_k.h"

/**
 * validate_concat_files
 * @c1: instance of concat struct in question
 *
 * This function validates input files (can be more than one)
 * and output file. All input files should exists and for output file
 * if it doesn't exists then it will be created. Similarly, all input files
 * should have read permission and output file(if exists) should have
 * write permission. Filenames can't be more than 256 characters.
 *
 * Returns 0 on success else EINVAL/EACCESS if arguments are not valid.
 */
int validate_concat_files(struct concat_struct *c1)
{
	int error = 0, no_of_infiles, i;
	struct kstat f_in_stat, out_stat;
	mm_segment_t oldfs;

	if (!c1->out || !c1->input_files) {
		pr_info("output file is not given\n");
		error = -EINVAL;
		goto ERR;
	}
	if (strlen(c1->out) > 256) {
		error = -EINVAL;
		goto ERR;
	}
	no_of_infiles = c1->no_of_infiles;
	if (no_of_infiles < 1) {
		pr_err("at least 2 files should be given\n");
		error = -EINVAL;
		goto ERR;
	}
	for (i = 0; i < no_of_infiles; i++) {
		if (strlen(c1->input_files[i]) > 256) {
			error = -EINVAL;
			goto ERR;
		}
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		error = vfs_stat(c1->input_files[i], &f_in_stat);
		set_fs(oldfs);

		if (error) {
			pr_info("error in vfs_stat for %s\n", c1->input_files[i]);
			goto ERR;
		}

		if (!(S_ISREG(f_in_stat.mode))) {
			pr_info("first input file is not regular\n");
			error = -EINVAL;
			goto ERR;
		}
		if (!(f_in_stat.mode & S_IRUSR)) {
			pr_info("no read permission for %d input file", i);
			error = -EACCES;
			goto ERR;
		}
		pr_info("validated infile number %d\n", i);
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	error = vfs_stat(c1->out, &out_stat);
	set_fs(oldfs);

	if (!error) {
		if (!S_ISREG(out_stat.mode)) {
			pr_info("output file is not regular!");
			error = -EINVAL;
			goto ERR;
		}
		if (!(out_stat.mode & S_IWUSR)) {
			pr_info("no write permission for output file");
			error = -EACCES;
			goto ERR;
		}
	}
	error = 0;
ERR:
	return error;
}

/**
 * concat_files
 * @f_in: pointer to file in question from which data will be read
 * @temp_file:p pointer to file in question to which data will be written
 *
 * This function copy data from input file to temp file. f_pos for temp file
 * will be set to postion where data was written previously.
 *
 * Returns 0 on success else EFAULT read/write operation is unsuccessful.
 */
int concat_files(struct file *f_in, struct file *temp_file)
{
	int bytes_read = 0, error = 0, bytes_written = 0;
	char *buf;

	f_in->f_pos = 0;

	while (1) {
		pr_info("before read from file\n");
		buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
		bytes_read = read_from_file(f_in, buf, PAGE_SIZE);
		pr_info("after read from file\n");
		if (bytes_read != 0) {
			bytes_written = write_to_file(temp_file, buf, strlen(buf));
			if (bytes_written != strlen(buf)) {
				error = -EFAULT;
				goto ERR;
			}
		}
		kfree(buf);
		if (bytes_read == 0)
			break;
	}
ERR:
	return error;
}

/**
 * concatenation
 * @c1: instance of concat struct in question
 *
 * This function is an entry point for concat operation. It will create temp file
 * to which all input files will be concatinated. After successfull operation
 * this temp file will be renamed to given output file. If operation is unsuccessful
 * then this temp file will be unlinked.
 *
 * Returns 0 on success else returns appropriate error while opening file.
 */
int concatenation(struct concat_struct *c1)
{
	int error = 0, create_out_file = 0, ret = 0, no_of_infiles, i, count = 0, temp_err;
	umode_t out_mode = 0;
	mm_segment_t oldfs;
	struct kstat out_stat;
	struct file *temp_filp, *out_filp;
	struct dentry *lower_old_dentry, *lower_new_dentry;
	struct dentry *lower_old_dir_dentry, *lower_new_dir_dentry;
	struct dentry *trap = NULL;

	struct file *f_in_filp[c1->no_of_infiles];

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	error = vfs_stat(c1->out, &out_stat);
	set_fs(oldfs);

	if (error) {
		create_out_file = 1;
	} else {
		create_out_file = 0;
		out_mode = out_stat.mode;
	}

	no_of_infiles = c1->no_of_infiles;

	if (create_out_file == 0) {
		pr_info("Creating file with same permission as existing output file\n");
		error = get_file_handle(&(temp_filp), "/tmp/my_temp_file", O_WRONLY | O_CREAT | O_TRUNC, out_mode);
	} else {
		pr_info("creating file with default permission\n");
		error = get_file_handle(&(temp_filp), "/tmp/my_temp_file", O_WRONLY | O_CREAT | O_TRUNC, 0666 - current_umask());
	}
	if (error)
		goto ERR;

	temp_filp->f_pos = 0;
	pr_info("number of infiles recv %d\n", no_of_infiles);
	pr_info("Mode value is %o and create val is %d\n", out_mode, create_out_file);
	for (i = 0; i < no_of_infiles; i++) {
		pr_info("Inside infile %d for concat\n", i);
		error = get_file_handle(&f_in_filp[i], c1->input_files[i], O_RDONLY, 0);
		pr_info("error is %d\n", error);
		if (error)
			goto DO_UNLINK;
		count++;

		/* Concating files */
		ret = concat_files(f_in_filp[i], temp_filp);

		if (ret == 0) {
			pr_info("Successfully concated %d input file\n", i);
		} else {
			error = ret;
			goto DO_UNLINK;
		}
	}

	if (create_out_file == 1)
		error = get_file_handle(&(out_filp), c1->out, O_WRONLY | O_CREAT | O_TRUNC, 0666 - current_umask());
	else
		error = get_file_handle(&(out_filp), c1->out, O_WRONLY, 0);

	if (error)
		goto DO_UNLINK;

	lower_old_dentry = temp_filp->f_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dentry = out_filp->f_path.dentry;
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);

	error = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
				d_inode(lower_new_dir_dentry), lower_new_dentry,
					NULL, 0);
	if (error)
		pr_info("Unexpected Error:Error in vfs rename\n");

	goto RELEASE_LOCK;

DO_UNLINK:
	temp_err = error;
	pr_info("Unsuccessfull concat operation\n");
	error = vfs_unlink(d_inode(temp_filp->f_path.dentry->d_parent), temp_filp->f_path.dentry, NULL);
	if (error)
		pr_info("Error in unlink\n");

	error = temp_err;
	goto CLOSE_INFILES;
RELEASE_LOCK:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);

	filp_close(out_filp, NULL);
CLOSE_INFILES:
	for (i = 0; i < count; i++)
		filp_close(f_in_filp[i], NULL);

	filp_close(temp_filp, NULL);
ERR:
	return error;
}
