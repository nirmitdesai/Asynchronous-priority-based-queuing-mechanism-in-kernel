#include "xhw3_k.h"

/*
 * handle_enc_dec
 * @f: file to which data will be written
 * @buf: data to be encrypted/decrypted
 * @n_bytes: no of bytes of buf to encrypt/decrypt
 * @key: key to encrypt/decrypt buf
 * @flags: 1 to encrypt, 0 to decrypt
 *
 * Returns 0 on success, err otherwise
*/
int handle_enc_dec(struct file *f, unsigned char *buf, int n_bytes, char *key, int flags)
{
	int err = 0, i, temp;
	struct crypto_blkcipher *blkcipher = NULL;
	unsigned char aes_key[AES_KEY_SIZE];

	unsigned char iv[AES_KEY_SIZE] = "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11";

	struct scatterlist sg;
	struct blkcipher_desc desc;

	if (n_bytes % AES_KEY_SIZE != 0) {
		pr_info("size not multiple of 16 for encryption\n");
		err = -EINVAL;
		goto ERR;
	}
	for (i = 0 ; i < AES_KEY_SIZE ; i++)
		aes_key[i] = key[i];

	blkcipher = crypto_alloc_blkcipher("cbc(aes)",  0, 0);
	if (IS_ERR(blkcipher)) {
		pr_info("could not allocate blkcipher handle for %s\n", "cbsaes");
		err = PTR_ERR(blkcipher);
		goto ERR;
	}

	if (crypto_blkcipher_setkey(blkcipher, aes_key, AES_KEY_SIZE)) {
		pr_info("key could not be set\n");
		err = -EAGAIN;
		goto ERR;
	}

	crypto_blkcipher_set_iv(blkcipher, iv, AES_KEY_SIZE);

	desc.flags = 0;
	desc.tfm = blkcipher;
	sg_init_one(&sg, buf, n_bytes);
	pr_info("sg iinited\n");
	/* encrypt data in place */
	if (flags == 1) {
		crypto_blkcipher_encrypt(&desc, &sg, &sg, n_bytes);

		pr_info("encryption done\n");
	} else {
		crypto_blkcipher_decrypt(&desc, &sg, &sg, n_bytes);
		pr_info("Decryption done\n");
	}

	pr_info("Cipher operation completed\n");

	temp = write_to_file(f, buf, n_bytes);

	if (blkcipher)
		crypto_free_blkcipher(blkcipher);

	err = 0;

ERR:
	return err;
}

/**
 * basic_validations
 * @e1: pointer to struct containing data required for encryption
 *
 * Returns 0 on success, non-zero otherwise
 */
int basic_validations(struct enc_struct *e1)
{
	int err = 0;
	struct kstat stat_in;
	mm_segment_t old_fs;

	if (strlen(e1->input_file) <= 0) {
		pr_info("Input file has invalid length\n");
		err = -EINVAL;
		goto out;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_stat(e1->input_file, &stat_in);
	set_fs(old_fs);
	if (err) {
		pr_info("error in vfs_stat for %s\n", e1->input_file);
		goto out;
	}

	if (!(S_ISREG(stat_in.mode))) {
		pr_info("input file is not regular\n");
		err = -EINVAL;
		goto out;
	}
	pr_info("All validations passed\n");

out:
	return err;
}

/*
 * do_encryption
 * @e1: pointer to struct containing data required for encryption
 *
 * Deals with encrypting the file
 * Returns 0 on success, err otherwise
 */
int do_encryption(struct enc_struct *e1)
{
	struct file *f, *out_file;
	int fz, padding_size, err = 0;
	char *output_file;
	char buf[BUF_SIZE];
	unsigned char pad[AES_KEY_SIZE], c[1];
	unsigned char enc_key_md5[16] = {0};

	err = compute_md5_checksum(e1->enc_key, AES_KEY_SIZE, enc_key_md5);
	if (err)
		goto out;

	output_file = get_output_file(e1->input_file, ".enc");
	if (IS_ERR(output_file)) {
		err = PTR_ERR(output_file);
		goto out;
	}

	err = get_file_handle(&f, e1->input_file, O_RDONLY, 0);
	if (err)
		goto out_free;

	fz = f->f_inode->i_size;
	padding_size = ((fz + 15) & -AES_KEY_SIZE) - fz;
	if (fz == 0)
		padding_size = 0x10;
	memset(pad, padding_size, padding_size);
	c[0] = padding_size;

	err = get_file_handle(&out_file, output_file, O_WRONLY | O_CREAT, 0666 - current_umask());
	if (err)
		goto out_infile;

	err = write_to_file(out_file, c, 1);
	err = write_to_file(out_file, enc_key_md5, AES_KEY_SIZE);

	if (fz == 0) {
		pr_info("zero length file\n");
		err = 0;
		goto out_outfile;
	}

	while (1) {
		err = read_from_file(f, buf, BUF_SIZE);
		if (err < 0) {
			pr_info("error in reading from file\n");
			goto out_outfile;
		}
		if (err == 0)
			break;
		if (err == BUF_SIZE) {
			err = handle_enc_dec(out_file, buf, BUF_SIZE, e1->enc_key, 1);
			if (err)
				goto out_outfile;
			continue;
		}
		if (padding_size) {
			pr_info("adding padding data to buffer\n");
			memcpy(buf + err, pad, padding_size);
			err = handle_enc_dec(out_file, buf, err + padding_size, e1->enc_key, 1);
			if (err)
				goto out_outfile;
		}
	}

	pr_info("\n");
	err = 0;

out_outfile:
	if (out_file && !IS_ERR(out_file))
		filp_close(out_file, NULL);
out_infile:
	if (f && !IS_ERR(f))
		filp_close(f, NULL);
out_free:
	if (output_file)
	kfree(output_file);
out:
	return err;
}

/*
 * do_decryption
 * @e1: pointer to struct containing data required for encryption
 *
 * Deals with decrypting the file
 * Returns 0 on success, err otherwise
*/
int do_decryption(struct enc_struct *e1)
{
	int i, err = 0, padding_size, fz;
	unsigned char buf[BUF_SIZE], enc_key_md5[16] = {0};
	struct file *in_file, *out_file;
	char *output_file = NULL;

	err = compute_md5_checksum(e1->enc_key, AES_KEY_SIZE, enc_key_md5);
	if (err)
		goto out;

	output_file = get_output_file(e1->input_file, ".dec");
	pr_info("output_file name for decryption %s\n", output_file);
	if (IS_ERR(output_file)) {
		err = PTR_ERR(output_file);
		goto out;
	}

	err = get_file_handle(&in_file, e1->input_file, O_RDONLY, 0);
	if (err)
		goto out_free;

	err = get_file_handle(&out_file, output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (err)
		goto out_infile;

	fz = in_file->f_inode->i_size - 17;
	err = read_from_file(in_file, buf, 17);

	for (i = 0 ; i < AES_KEY_SIZE ; i++) {
		if (enc_key_md5[i] != buf[i + 1]) {
			pr_info("invalid password to decrypt\n");
			err = -EACCES;
			goto out_outfile;
		}
	}

	padding_size = (int)buf[0];
	pr_info("padding size in this file = %d\n", padding_size);
	if (fz == 0) {
		err = 0;
		goto out_outfile;
	}
	while (1) {
		err = read_from_file(in_file, buf, BUF_SIZE);
		if (err == 0)
			break;
		if (err < 0) {
			pr_info("error in reading file\n");
			goto out_outfile;
		}
		err = handle_enc_dec(out_file, buf, err, e1->enc_key, 0);
		if (err)
			goto out_outfile;
	}

	vfs_truncate(&out_file->f_path, fz - padding_size);

out_outfile:
	if (out_file && !IS_ERR(out_file))
		filp_close(out_file, NULL);
out_infile:
	if (in_file && !IS_ERR(in_file))
		filp_close(in_file, NULL);
out_free:
	if (output_file)
		kfree(output_file);
out:
	return err;
}
