#include "xhw3_k.h"

/**
 * compute_sha512_checksum
 * @in_buf: data whose checksum is to be found
 * @buf_len: length of data in bytes
 * @out_buf: buffer which contains checksum of in_buf
 *
 * Computes sha512 checksum of data pointed to by in_buf
 * run sha512sum filename to verify the sum
 *
 * Returns 0 on success, non-zero otherwise
 */
int compute_sha512_checksum(unsigned char *in_buf, int buf_len, unsigned char *out_buf)
{
	struct scatterlist sg;
	struct hash_desc desc;
	int err;

	desc.tfm = crypto_alloc_hash("sha512", 0, CRYPTO_ALG_ASYNC);
	pr_info("allocation done\n");
	if (IS_ERR(desc.tfm)) {
		err = PTR_ERR(desc.tfm);
		pr_info("error in allocating hash");
		goto ERR;
	}
	desc.flags = 0;
	sg_init_one(&sg, in_buf, buf_len);
	pr_info("sg inited\n");

	err = crypto_hash_init(&desc);
	if (err) {
		pr_info("error in initializing crypto hash\n");
		goto ERR;
	}
	pr_info("hash_inited\n");
	err = crypto_hash_update(&desc, &sg, buf_len);
	if (err) {
		pr_info("error in updating crypto hash\n");
		goto ERR;
	}
	if (err) {
		pr_info("error in updating crypto hash\n");
		goto ERR;
	}

	pr_info("crypto hash updated\n");
	err = crypto_hash_final(&desc, out_buf);
	if (err) {
		pr_info("error in finalizing crypto hash\n");
		goto ERR;
	}
	pr_info("hash finalised\n");
	crypto_free_hash(desc.tfm);
	return 0;
ERR:
	if (desc.tfm)
		crypto_free_hash(desc.tfm);
	return err;
}

/**
 * compute_sha512_checksum
 * @in_buf: data whose checksum is to be found
 * @buf_len: length of data in bytes
 * @out_buf: buffer which contains checksum of in_buf
 *
 * Computes sha1 checksum of data pointed to by in_buf
   run sha1sum filename on command-line to verify the checksum
 *
 * Returns 0 on success, non-zero on error
 */
int compute_sha1_checksum(unsigned char *in_buf, int buf_len, unsigned char *out_buf)
{
	struct scatterlist sg;
	struct hash_desc desc;
	int i, err;

	desc.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	pr_info("allocation done\n");
	if (IS_ERR(desc.tfm)) {
		err = PTR_ERR(desc.tfm);
		pr_info("error in allocating hash");
		goto ERR;
	}
	desc.flags = 0;
	sg_init_one(&sg, in_buf, buf_len);
	pr_info("sg inited\n");
	err = crypto_hash_init(&desc);
	if (err) {
		pr_err("error in initializing crypto hash\n");
		goto ERR;
	}
	pr_info("hash_inited\n");
	err = crypto_hash_update(&desc, &sg, buf_len);
	if (err) {
		pr_info("error in updating crypto hash\n");
		goto ERR;
	}
	if (err) {
		pr_info("error in updating crypto hash\n");
		goto ERR;
	}
	pr_info("crypto hash updated\n");
	err = crypto_hash_final(&desc, out_buf);
	if (err) {
		pr_info("error in finalizing crypto hash\n");
		goto ERR;
	}
	pr_info("hash finalised\n");
	for (i = 0; i < 20; i++)
		pr_info("%02x\n", out_buf[i] & 0xFF);

	crypto_free_hash(desc.tfm);
	return 0;
ERR:
	if (desc.tfm)
		crypto_free_hash(desc.tfm);
	return err;
}

/**
 * compute_sha512_checksum
 * @in_buf: data whose checksum is to be found
 * @buf_len: length of data in bytes
 * @out_buf: buffer which contains checksum of in_buf
 *
 * Computes md5 checksum of data pointed to by in_buf
   run md5sum filename to verify the sum
 *
 * Returns 0 on success, non-zero otherwise
 */
int compute_md5_checksum(unsigned char *in_buf, int buf_len, unsigned char *out_buf)
{
	struct scatterlist sg;
	struct hash_desc desc;
	int i, err;

	desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(desc.tfm)) {
		err = PTR_ERR(desc.tfm);
		pr_info("error in allocating hash");
		goto ERR;
	}
	desc.flags = 0;
	sg_init_one(&sg, in_buf, buf_len);
	err = crypto_hash_init(&desc);
	if (err) {
		pr_info("error in initializing crypto hash\n");
		goto ERR;
	}
	err = crypto_hash_update(&desc, &sg, buf_len);
	if (err) {
		pr_info("error in updating crypto hash\n");
		goto ERR;
	}

	err = crypto_hash_final(&desc, out_buf);
	if (err) {
		pr_info("error in finalizing crypto hash\n");
		goto ERR;
	}
	for (i = 0; i < 16; i++)
		pr_info("%02x", out_buf[i] & 0xFF);
	crypto_free_hash(desc.tfm);
	return 0;
ERR:
	if (desc.tfm)
		crypto_free_hash(desc.tfm);
	return err;
}

/**
 * compute_sha512_checksum
 * @ck: pointer to struct which contains data needed to compute checksum
 *
 * Opens file, reads data and calls appropriate function
 * based on parameter to find checksum of data
 *
 * Returns checksum of data on success, error otherwise
 */
char *do_checksum(struct comp_struct *ck)
{
	int rc = 0;
	unsigned char buf[BUF_SIZE] = {0};
	char *err = NULL;
	struct file *in_file;
	int i;

	pr_info("in dochecks, inp file = %s\n", ck->input_file);
	pr_info("comp type = %d\n", ck->comp_type);
	rc = get_file_handle(&in_file, ck->input_file, O_RDONLY, 0);
	if (rc)
		goto out;
	pr_info("file opened\n");
	while (1) {
		rc = read_from_file(in_file, buf, BUF_SIZE);
		if (rc == 0)
			break;
		if (rc < 0) {
			pr_info("error in reading file\n");
			goto out_infile;
		}
		switch (ck->comp_type) {
		case MD5:
			pr_info("computing md5\n");
			err = kzalloc(16, GFP_KERNEL);
			if (!err) {
				pr_info("error in malloc");
				goto out_infile;
			}
			rc = compute_md5_checksum(buf, strlen(buf), err);
			if (rc) {
				err = ERR_PTR(rc);
				goto out_infile;
			}
			break;
		case SHA1:
			pr_info("computing sha1\n");
			err = kzalloc(20, GFP_KERNEL);
			if (!err) {
				pr_info("error in malloc");
				goto out_infile;
			}

			rc = compute_sha1_checksum(buf, strlen(buf), err);
			if (rc) {
				err = ERR_PTR(rc);
				goto out_infile;
			}
			break;
		case SHA512:
			err = kzalloc(64, GFP_KERNEL);
			if (!err) {
				pr_info("error in malloc");
				goto out_infile;
			}

			rc = compute_sha512_checksum(buf, strlen(buf), err);
			if (rc) {
				err = ERR_PTR(rc);
				goto out_infile;
			}

			pr_info("===== in sha512\n");
			for (i = 0; i < 64; i++)
				printk("%02x", err[i] & 0xFF);
			break;
		default:
			pr_info("invalid value for checksum %d\n", ck->comp_type);
			break;
		}
	}
out_infile:
	if (in_file)
		filp_close(in_file, NULL);
out:
	return err;
}
