#include "xhw3_k.h"

/**
 * compress_file
 * @inpfile: name of input file to be compressed
 * @buf: data to be compressed
 * @buf_len: length of data in buf to be compressed
 * @extn: extension of output file
 * @name: name of compression algorithm to use
 *
 * Uses crypto API to compress the data in buf. Compresses buf_len bytes
   and creates output file with extension extn.
   supports deflate, lz4, lz4hc
 */
int compress_file(char *inpfile, char *buf, int buf_len, char *extn, char *name)
{
	struct crypto_comp *tfm;
	char *output_file = NULL;
	int err;
	struct file *out_file;
	char result[512];
	unsigned int dlen = 512;

	tfm = crypto_alloc_comp(name, 0, 0);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		pr_err("could not alloc crypto comp %s : %ld\n", name, PTR_ERR(tfm));
		goto out;
	}
	memset(result, 0, sizeof(result));
	err = crypto_comp_compress(tfm, buf, buf_len, result, &dlen);
	if (err) {
		pr_err("compression failed\n");
		crypto_free_comp(tfm);
		goto out;
	}

	pr_info("dlen = %d\n", dlen);
	crypto_free_comp(tfm);

	output_file = get_output_file(inpfile, extn);
	if (IS_ERR(output_file)) {
		err = PTR_ERR(output_file);
		goto out;
	}

	pr_info("output file = %s\n", output_file);
	err = get_file_handle(&out_file, output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (err)
		goto out_free;

	err = write_to_file(out_file, result, dlen);
	pr_info("%d chars written to output file\n", err);
	err = 0;
	filp_close(out_file, NULL);

out_free:
	if (output_file)
		kfree(output_file);
out:
	return err;
}

/**
 * do_compression
 * @ck: pointer to struct which has data related to compression
 *
 * Central function which opens file, reads data and calls
   compress_file function with appropriate parameters
 */
int do_compression(struct comp_struct *ck)
{
	int err = 0;
	unsigned char buf[BUF_SIZE] = {0};
	struct file *in_file;

	pr_info("in dochecks, inp file = %s\n", ck->input_file);
	pr_info("comp type = %d\n", ck->comp_type);
	err = get_file_handle(&in_file, ck->input_file, O_RDONLY, 0);
	if (err)
		goto out;
	pr_info("file opened\n");
	while (1) {
		err = read_from_file(in_file, buf, BUF_SIZE);
		if (err == 0)
			break;
		if (err < 0) {
			pr_info("error in reading file\n");
			goto out_infile;
		}
		switch (ck->comp_type) {
		case DEFLATE:
			pr_info("delate compression\n");
			err = compress_file(ck->input_file, buf, err, ".deflate", "deflate");
			if (err)
				goto out_infile;
			break;
		case LZ4:
			pr_info("lz4 compression");
			err = compress_file(ck->input_file, buf, err, ".lz4", "lz4");
			if (err)
				goto out_infile;
			break;
		case LZ4HC:
			pr_info("lz4hc compression");
			err = compress_file(ck->input_file, buf, err, ".lz4hc", "lz4hc");
			if (err)
				goto out_infile;
			break;
		default:
			pr_info("invalid value for compression %d\n", ck->comp_type);
			break;
		}
	}

out_infile:
	if (in_file)
		filp_close(in_file, NULL);
out:
	return err;
}

/**
 * decompress_file
 * @inpfile: name of input file to be decompressed
 * @buf: data to be decompressed
 * @buf_len: length of data in buf to be decompressed
 * @extn: extension of output file
 * @name: name of decompression algorithm to use
 *
 * Uses crypto API to decompress the data in buf. Dcompresses buf_len bytes
   and creates output file with extension extn.
   supports deflate, lz4, lz4hc
 */
int decompress_file(char *inpfile, char *buf, int buf_len, char *extn, char *name)
{
	struct crypto_comp *tfm;
	char *output_file = NULL;
	int err;
	struct file *out_file;
	char result[512];
	unsigned int dlen = 512;

	pr_info("buf_len = %d in decompress file\n", buf_len);
	tfm = crypto_alloc_comp(name, 0, 0);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		pr_err("could not alloc crypto comp %s : %ld\n", name, PTR_ERR(tfm));
		goto out;
	}
	memset(result, 0, sizeof(result));

	err = crypto_comp_decompress(tfm, buf, buf_len, result, &dlen);
	if (err) {
		pr_err("decompression failed\n");
		crypto_free_comp(tfm);
		goto out;
	}

	pr_info("dlen = %d\n", dlen);
	crypto_free_comp(tfm);

	output_file = get_output_file(inpfile, extn);
	if (IS_ERR(output_file)) {
		err = PTR_ERR(output_file);
		goto out;
	}

	pr_info("output file = %s\n", output_file);
	err = get_file_handle(&out_file, output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (err)
		goto out_free;

	err = write_to_file(out_file, result, dlen);
	pr_info("%d chars written to output file\n", err);
	err = 0;
	filp_close(out_file, NULL);

out_free:
	if (output_file)
		kfree(output_file);
out:
	return err;
}

/**
 * do_decompression
 * @ck: pointer to struct which has data related to decompression
 *
 * Central function which opens file, reads data and calls
   decompress_file function with appropriate parameters
 */
int do_decompression(struct comp_struct *ck)
{
	int err = 0;
	unsigned char buf[BUF_SIZE] = {0};
	struct file *in_file;

	pr_info("in dochecks, inp file = %s\n", ck->input_file);
	pr_info("comp type = %d\n", ck->comp_type);
	err = get_file_handle(&in_file, ck->input_file, O_RDONLY, 0);
	if (err)
		goto out;
	pr_info("file opened\n");
	while (1) {
		err = read_from_file(in_file, buf, BUF_SIZE);
		pr_info("======byted read = %d\n", err);
		if (err == 0)
			break;
		if (err < 0) {
			pr_info("error in reading file\n");
			goto out_infile;
		}
		switch (ck->comp_type) {
		case DEFLATE:
			pr_info("delate decompression\n");
			err = decompress_file(ck->input_file, buf, err, ".dcmp", "deflate");
			if (err)
				goto out_infile;
			break;
		case LZ4:
			pr_info("lz4 decompression");
			pr_info("bytes read in lz4 = %d\n", err);
			err = decompress_file(ck->input_file, buf, err, ".dcmp", "lz4");
			if (err)
				goto out_infile;
			break;
		case LZ4HC:
			pr_info("lz4hc compression");
			err = decompress_file(ck->input_file, buf, err, ".dcmp", "lz4hc");
			if (err)
				goto out_infile;
			break;
		default:
			pr_info("invalid value for compression %d\n", ck->comp_type);
			break;
		}
	}

out_infile:
	if (in_file)
		filp_close(in_file, NULL);
out:
	return err;
}
