#include "xhw3_k.h"
#include "common_utility.h"

struct sock *nl_sk;
int job_count;

asmlinkage extern long (*sysptr)(void *arg, int argslen);

/**
 * send_callback
 * @pid: port number to which status of job should be sent
 * @msg: success or failure message to be sent to user
 *
 * sends status of job to user
 *
 */
void send_callback(int pid, char *msg, int len)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	int res;

	skb = nlmsg_new(len, 0);
	pr_info(" ***************** in callback , msg len = %d\n", len);
	if (!skb) {
	    pr_info("error: callback failed to allocate new skb\n");
	    return;
	}

	nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, len, 0);
	NETLINK_CB(skb).dst_group = 0;
	memcpy(nlmsg_data(nlh), msg, len);
	res = nlmsg_unicast(nl_sk, skb, pid);

	if (res < 0)
		pr_info("error: callback failed  while sending status back to user: %d\n", res);
}

static int consumer(void *data)
{
	int len = 0, err = 0;
	char *status = NULL;
	struct job_item *my_job;
	char *chksum = NULL;
	int dlen[] = {0, 16, 20, 64};
	while (1) {
		mutex_lock(&waitq.mq);
		if (job_count == 0) {
			mutex_unlock(&waitq.mq);
			wait_event_interruptible(waitq_c, job_count > 0);
			msleep(3000);
			mutex_lock(&waitq.mq);
		}

		pr_info("consumer has woken up\n");

		if (need_to_exit)
			goto out_unlock;

		my_job = get_first_job(&waitq);
		if (IS_ERR(my_job)) {
			pr_err("Error while getting first job\n");
			err = PTR_ERR(my_job);
			mutex_unlock(&waitq.mq);
			goto retry;
		}

		job_count--;
		if (job_count == 0) {
			/* should not put consumer in waitq_c, as it has to
			 * process recently removed job item first.
			 * Solution:
			 * once job_item is processed, consumer thread should
			 * yield to scheduler - using schedule(); - to indicate
			 * voluntarily to the scheduler that it can schedule
			 * some other process on the processor.
			 */
		} else if (job_count == MAX_JOBS - 1) {
			wake_up_all(&waitq_p);
		}

		mutex_unlock(&waitq.mq);
		pr_info("job type = %d\n", my_job->j->job_type);
		/* start processing my_job */
		if (my_job->j->job_type == ENCRYPT) {
			err = do_encryption((struct enc_struct *)my_job->j->job_struct);
		} else if (my_job->j->job_type == DECRYPT) {
			err = do_decryption((struct enc_struct *)my_job->j->job_struct);
		} else if (my_job->j->job_type == CONCAT) {
			err = concatenation((struct concat_struct *)my_job->j->job_struct);
		} else if  (my_job->j->job_type == CHECKSUM) {
			pr_info("calling do checksum now==========\n");
			chksum = do_checksum((struct comp_struct *)my_job->j->job_struct);
			err = 0;
			pr_info("======= digest len = %d\n", ((struct comp_struct *)my_job->j->job_struct)->digest_len);
			if (IS_ERR(chksum))
				err = PTR_ERR(chksum);
			pr_info("called..fun returned %d\n", err);

		} else if  (my_job->j->job_type == COMPRESS) {
			pr_info("calling do compress now==========\n");
			err = do_compression((struct comp_struct *)my_job->j->job_struct);
			pr_info("called..fun returned %d\n", err);
		} else if  (my_job->j->job_type == DECOMPRESS) {
			pr_info("calling do decompress now==========\n");
			err = do_decompression((struct comp_struct *)my_job->j->job_struct);
			pr_info("called..fun returned %d\n", err);
		}


		if (err) {
			len += snprintf(NULL, 0, "%s%d%s%d%s%d%s", "job: id[", my_job->j->job_id, "] type[", my_job->j->job_type, "] status[failed! (err no: ", err, ")]\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s%d%s%d%s%d%s", "job: id[", my_job->j->job_id, "] type[", my_job->j->job_type, "] status[failed! (err no: ", err, ")]\n ");
		} else {
			if (my_job->j->job_type == CHECKSUM) {
				status = chksum;
				len = dlen[((struct comp_struct *)(my_job->j->job_struct))->comp_type % 4];
			} else {
			len += snprintf(NULL, 0, "%s%d%s%d%s", "job: id[", my_job->j->job_id, "] type[", my_job->j->job_type, "] status[success!]\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s%d%s%d%s", "job: id[", my_job->j->job_id, "] type[", my_job->j->job_type, "] status[success!]\n ");
			}
		}

		/* send job status to user */
		send_callback(my_job->j->pid, status, len);
		kfree(status);

		release_job_item(my_job);
retry:
		schedule();
	}

out_unlock:
	mutex_unlock(&waitq.mq);
	return err;
}

void *job_validation(struct job_info *my_job)
{
	struct enc_struct *e1 = NULL;
	struct comp_struct *ck = NULL;
	struct concat_struct *c1 = NULL;
	void *ret_struct = NULL;
	int err = 0, i;

	if (my_job->job_type == ENCRYPT) {
		e1 = kzalloc(sizeof(struct enc_struct), GFP_KERNEL);
		if (!e1) {
			pr_err("kzalloc failed for enc_struct\n");
			err = -ENOMEM;
			goto out;
		}
		if (copy_from_user(e1, my_job->job_struct, sizeof(struct enc_struct))) {
			pr_info("error in copy from user in encrypt\n");
			err = -EFAULT;
			goto out_release_e1;
		}
		pr_info("validating for encryption\n");
		err = basic_validations(e1);
		if (err) {
			pr_info("Error in validation of encryption\n");
			goto out_release_e1;
		}
		ret_struct = (void *)e1;
	} else if (my_job->job_type == CONCAT) {
		c1 = kzalloc(sizeof(struct concat_struct), GFP_KERNEL);
		if (!c1) {
			pr_err("kzalloc failed for concat_struct\n");
			err = -ENOMEM;
			goto out;
		}
		if (copy_from_user(c1, my_job->job_struct, sizeof(struct concat_struct))) {
			pr_info("error in copy from user in concat\n");
			err = -EFAULT;
			goto out_release_c1;
		}

		c1->input_files = kzalloc(sizeof(char *) * c1->no_of_infiles, GFP_KERNEL);
		if (copy_from_user(c1->input_files, ((struct concat_struct *)my_job->job_struct)->input_files, sizeof(char *) * c1->no_of_infiles)) {
			pr_info("error in copy from user in concat\n");
			err = -EFAULT;
			goto out_release_c1;
		}

		for (i = 0; i < c1->no_of_infiles; i++) {
			c1->input_files[i] = kzalloc(sizeof(char *) * 257, GFP_KERNEL);
			if (copy_from_user(c1->input_files[i], ((struct concat_struct *)my_job->job_struct)->input_files[i], sizeof(char *) * 256)) {
				pr_info("error in copy from user for list of input files\n");
				err = -EFAULT;
				goto out_release_c1;
			}
		}

		c1->out = kzalloc(sizeof(char *) * 257, GFP_KERNEL);
		if (copy_from_user(c1->out, ((struct concat_struct *)my_job->job_struct)->out, sizeof(char *) * 256)) {
			pr_info("error in copy from user in concat\n");
			err = -EFAULT;
			goto out_release_c1;
		}

		pr_info("validating for concating files\n");
		err = validate_concat_files(c1);
		if (err) {
			pr_info("Error in validation of concat\n");
			goto out_release_c1;
		}
		ret_struct = (void *)c1;
	} else if (my_job->job_type == DECRYPT)  {
		pr_info("in decryption=================");
		e1 = kzalloc(sizeof(struct enc_struct), GFP_KERNEL);
		if (!e1) {
			pr_err("kzalloc failed for enc_struct\n");
			err = -ENOMEM;
			goto out;
		}
		if (copy_from_user(e1, my_job->job_struct, sizeof(struct enc_struct))) {
			pr_info("error in copy from user in decrypt\n");
			err = -EFAULT;
			goto out_release_e1;
		}
		pr_info("validating for decryption\n");
		err = basic_validations(e1);
		if (err) {
			pr_info("Error in validation of decryption\n");
			goto out_release_e1;
		}
		ret_struct = (void *)e1;
	}  else if (my_job->job_type == CHECKSUM)  {
		pr_info("=========== in checksum\n");
		     ck = kzalloc(sizeof(struct comp_struct), GFP_KERNEL);
		if (!ck) {
			pr_err("kzalloc failed for comp_struct\n");
			err = -ENOMEM;
			goto out;
		}
		if (copy_from_user(ck, my_job->job_struct, sizeof(struct comp_struct))) {
			pr_info("error in copy from user in checksum\n");
			err = -EFAULT;
			goto out_release_ck;
		}
		pr_info("validating for checksum\n");
		pr_info("=======file to checksum = %s\n", ck->input_file);
		 if (err) {
			pr_info("Error in validation of checksum\n");
			goto out_release_ck;
		}
		ret_struct = (void *)ck;
	} else if (my_job->job_type == COMPRESS  || my_job->job_type == DECOMPRESS)  {
		pr_info("=========== in cOMPRESS\n");
		ck = kzalloc(sizeof(struct comp_struct), GFP_KERNEL);
		if (!ck) {
			pr_err("kzalloc failed for comp_struct\n");
			err = -ENOMEM;
			goto out;
		}
		if (copy_from_user(ck, my_job->job_struct, sizeof(struct comp_struct))) {
			pr_info("error in copy from user in compress\n");
			err = -EFAULT;
			goto out_release_ck;
		}
		pr_info("=======file to checksum = %s\n", ck->input_file);
		if (err) {
			pr_info("Error in validation of checksum\n");
			goto out_release_ck;
		}
		ret_struct = (void *)ck;
	}


out_release_e1:
	if (e1 && err)
		release_job_struct(ENCRYPT, e1);
out_release_ck:
	if (ck && err)
		release_job_struct(CHECKSUM, ck);
out_release_c1:
	if (c1 && err)
		release_job_struct(CONCAT, c1);
out:
	if (err)
		return ERR_PTR(err);
	else
		return ret_struct;
}

asmlinkage long submitjob(void *arg, int argslen)
{
	int err;
	struct job_info *my_job_info;
	void *job_struct;
	err = 0;

	pr_info("=========== argslen ======== %d\n", argslen);

	if (arg == NULL) {
		pr_info("NULL arg received in syscall\n");
		err = -EINVAL;
		goto out;
	}

	my_job_info = (struct job_info *)kzalloc(sizeof(struct job_info), GFP_KERNEL);
	if (!my_job_info) {
		pr_err("kzalloc failed for my_job_info\n");
		err = -ENOMEM;
		goto out;
	}
	if (copy_from_user(my_job_info, arg, sizeof(struct job_info))) {
		pr_err("error in copy from user\n");
		err = -EFAULT;
		goto out_release_job_info;
	}

	/* check if job_type is remove_by_job_id, remove all,
	* ls etc, if yes then perform those operations right
	* here. No need to add those to queue
	*/
	if (my_job_info->job_type == LIST) {
		char *status = NULL;
		int len = 0, d_len = 0;
		struct job_item *tmp;
		char detail[100];
		char job_type_str[7][12] = {"", "ENCRYPT", "DECRYPT", "CONCAT", "CHECKSUM", "COMPRESS", "DECOMPRESS"};

		mutex_lock(&waitq.mq);
		list_for_each_entry(tmp, &waitq.list, list) {
			len += snprintf(NULL, 0, "%5d|%13s|%13d|%s", tmp->j->job_id, job_type_str[tmp->j->job_type], tmp->j->priority, "\n ");
		}
		mutex_unlock(&waitq.mq);

		if (len == 0) {
			len += snprintf(NULL, 0, "%s", "No jobs pending in the queue!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s", "No jobs pending in the queue!\n ");
		} else {
			len += snprintf(NULL, 0, "%s", "JOBID|      JOBTYPE|     PRIORITY|\n----------------------------------\n ");

			status = (char *)kzalloc(len, GFP_KERNEL);

			d_len += snprintf(NULL, 0, "%s", "JOBID|      JOBTYPE|     PRIORITY|\n----------------------------------\n ");
			snprintf(status, d_len, "%s", "JOBID|      JOBTYPE|     PRIORITY|\n----------------------------------\n ");

			mutex_lock(&waitq.mq);
			list_for_each_entry(tmp, &waitq.list, list) {
				d_len = snprintf(NULL, 0, "%5d|%13s|%13d|%s", tmp->j->job_id, job_type_str[tmp->j->job_type], tmp->j->priority, "\n ");
				snprintf(detail, d_len, "%5d|%13s|%13d|%s", tmp->j->job_id, job_type_str[tmp->j->job_type], tmp->j->priority, "\n ");
				strncat(status, detail, d_len);
			}
			mutex_unlock(&waitq.mq);
		}

		/* send job status to user */
		send_callback(my_job_info->pid, status, strlen(status));
		kfree(status);

		if (my_job_info)
			kfree(my_job_info);
		goto out;
	} else if (my_job_info->job_type == REMOVE) {
		char *status = NULL;
		int len = 0, err = 0, id = 0;

		my_job_info->job_struct = kzalloc(sizeof(struct op_struct), GFP_KERNEL);
		if (!my_job_info->job_struct) {
			pr_err("kzalloc failed for op_struct\n");
			err = -ENOMEM;
			goto out_remove;
		}
		if (copy_from_user(my_job_info->job_struct, ((struct job_info *)arg)->job_struct, sizeof(struct op_struct))) {
			pr_info("error in copy from user in remove\n");
			err = -EFAULT;
			goto out_release_r1;
		}
		id = ((struct op_struct *)(my_job_info->job_struct))->id;

		mutex_lock(&waitq.mq);

		if (job_count == 0) {
			len += snprintf(NULL, 0, "%s", "No pending jobs to delete!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s", "No pending jobs to delete!\n ");
			goto remove_done;
		}

		err =  remove_job_by_id(id, &waitq);
		if (err) {
			len += snprintf(NULL, 0, "%s%d%s", "Job with id ", id, " not found!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s%d%s", "Job with id ", id, " not found!\n ");
		} else {
			len += snprintf(NULL, 0, "%s%d%s", "Removed job with id ", id, " successfully!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s%d%s", "Removed job with id ", id, " successfully!\n ");
		}

remove_done:
		mutex_unlock(&waitq.mq);

		/* send job status to user */
		send_callback(my_job_info->pid, status, strlen(status));
		kfree(status);
out_release_r1:
		if (my_job_info->job_struct)
			kfree(my_job_info->job_struct);
out_remove:
		if (my_job_info)
			kfree(my_job_info);
		goto out;
	} else if (my_job_info->job_type == REMOVE_ALL) {
		char *status = NULL;
		int len = 0;
		int err = 0;

		mutex_lock(&waitq.mq);

		if (job_count == 0) {
			len += snprintf(NULL, 0, "%s", "No pending jobs to delete!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s", "No pending jobs to delete!\n ");
			goto remove_all_done;
		}

		err =  remove_all_jobs(&waitq);
		if (err) {
			len += snprintf(NULL, 0, "%s", "Error occured while removing jobs!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s", "Error occured while removing jobs!\n ");
		} else {
			len += snprintf(NULL, 0, "%s", "Removed all jobs successfully!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s", "Removed all jobs successfully!\n ");
		}

remove_all_done:
		mutex_unlock(&waitq.mq);

		/* send job status to user */
		send_callback(my_job_info->pid, status, strlen(status));
		kfree(status);

		if (my_job_info)
			kfree(my_job_info);
		goto out;
	} else if (my_job_info->job_type == CHANGE_PRIORITY) {
		char *status = NULL;
		int len = 0, old_priority = 0;
		int id = 0, new_priority = 0;

		my_job_info->job_struct = kzalloc(sizeof(struct op_struct), GFP_KERNEL);
		if (!my_job_info->job_struct) {
			pr_err("kzalloc failed for op_struct\n");
			err = -ENOMEM;
			goto out_pchange;
		}
		if (copy_from_user(my_job_info->job_struct, ((struct job_info *)arg)->job_struct, sizeof(struct op_struct))) {
			pr_info("error in copy from user in change priority\n");
			err = -EFAULT;
			goto out_release_p1;
		}
		id = ((struct op_struct *)(my_job_info->job_struct))->id;
		new_priority = ((struct op_struct *)(my_job_info->job_struct))->priority;

		mutex_lock(&waitq.mq);

		if (job_count == 0) {
			len += snprintf(NULL, 0, "%s", "No pending jobs in queue!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s", "No pending jobs in queue!\n ");
			goto pchange_done;
		}

		old_priority = get_priority_by_job_id(id, &waitq);

		if (old_priority < 0) {
			len += snprintf(NULL, 0, "%s%d%s", "Job with id ", id, " not found!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s%d%s", "Job with id ", id, " not found!\n ");
		} else if (new_priority == old_priority) {
			len += snprintf(NULL, 0, "%s", "Given priority is same as previous!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s", "Given priority is same as previous!\n ");
		} else {
			struct job_item *tmp;
			struct job_item *it;

			list_for_each_entry(tmp, &waitq.list, list) {
				if (tmp->j->job_id == id) {
					list_del(&tmp->list);
					break;
				}
			}
			tmp->j->priority = new_priority;

			list_for_each_entry(it, &waitq.list, list) {
				if (it->j->priority < tmp->j->priority) {
					list_add_tail(&tmp->list, &it->list);
					break;
				}
			}
			if (&it->list == &waitq.list) {
				list_add_tail(&tmp->list, &waitq.list);
			}

			len += snprintf(NULL, 0, "%s%d%s", "Changed priority of job id ", id, " successfully!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s%d%s", "Changed priority of job id ", id, " successfully!\n ");

		}

pchange_done:
		mutex_unlock(&waitq.mq);

		/* send job status to user */
		send_callback(my_job_info->pid, status, strlen(status));
		kfree(status);
out_release_p1:
		if (my_job_info->job_struct)
			kfree(my_job_info->job_struct);
out_pchange:
		if (my_job_info)
			kfree(my_job_info);
		goto out;

	}

	job_struct = job_validation(my_job_info);
	if (IS_ERR(job_struct)) {
		pr_err("Invalid job!\n");
		err = PTR_ERR(job_struct);
		goto out_release_job_info;
	}
	my_job_info->job_struct = job_struct;

	pr_info("adding job to the queue\n");

	mutex_lock(&waitq.mq);
	/* if max no of jobs are waiting to be processed
	 * then add current thread to waitq_p
	 */
	if (job_count >= MAX_JOBS) {
		mutex_unlock(&waitq.mq);
		wait_event_interruptible(waitq_p, job_count < MAX_JOBS);
		mutex_lock(&waitq.mq);
	}

	err = add_job_by_priority(my_job_info, &waitq);
	if (err)
		goto out_unlock;

	job_count++;
	if (job_count == 1) {
		wake_up_all(&waitq_c);
	}

out_unlock:
	mutex_unlock(&waitq.mq);
out_release_job_info:
	if (err && my_job_info)
		kfree(my_job_info);
out:
	return err;
}

static int __init init_sys_submitjob(void)
{
	int ret = 0;
	struct netlink_kernel_cfg cfg = {
		.input = NULL,
	};
	int i = 0;

	if (!sysptr) {
		/* init job count */
		job_count = 0;

		/* Initialize wait queue */
		INIT_LIST_HEAD(&waitq.list);
		mutex_init(&waitq.mq);

		/* Initialize producer and consumer wait queue */
		init_waitqueue_head(&waitq_p);
		init_waitqueue_head(&waitq_c);

		nl_sk = netlink_kernel_create(&init_net, CALLER_NETLINK, &cfg);
		if (!nl_sk) {
			pr_info("error: failed while creating netlink socket.\n");
			return -ENOMEM;
		}

		/* creating consumer thread */
		for (i = 0; i < MAX_CONSUMER_THREADS; i++) {
			pr_info("thread %d\n", i);
			consumer_threads[i] = kthread_create(consumer, NULL, "consumer");
			if (IS_ERR(consumer_threads[i])) {
				printk(KERN_CRIT "unable to start consumer_thread!\n");
				ret = PTR_ERR(consumer_threads[i]);
				consumer_threads[i] = NULL;
				goto out;
			}
			wake_up_process(consumer_threads[i]);
		}

		sysptr = submitjob;
	}
	pr_info("installed new sys_submitjob module\n");
out:
	return ret;
}

static void  __exit exit_sys_submitjob(void)
{
	int ret = 0;

	if (sysptr != NULL) {
		sysptr = NULL;

		/* free each and every job item */
		ret = remove_all_jobs(&waitq);
		if (ret)
			pr_err("remove_all_jobs failed!\n");
		else if (list_empty(&waitq.list))
			pr_err("remove_all_jobs was successful!\n");
		/* release netlink socket */
		if (nl_sk)
			netlink_kernel_release(nl_sk);

		/* waitq_c and waitq_p need to be released */
		need_to_exit++;
		wake_up_all(&waitq_c);

		/* destroy mutex */
		mutex_destroy(&waitq.mq);
	}
	pr_info("removed sys_submitjob module\n");
}
module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
