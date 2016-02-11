#ifndef _COMMON_UTILITY_H_
#define _COMMON_UTILITY_H_

#include <linux/list.h>

#define MAX_JOBS 5
#define MAX_CONSUMER_THREADS 3

extern int job_count;
static int need_to_exit;

struct q_head {
	struct list_head list;
	struct mutex mq; /*mutex to protect queue*/
};

struct q_head waitq;

struct job_item {
	struct list_head list;
	struct job_info *j;
};

struct task_struct *consumer_threads[MAX_CONSUMER_THREADS];

/* wait queue for producer */
wait_queue_head_t waitq_p;

/* wait queue for consumer */
wait_queue_head_t waitq_c;

/* useful for tracking code reachability */
#define UDBG pr_info("DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

void send_callback(int pid, char *msg, int len);

/* List APIs */

/**
 * release_job_struct
 * @job_type: type of job to be released
 * @job_struct: ponter to job structure in question
 *
 * This function do memory free operation for job structure based on the type of
 * the job
 *
 * Returns zero on success and EINVAL if no such structure exists
 */
int release_job_struct(int job_type, void *job_struct)
{
	int ret = 0;

	if (!job_struct) {
		ret = -EINVAL;
		pr_err("invalid job struct\n");
		goto out;
	}

	if (job_type == CONCAT) {
		struct concat_struct *c1 = (struct concat_struct *)job_struct;
		int i = 0;

		for (i = 0; i < c1->no_of_infiles; i++) {
			if (c1->input_files[i])
				kfree(c1->input_files[i]);
		}

		if (c1->input_files)
			kfree(c1->input_files);

		if (c1->out)
			kfree(c1->out);
	}

	if (job_struct) {
		kfree(job_struct);
		job_struct = NULL;
	}

out:
	return ret;
}

/**
 * release_job_info
 * @info: ponter to job info structure in question
 *
 * This function do memory free operation for job info structure
 *
 * Returns zero on success and EINVAL if no such structure exists
 */
int release_job_info(struct job_info *info)
{
	int ret = 0;

	if (!info) {
		ret = -EINVAL;
		pr_err("invalid job info\n");
		goto out;
	}

	release_job_struct(info->job_type, info->job_struct);
	kfree(info);
	info = NULL;
out:
	return ret;
}

/**
 * release_job_item
 * @item: ponter to job structure in question
 *
 * This function do memory free operation for job item structure
 *
 * Returns zero on success and EINVAL if no such structure exists
 */
int release_job_item(struct job_item *item)
{
	int ret = 0;

	if (!item) {
		ret = -EINVAL;
		pr_info("invalid job item\n");
		goto out;
	}

	release_job_info(item->j);
	kfree(item);
	item = NULL;
out:
	return ret;
}

/**
 * add_job_by_priority
 * @j: pointer to job info structure
 * @waitq: pointer to head of waitq
 *
 * This function add jobs to queue pointed by whose head is pointed by waitq
 * Job will be added based on the priority. Higher priority job is added at the begining
 * of the queue
 *
 * Returns zero on success else appropriate error (EINVAL or ENOMEM)
 */
int add_job_by_priority(struct job_info *j, struct q_head *waitq)
{
	int ret = 0;
	struct job_item *tmp;
	struct job_item *it;

	/* check if q_head waitq is valid */
	if (!waitq) {
		ret = -EINVAL;
		pr_info("waitq is not initialized\n");
		goto out;
	}

	tmp = (struct job_item *)kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp) {
		ret = -ENOMEM;
		pr_info("kzalloc failed for new job item\n");
		goto out;
	}

	tmp->j = j;
	list_for_each_entry(it, &waitq->list, list) {
		if (it->j->priority < tmp->j->priority) {
			list_add_tail(&tmp->list, &it->list);
			break;
		}
	}
	if (&it->list == &waitq->list)
		list_add_tail(&tmp->list, &waitq->list);
out:
	return ret;
}

/**
 * get_first_job
 * @waitq: pointer to head of waitq
 *
 * This function gets first job in the queue by removing it from the queue
 * As higher priority jobs are in the begining of the queue this will always
 * take job with higher priority
 *
 * Returns pointer to job item struct on success else appropriate pointer to error
 */
struct job_item *get_first_job(struct q_head *waitq)
{
	int ret = 0;
	struct job_item *item = NULL;

	/* check if q_head waitq is valid */
	if (!waitq) {
		ret = -EINVAL;
		pr_info("waitq is not initialized\n");
		goto out;
	}

	if (job_count == 0) {
		ret = -EINVAL;
		goto out;
	}

	if (!list_empty(&waitq->list)) {
		item = list_first_entry(&waitq->list, struct job_item, list);
		list_del(&item->list);
	}

out:
	if (ret)
		return ERR_PTR(ret);
	else
		return item;
}

/**
 * get_priority_by_job_id
 * @job_id: ID of job in question
 * @waitq: pointer to head of waitq
 *
 * This function returns priority of the given job based on the job ID
 *
 * Returns priority success else EINVAL on error
 */
int get_priority_by_job_id(int job_id, struct q_head *waitq)
{
	int ret = -EINVAL;
	struct job_item *tmp;

	/* check if q_head waitq is valid */
	if (!waitq) {
		pr_info("waitq is not initialized\n");
		goto out;
	}

	list_for_each_entry(tmp, &waitq->list, list) {
		if (tmp->j->job_id == job_id) {
			ret = 0;
			break;
		}
	}
out:
	if (ret)
		return ret;
	else
		return tmp->j->priority;
}

/**
 * remove_job_by_id
 * @job_id: ID of job in question
 * @waitq: pointer to head of waitq
 *
 * This function removes job from the queue whose head is pointed by waitq
 * based on the given ID
 *
 * Returns zero success else EINVAL on error
 */
int remove_job_by_id(int job_id, struct q_head *waitq)
{
	int ret = -EINVAL;
	struct job_item *tmp;
	char *status = NULL;
	int len = 0;

	/* check if q_head waitq is valid */
	if (!waitq) {
		pr_info("waitq is not initialized\n");
		goto out;
	}

	list_for_each_entry(tmp, &waitq->list, list) {
		if (tmp->j->job_id == job_id) {
			list_del(&tmp->list);
			job_count--;

			len += snprintf(NULL, 0, "%s%d%s", "Job with id ", tmp->j->job_id, " is pre-empted!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
			snprintf(status, len, "%s%d%s", "Job with id ", tmp->j->job_id, " is pre-empted!\n ");
			/* send job status to user */
			send_callback(tmp->j->pid, status, strlen(status));
			kfree(status);

			if (tmp)
				release_job_item(tmp);

			ret = 0;
			break;
		}
	}
out:
	return ret;
}

/**
 * remove_all_jobs
 * @waitq: pointer to head of waitq
 *
 * This function remove all queued jobs from the queue
 *
 * Returns zero success else EINVAL on error
 */
int remove_all_jobs(struct q_head *waitq)
{
	int ret = 0, len = 0;
	struct list_head *pos, *n;
	struct job_item *tmp;
	char *status = NULL;

	/* check if q_head waitq is valid */
	if (!waitq) {
		ret = -EINVAL;
		pr_info("waitq is not initialized\n");
		goto out;
	}

	if (!list_empty(&waitq->list)) {
		list_for_each_safe(pos, n, &waitq->list) {
			tmp = list_entry(pos, struct job_item, list);
			list_del(pos);
			job_count--;

			len += snprintf(NULL, 0, "%s%d%s", "Job with id ", tmp->j->job_id, " is pre-empted!\n ");
			status = (char *)kzalloc(len, GFP_KERNEL);
                        snprintf(status, len, "%s%d%s", "Job with id ", tmp->j->job_id, " is pre-empted!\n ");
			/* send job status to user */
			send_callback(tmp->j->pid, status, strlen(status));
			kfree(status);

			release_job_item(tmp);
		}
	}
out:
	return ret;
}
#endif
