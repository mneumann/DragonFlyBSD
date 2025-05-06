/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Dell Inc.
 *
 *	Alvin Chen <weike_chen@dell.com, vico.chern@qq.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * UVC spec:https://www.usb.org/sites/default/files/USB_Video_Class_1_5.zip
 */

#include <sys/cdefs.h>
#include <sys/stdint.h>
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/condvar.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/unistd.h>
#include <sys/callout.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/sbuf.h>

#include <sys/filedesc.h>
#include <bus/u4b/usb.h>
#include <bus/u4b/usbdi.h>
#include <bus/u4b/usbdi_util.h>
#include <bus/u4b/usbhid.h>

#define USB_DEBUG_VAR uvc_debug
#include <bus/u4b/usb_debug.h>

#include <bus/u4b/usb_core.h>
#include <bus/u4b/usb_dev.h>
#include <bus/u4b/usb_mbuf.h>
#include <bus/u4b/usb_process.h>
#include <bus/u4b/usb_device.h>
#include <bus/u4b/usb_busdma.h>
#include <bus/u4b/usb_dynamic.h>
#include <bus/u4b/usb_util.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <contrib/v4l/videodev.h>
#include <contrib/v4l/videodev2.h>

#include "uvc_drv.h"
#include "uvc_buf.h"
#include "uvc_v4l2.h"

#define UVC_LOCK(lkp)   lockmgr(lkp, LK_EXCLUSIVE)
#define UVC_UNLOCK(lkp) lockmgr(lkp, LK_RELEASE)

#define FRAME_DUMP 1
#if FRAME_DUMP
#include <sys/kern_syscall.h>
#include <sys/nlookup.h>
static void uvc_writefile(char *path, void *data, int len);
#endif


static void
uvc_buf_fill_v4l2(struct v4l2_buffer *buf, uint32_t index, uint32_t size,
	uint32_t len)
{
	buf->index = index;
	buf->m.offset = index * size;
	buf->length = len;
	buf->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	buf->sequence = 0;
	buf->field = V4L2_FIELD_NONE;
	buf->memory = V4L2_MEMORY_MMAP;
	buf->flags = 0;
}

void
uvc_buf_queue_mmap(struct uvc_buf_queue *bq,
	vm_paddr_t *paddr, vm_offset_t offset)
{
	UVC_LOCK(&bq->mtx);
	if (bq->mem)
		*paddr = vtophys((uint8_t *)bq->mem + offset);
	UVC_UNLOCK(&bq->mtx);
}

static void
uvc_buf_queue_show_qbuf(struct uvc_buf *buf)
{
	DPRINTF("buf index:%lu status:%lu mem:%p offset:%lu\n",
		buf->index, buf->status, buf->mem, buf->offset);
}

static void
uvc_buf_queue_show(struct uvc_buf_queue *bq)
{
	int i;

	DPRINTF("mem:%p status:%lx flags:%lx seq:%lu buf size:%lu count:%lu\n",
		bq->mem, bq->status, bq->flags, bq->seq,
		bq->buf_size, bq->buf_count);
	for (i = 0; i < UVC_BUF_MAX_BUFFERS; i++)
		uvc_buf_queue_show_qbuf(bq->buf + i);
}

int
uvc_buf_reset_buf(struct uvc_buf_queue *bq)
{
	struct uvc_buf *buf;

	UVC_LOCK(&bq->mtx);
	buf = STAILQ_FIRST(&bq->product);
	if (buf) {
		buf->vbuf.bytesused = 0;
	}
	UVC_UNLOCK(&bq->mtx);

	return 0;
}

static int
uvc_buf_check_length(struct uvc_drv_video *v, struct uvc_buf *buf,
		     uint32_t len, uint32_t finish)
{
	struct v4l2_buffer *vbuf = &buf->vbuf;

	/*
	 * guvcview enables video stream twice on ThinOS, first time it calls
	 * VIDIOC_REQBUFS to alloc buf for data stream, then disable video
	 * but second time it does not call VIDIOC_REQBUFS to alloc mem which
	 * calls crash not call, we do not figure out why yet, so do not let go
	 * temply, we will figure out why it behaves this weird here
	 */

	if (vbuf->length == 0) {
		return 1;
	}


	if (vbuf->bytesused + len > vbuf->length) {
		return 1;
	}
	/*
	 * -------------------2208 release----------------------------------
	 * So far we found that sometime driver will upload incompleted frame
	 * when using YUYV format so we check whether the data fully occupy
	 * buffer, but NV12 format's data does not fully occupy buffer
	 * origenally, and now we not fully know all kinds of formats'
	 * speciality so we quit it now for 2208 relase.
	 * -------------------------end--------------------------------------
	 * Logitech BRIO gives wrong dwMaxFrameSize in its NV12 format
	 * fixed it at video probe, so uncomment "return" here
	 */
	if (v->cur_fmt && (v->cur_fmt->fcc != V4L2_PIX_FMT_MJPEG &&
			   v->cur_fmt->fcc != V4L2_PIX_FMT_H264)) {
		if (finish && (vbuf->bytesused + len < vbuf->length)) {
			return 1;
		}
	}

	return 0;
}

int
uvc_bulkbuf_sell_buf(struct uvc_buf_queue *bq,
		struct usb_page_cache *pc, usb_frlength_t offset,
		usb_frlength_t len,
		usb_frlength_t actlen,
		usb_frlength_t maxFramelen)
{
	struct uvc_buf *buf;
	struct uvc_drv_video *v;
	unsigned char *ptr;
	uint32_t maxlen, nbytes;
	int ret = 0;

	UVC_LOCK(&bq->mtx);
	if (!UVC_BUF_QUEUE_IS_RUNNING(bq)) {
		ret = EINVAL;
		goto done;
	}

	v = bq->video;

	buf = STAILQ_FIRST(&bq->product);
	if (!buf) {
		ret = EINVAL;
		v->bulk.skip_payload = 1;
	}

	if (!v->bulk.skip_payload && buf) {
		if (buf->status != UVC_BUF_STATE_ACTIVE) {
			if (v->bulk.last_fid ==
					(v->bulk.header[1] & UVC_PL_HEADER_BIT_FID)) {
				v->bulk.skip_payload = 1;
				buf->vbuf.bytesused = 0;
				goto done;
			}
			buf->status = UVC_BUF_STATE_ACTIVE;
		}
	}

	if (v->bulk.last_fid != (v->bulk.header[1] & UVC_PL_HEADER_BIT_FID))
		v->bulk.last_fid = (v->bulk.header[1] & UVC_PL_HEADER_BIT_FID);

	if (len != 0 && !v->bulk.skip_payload) {
		maxlen = buf->vbuf.length - buf->vbuf.bytesused;
		nbytes = min(maxlen, len);

		ptr = (char *)(buf->mem) + buf->offset;
		usbd_copy_out(pc, offset, ptr + buf->vbuf.bytesused,
			nbytes);
		buf->vbuf.bytesused += nbytes;

		if (len > maxlen) {
			len -= nbytes;
			goto finished;
		}
	}

	if (actlen < maxFramelen ||
	    v->bulk.payload_size >= v->bulk.max_payload_size) {
		if (!v->bulk.skip_payload && buf)
			if (uvc_drv_check_video_context(v, buf->mem,
						buf->vbuf.bytesused)) {
				buf->vbuf.bytesused = 0;
				goto clean;
			}

		if (!v->bulk.skip_payload &&
		    ((v->bulk.header[1] & UVC_PL_HEADER_BIT_EOF) ||
			(bq->video && bq->video->sc &&
				bq->video->sc->quirks & UVC_NO_EOF)))
finished:
			if (buf->vbuf.bytesused > 0) {
				STAILQ_REMOVE_HEAD(&bq->product, link);
				buf->vbuf.sequence = bq->seq++;
				microtime(&buf->vbuf.timestamp);
				buf->status = UVC_BUF_STATE_DONE;
				STAILQ_INSERT_TAIL(&bq->consumer, buf, link);
				cv_broadcast(&bq->io_cv);
				KNOTE(&bq->sel.ki_note, 0);
			}

clean:
		v->bulk.header_size = 0;
		v->bulk.skip_payload = 0;
		v->bulk.payload_size = 0;
	}

done:
	UVC_UNLOCK(&bq->mtx);
	return ret;
}

int
uvc_buf_sell_buf(struct uvc_buf_queue *bq,
		struct usb_page_cache *pc, usb_frlength_t offset,
		usb_frlength_t len, uint32_t finish, uint8_t fid)
{
	struct uvc_buf *buf;
	unsigned char *ptr;
	int ret = 0;

	UVC_LOCK(&bq->mtx);
	if (!UVC_BUF_QUEUE_IS_RUNNING(bq)) {
		ret = EINVAL;
		goto done;
	}

	buf = STAILQ_FIRST(&bq->product);
	if (buf) {
		if (buf->status != UVC_BUF_STATE_ACTIVE) {
			if (bq->video->last_fid == fid) {
				buf->vbuf.bytesused = 0;
				goto done;
			}
			buf->status = UVC_BUF_STATE_ACTIVE;
		}
		if (uvc_buf_check_length(bq->video, buf, len, finish)) {
			buf->vbuf.bytesused = 0;
			goto done;
		}
		if (bq->video->last_fid != fid)
			bq->video->last_fid = fid;

		if (len != 0) {
			ptr = (char *)(buf->mem) + buf->offset;
			usbd_copy_out(pc, offset, ptr + buf->vbuf.bytesused,
				len);
			buf->vbuf.bytesused += len;
		}

		if (!finish)
			goto done;

		if (uvc_drv_check_video_context(bq->video, (char *)buf->mem + buf->offset,
			buf->vbuf.bytesused)) {
			buf->vbuf.bytesused = 0;
			goto done;
		}

		if (buf->vbuf.bytesused > 0) {

#if FRAME_DUMP
			char path[PATH_MAX];
			ksprintf(path, "/tmp/%p_%4lu.data", bq->video, bq->seq);
			uvc_writefile(path,
				      (void *)((char *)buf->mem + buf->offset),
				      buf->vbuf.bytesused);
#endif
			STAILQ_REMOVE_HEAD(&bq->product, link);
			buf->vbuf.sequence = bq->seq++;
			microtime(&buf->vbuf.timestamp);
			buf->status = UVC_BUF_STATE_DONE;
			STAILQ_INSERT_TAIL(&bq->consumer, buf, link);
			cv_broadcast(&bq->io_cv);
			KNOTE(&bq->sel.ki_note, 0);
		}
	}

done:
	UVC_UNLOCK(&bq->mtx);
	return ret;
}

static void
uvc_buf_queue_query_buf_locked(struct uvc_buf *buf, struct v4l2_buffer *vbuf)
{
	memcpy(vbuf, &buf->vbuf, sizeof(*vbuf));

	switch (buf->status) {
	case UVC_BUF_STATE_QUEUED:
	case UVC_BUF_STATE_ACTIVE:
		vbuf->flags |= V4L2_BUF_FLAG_QUEUED;
		break;
	case UVC_BUF_STATE_DONE:
	case UVC_BUF_STATE_ERROR:
		vbuf->flags |= V4L2_BUF_FLAG_DONE;
		break;
	case UVC_BUF_STATE_IDLE:
	default:
		break;
	}
}

int
uvc_buf_queue_dequeue_buf(struct uvc_buf_queue *bq,
	struct v4l2_buffer *vbuf, int nonblock)
{
	struct uvc_buf *buf;
	int ret = 0;

	UVC_LOCK(&bq->mtx);
	do {
		if (!UVC_BUF_QUEUE_IS_RUNNING(bq)) {
			ret = EINVAL;
			break;
		}

		buf = STAILQ_FIRST(&bq->consumer);
		if (buf) {
			switch (buf->status) {
			case UVC_BUF_STATE_ERROR:
				ret = EIO;
			case UVC_BUF_STATE_DONE:
				buf->status = UVC_BUF_STATE_IDLE;
				break;
			default:
				DPRINTF("fatal %s\n", __func__);
				break;
			}
			STAILQ_REMOVE_HEAD(&bq->consumer, link);
			uvc_buf_queue_query_buf_locked(buf, vbuf);
			break;
		} else {
			if (STAILQ_EMPTY(&bq->product)) {
				DPRINTF("%s buf empty\n", __func__);
				ret = EPIPE;
				break;
			}

			if (!nonblock) {
				ret = cv_wait_sig(&bq->io_cv, &bq->mtx);
				if (ret) {
					DPRINTF("cv wait sig:%d\n", ret);
					break;
				}
			} else {
				ret = EAGAIN;
			}
		}
	} while (!nonblock);

	UVC_UNLOCK(&bq->mtx);
	return ret;
}

int
uvc_buf_queue_queue_buf(struct uvc_buf_queue *bq, struct v4l2_buffer *vbuf)
{
	struct uvc_buf *buf;
	int ret = 0;

	UVC_LOCK(&bq->mtx);
	if (vbuf->index >= bq->buf_count) {
		ret = EINVAL;
		goto done;
	}

	if (!UVC_BUF_QUEUE_IS_RUNNING(bq)) {
		ret = EINVAL;
		goto done;
	}

	buf = bq->buf + vbuf->index;
	if (buf->status != UVC_BUF_STATE_IDLE) {
		DPRINTF("%s wrong buf type %lu\n", __func__, buf->status);
		ret = EINVAL;
		goto done;
	}

	buf->status = UVC_BUF_STATE_QUEUED;
	buf->vbuf.bytesused = 0;
	STAILQ_INSERT_TAIL(&bq->product, buf, link);
done:
	UVC_UNLOCK(&bq->mtx);
	return ret;
}

int
uvc_buf_queue_query_buf(struct uvc_buf_queue *bq, struct v4l2_buffer *vbuf)
{
	int ret = 0;

	DPRINTF("%s\n", __func__);

	UVC_LOCK(&bq->mtx);

	if (vbuf->index >= bq->buf_count) {
		ret = EINVAL;
		goto done;
	}

	uvc_buf_queue_query_buf_locked(bq->buf + vbuf->index, vbuf);
done:
	UVC_UNLOCK(&bq->mtx);
	return ret;
}

void
uvc_buf_queue_set_drop_flag(struct uvc_buf_queue *bq)
{
	bq->flags |= UVC_BUFFER_QUEUE_DROP_INCOMPLETE;
}

static void
uvc_buf_queue_free_bufs_locked(struct uvc_buf_queue *bq)
{
	if (bq->mem) {
		kfree(bq->mem, M_UVC);
		bq->mem = NULL;
		bq->buf_count = 0;
	}
}

void
uvc_buf_queue_free_bufs(struct uvc_buf_queue *bq)
{
	UVC_LOCK(&bq->mtx);

	/* check mmap finish */
	uvc_buf_queue_free_bufs_locked(bq);
	UVC_UNLOCK(&bq->mtx);
}

int
uvc_buf_queue_req_bufs(struct uvc_buf_queue *bq, uint32_t *count, uint32_t len)
{
	void *mem;
	struct uvc_buf *buf;
	int i, num, ret = 0;
	unsigned long rl;

	DPRINTF("%s\n", __func__);
	rl = round_page(len);
	DPRINTF("page align size:%lu-real size:%u\n", rl, len);

	num = *count;
	if (num > UVC_BUF_MAX_BUFFERS)
		num = UVC_BUF_MAX_BUFFERS;

	UVC_LOCK(&bq->mtx);
	uvc_buf_queue_free_bufs_locked(bq);
	if (!num)
		goto done;

	for (; num > 0; num--) {
		mem = kmalloc(num * rl, M_UVC, M_WAITOK | M_ZERO);
		if (mem)
			break;
	}

	if (!mem) {
		ret = ENOMEM;
		goto done;
	}

	for (i = 0; i < num; i++) {
		buf = bq->buf + i;
		buf->index = i;
		buf->mem = mem;
		buf->offset = i * rl;
		buf->status = UVC_BUF_STATE_IDLE;
		uvc_buf_fill_v4l2(&buf->vbuf, i, rl, len);
	}

	bq->mem = mem;
	bq->buf_count = num;
	bq->buf_size = rl;
	*count = num;

	uvc_buf_queue_show(bq);

done:
	UVC_UNLOCK(&bq->mtx);
	DPRINTF("reqbuf nums:%d\n", *count);
	return ret;
}


static void
uvc_buf_queue_init_qbuf(struct uvc_buf *buf, int ind)
{
	memset(buf, 0x0, sizeof(*buf));
	buf->index = ind;
	buf->status = UVC_BUF_STATE_IDLE;
}

// TODO: kqueue
#if 0
int
uvc_buf_queue_poll(struct uvc_buf_queue *queue, int events, struct thread *td)
{
	int ret = 0;
	struct uvc_buf *buf;

	UVC_LOCK(&queue->mtx);

	if (queue->flags == 0) {
		UVC_UNLOCK(&queue->mtx);
		return POLLHUP;
	}

	buf = STAILQ_FIRST(&queue->consumer);
	if (buf) {
		if ((buf->status == UVC_BUF_STATE_DONE) ||
			(buf->status == UVC_BUF_STATE_ERROR)) {
			ret |= (events & (POLLIN | POLLRDNORM));
		}
	} else {
		selrecord(td, &(queue->sel));
		buf = STAILQ_FIRST(&queue->product);
		if (!buf) {
			for (int i = 0; i < queue->buf_count; i++) {
				buf = queue->buf + i;
				STAILQ_INSERT_TAIL(&queue->product, buf, link);
			}
		}
	}
	UVC_UNLOCK(&queue->mtx);

	return ret;
}
#endif

int
uvc_buf_queue_disable(struct uvc_buf_queue *queue)
{
	int i;

	DPRINTF("%s\n", __func__);

	UVC_LOCK(&queue->mtx);
	if ((queue->flags & UVC_BUFFER_QUEUE_WORKING) == 0) {
		UVC_UNLOCK(&queue->mtx);
		return EINVAL;
	}

	STAILQ_INIT(&queue->consumer);
	STAILQ_INIT(&queue->product);
	for (i = 0; i < UVC_BUF_MAX_BUFFERS; i++)
		uvc_buf_queue_init_qbuf(queue->buf + i, i);

	cv_broadcast(&queue->io_cv);
	queue->flags = 0;
	UVC_UNLOCK(&queue->mtx);
	return 0;
}

int
uvc_buf_queue_enable(struct uvc_buf_queue *queue)
{
	DPRINTF("%s\n", __func__);

	UVC_LOCK(&queue->mtx);

	if (queue->flags & UVC_BUFFER_QUEUE_WORKING) {
		UVC_UNLOCK(&queue->mtx);
		return EBUSY;
	}

	queue->seq = 0;

	queue->flags |= UVC_BUFFER_QUEUE_WORKING;
	UVC_UNLOCK(&queue->mtx);
	return 0;
}

void
uvc_buf_queue_init(struct uvc_drv_video *v, struct uvc_buf_queue *bq)
{
	int i;

	DPRINTF("init buf\n");

	bq->video = v;
	lockinit(&bq->mtx, "uvc buffer lock", 0, 0);
	cv_init(&bq->io_cv, "uvcbufiocv");
	STAILQ_INIT(&bq->consumer);
	STAILQ_INIT(&bq->product);

	for (i = 0; i < UVC_BUF_MAX_BUFFERS; i++)
		uvc_buf_queue_init_qbuf(bq->buf + i, i);

	return;
}

#if FRAME_DUMP
// TODO: fix
static void
uvc_writefile(char *path, void *data, int len)
{
	struct uio auio;
	struct iovec aiov;
	int error, fd = -1;
	struct nlookupdata nd;

	error = nlookup_init(&nd, path, UIO_USERSPACE, NLC_FOLLOW|NLC_LOCKVP);
	if (error)
		return;

	error = kern_open(&nd, O_CREAT | O_RDWR, 0666, &fd);
	if (error) {
		goto out;
	}

	aiov.iov_base = data;
	aiov.iov_len = len;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_SYSSPACE;
	error = kern_pwritev(fd, &auio, 0, NULL);
	if (error) {
		goto out;
	}
out:
	if (fd >= 0)
		kern_close(fd);

	nlookup_done(&nd);
}
#endif
