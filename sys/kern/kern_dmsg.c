/*-
 * Copyright (c) 2012 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * TODO: txcmd CREATE state is deferred by tx msgq, need to calculate
 *	 a streaming response.  See subr_diskiocom()'s diskiodone().
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/caps.h>
#include <sys/thread.h>
#include <sys/globaldata.h>
#include <sys/limits.h>

#include <sys/dmsg.h>

RB_GENERATE(kdmsg_state_tree, kdmsg_state, rbnode, kdmsg_state_cmp);

SYSCTL_NODE(, OID_AUTO, kdmsg, CTLFLAG_RW, 0, "kdmsg");
static int kdmsg_debug = 1;
SYSCTL_INT(_kdmsg, OID_AUTO, debug, CTLFLAG_RW, &kdmsg_debug, 0,
	   "Set debug level for kernel dmsg layer");

#define kd_printf(level, ctl, ...)      	\
        if (kdmsg_debug >= (level)) kprintf("kdmsg: " ctl, __VA_ARGS__)

#define kdio_printf(iocom, level, ctl, ...)      \
        if (kdmsg_debug >= (level)) kprintf("kdmsg: " ctl, __VA_ARGS__)

static int kdmsg_msg_receive_handling(kdmsg_msg_t *msg);
static int kdmsg_state_msgrx(kdmsg_msg_t *msg);
static int kdmsg_state_msgtx(kdmsg_msg_t *msg);
static void kdmsg_msg_write_locked(kdmsg_iocom_t *iocom, kdmsg_msg_t *msg);
static void kdmsg_state_cleanuprx(kdmsg_msg_t *msg);
static void kdmsg_state_cleanuptx(kdmsg_msg_t *msg);
static void kdmsg_subq_delete(kdmsg_state_t *state);
static void kdmsg_simulate_failure(kdmsg_state_t *state, int meto, int error);
static void kdmsg_state_abort(kdmsg_state_t *state);
static void kdmsg_state_dying(kdmsg_state_t *state);
static void kdmsg_state_free(kdmsg_state_t *state);
static void kdmsg_drain_msg(kdmsg_msg_t *msg);

#ifdef KDMSG_DEBUG
#define KDMSG_DEBUG_ARGS	, const char *file, int line
#define kdmsg_state_hold(state)	_kdmsg_state_hold(state, __FILE__, __LINE__)
#define kdmsg_state_drop(state)	_kdmsg_state_drop(state, __FILE__, __LINE__)
#else
#define KDMSG_DEBUG 0
#define KDMSG_DEBUG_ARGS
#define kdmsg_state_hold(state)	_kdmsg_state_hold(state)
#define kdmsg_state_drop(state)	_kdmsg_state_drop(state)
#endif
static void _kdmsg_state_hold(kdmsg_state_t *state KDMSG_DEBUG_ARGS);
static void _kdmsg_state_drop(kdmsg_state_t *state KDMSG_DEBUG_ARGS);

static void kdmsg_iocom_thread_rd(void *arg);
static void kdmsg_iocom_thread_wr(void *arg);
static int kdmsg_autorxmsg(kdmsg_msg_t *msg);

/*static struct lwkt_token kdmsg_token = LWKT_TOKEN_INITIALIZER(kdmsg_token);*/

/*
 * Initialize the roll-up communications structure for a network
 * messaging session.  This function does not install the socket.
 */
void
kdmsg_iocom_init(kdmsg_iocom_t *iocom, void *handle, uint32_t flags,
		 struct malloc_type *mmsg,
		 int (*rcvmsg)(kdmsg_msg_t *msg))
{
	bzero(iocom, sizeof(*iocom));
	iocom->handle = handle;
	iocom->mmsg = mmsg;
	iocom->rcvmsg = rcvmsg;
	iocom->flags = flags;
	lockinit(&iocom->msglk, "h2msg", 0, 0);
	TAILQ_INIT(&iocom->msgq);
	RB_INIT(&iocom->staterd_tree);
	RB_INIT(&iocom->statewr_tree);

	iocom->state0.iocom = iocom;
	iocom->state0.parent = &iocom->state0;
	TAILQ_INIT(&iocom->state0.subq);
}

/*
 * [Re]connect using the passed file pointer.  The caller must ref the
 * fp for us.  We own that ref now.
 */
void
kdmsg_iocom_reconnect(kdmsg_iocom_t *iocom, struct file *fp,
		      const char *subsysname)
{
	/*
	 * Destroy the current connection
	 */
	lockmgr(&iocom->msglk, LK_EXCLUSIVE);
	atomic_set_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILLRX);
	while (iocom->msgrd_td || iocom->msgwr_td) {
		wakeup(&iocom->msg_ctl);
		lksleep(iocom, &iocom->msglk, 0, "clstrkl", hz);
	}

	/*
	 * Drop communications descriptor
	 */
	if (iocom->msg_fp) {
		fdrop(iocom->msg_fp);
		iocom->msg_fp = NULL;
	}

	/*
	 * Setup new communications descriptor
	 */
	iocom->msg_ctl = 0;
	iocom->msg_fp = fp;
	iocom->msg_seq = 0;
	iocom->flags &= ~KDMSG_IOCOMF_EXITNOACC;

	lwkt_create(kdmsg_iocom_thread_rd, iocom, &iocom->msgrd_td,
		    NULL, 0, -1, "%s-msgrd", subsysname);
	lwkt_create(kdmsg_iocom_thread_wr, iocom, &iocom->msgwr_td,
		    NULL, 0, -1, "%s-msgwr", subsysname);
	lockmgr(&iocom->msglk, LK_RELEASE);
}

/*
 * Caller sets up iocom->auto_lnk_conn and iocom->auto_lnk_span, then calls
 * this function to handle the state machine for LNK_CONN and LNK_SPAN.
 */
static int kdmsg_lnk_conn_reply(kdmsg_state_t *state, kdmsg_msg_t *msg);
static int kdmsg_lnk_span_reply(kdmsg_state_t *state, kdmsg_msg_t *msg);

void
kdmsg_iocom_autoinitiate(kdmsg_iocom_t *iocom,
			 void (*auto_callback)(kdmsg_msg_t *msg))
{
	kdmsg_msg_t *msg;

	iocom->auto_callback = auto_callback;

	msg = kdmsg_msg_alloc(&iocom->state0,
			      DMSG_LNK_CONN | DMSGF_CREATE,
			      kdmsg_lnk_conn_reply, NULL);
	iocom->auto_lnk_conn.head = msg->any.head;
	msg->any.lnk_conn = iocom->auto_lnk_conn;
	iocom->conn_state = msg->state;
	kdmsg_state_hold(msg->state);	/* iocom->conn_state */
	kdmsg_msg_write(msg);
}

static
int
kdmsg_lnk_conn_reply(kdmsg_state_t *state, kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = state->iocom;
	kdmsg_msg_t *rmsg;

	/*
	 * Upon receipt of the LNK_CONN acknowledgement initiate an
	 * automatic SPAN if we were asked to.  Used by e.g. xdisk, but
	 * not used by HAMMER2 which must manage more than one transmitted
	 * SPAN.
	 */
	if ((msg->any.head.cmd & DMSGF_CREATE) &&
	    (iocom->flags & KDMSG_IOCOMF_AUTOTXSPAN)) {
		rmsg = kdmsg_msg_alloc(&iocom->state0,
				       DMSG_LNK_SPAN | DMSGF_CREATE,
				       kdmsg_lnk_span_reply, NULL);
		iocom->auto_lnk_span.head = rmsg->any.head;
		rmsg->any.lnk_span = iocom->auto_lnk_span;
		kdmsg_msg_write(rmsg);
	}

	/*
	 * Process shim after the CONN is acknowledged and before the CONN
	 * transaction is deleted.  For deletions this gives device drivers
	 * the ability to interlock new operations on the circuit before
	 * it becomes illegal and panics.
	 */
	if (iocom->auto_callback)
		iocom->auto_callback(msg);

	if ((state->txcmd & DMSGF_DELETE) == 0 &&
	    (msg->any.head.cmd & DMSGF_DELETE)) {
		/*
		 * iocom->conn_state has a state ref, drop it when clearing.
		 */
		if (iocom->conn_state)
			kdmsg_state_drop(iocom->conn_state);
		iocom->conn_state = NULL;
		kdmsg_msg_reply(msg, 0);
	}

	return (0);
}

static
int
kdmsg_lnk_span_reply(kdmsg_state_t *state, kdmsg_msg_t *msg)
{
	/*
	 * Be sure to process shim before terminating the SPAN
	 * transaction.  Gives device drivers the ability to
	 * interlock new operations on the circuit before it
	 * becomes illegal and panics.
	 */
	if (state->iocom->auto_callback)
		state->iocom->auto_callback(msg);

	if ((state->txcmd & DMSGF_DELETE) == 0 &&
	    (msg->any.head.cmd & DMSGF_DELETE)) {
		kdmsg_msg_reply(msg, 0);
	}
	return (0);
}

/*
 * Disconnect and clean up
 */
void
kdmsg_iocom_uninit(kdmsg_iocom_t *iocom)
{
	kdmsg_state_t *state;
	kdmsg_msg_t *msg;
	int retries;

	/*
	 * Ask the cluster controller to go away by setting
	 * KILLRX.  Send a PING to get a response to unstick reading
	 * from the pipe.
	 *
	 * After 10 seconds shitcan the pipe and do an unclean shutdown.
	 */
	lockmgr(&iocom->msglk, LK_EXCLUSIVE);

	atomic_set_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILLRX);
	msg = kdmsg_msg_alloc(&iocom->state0, DMSG_LNK_PING, NULL, NULL);
	kdmsg_msg_write_locked(iocom, msg);

	retries = 10;
	while (iocom->msgrd_td || iocom->msgwr_td) {
		wakeup(&iocom->msg_ctl);
		lksleep(iocom, &iocom->msglk, 0, "clstrkl", hz);
		if (--retries == 0 && iocom->msg_fp) {
			kdio_printf(iocom, 0, "%s\n",
				    "iocom_uninit: "
				    "shitcanning unresponsive pipe");
			fp_shutdown(iocom->msg_fp, SHUT_RDWR);
			/* retries allowed to go negative, keep looping */
		}
	}

	/*
	 * Cleanup caches
	 */
	if ((state = iocom->freerd_state) != NULL) {
		iocom->freerd_state = NULL;
		kdmsg_state_drop(state);
	}

	if ((state = iocom->freewr_state) != NULL) {
		iocom->freewr_state = NULL;
		kdmsg_state_drop(state);
	}

	/*
	 * Drop communications descriptor
	 */
	if (iocom->msg_fp) {
		fdrop(iocom->msg_fp);
		iocom->msg_fp = NULL;
	}
	lockmgr(&iocom->msglk, LK_RELEASE);
}

/*
 * Cluster controller thread.  Perform messaging functions.  We have one
 * thread for the reader and one for the writer.  The writer handles
 * shutdown requests (which should break the reader thread).
 */
static
void
kdmsg_iocom_thread_rd(void *arg)
{
	kdmsg_iocom_t *iocom = arg;
	dmsg_hdr_t hdr;
	kdmsg_msg_t *msg = NULL;
	size_t hbytes;
	size_t abytes;
	int error = 0;

	while ((iocom->msg_ctl & KDMSG_CLUSTERCTL_KILLRX) == 0) {
		/*
		 * Retrieve the message from the pipe or socket.
		 */
		error = fp_read(iocom->msg_fp, &hdr, sizeof(hdr),
				NULL, 1, UIO_SYSSPACE);
		if (error)
			break;
		if (hdr.magic != DMSG_HDR_MAGIC) {
			kdio_printf(iocom, 1, "bad magic: %04x\n", hdr.magic);
			error = EINVAL;
			break;
		}
		hbytes = (hdr.cmd & DMSGF_SIZE) * DMSG_ALIGN;
		if (hbytes < sizeof(hdr) || hbytes > DMSG_HDR_MAX) {
			kdio_printf(iocom, 1, "bad header size %zd\n", hbytes);
			error = EINVAL;
			break;
		}

		/* XXX messy: mask cmd to avoid allocating state */
		msg = kdmsg_msg_alloc(&iocom->state0,
				      hdr.cmd & DMSGF_BASECMDMASK,
				      NULL, NULL);
		msg->any.head = hdr;
		msg->hdr_size = hbytes;
		if (hbytes > sizeof(hdr)) {
			error = fp_read(iocom->msg_fp, &msg->any.head + 1,
					hbytes - sizeof(hdr),
					NULL, 1, UIO_SYSSPACE);
			if (error) {
				kdio_printf(iocom, 1, "%s\n",
					    "short msg received");
				error = EINVAL;
				break;
			}
		}
		msg->aux_size = hdr.aux_bytes;
		if (msg->aux_size > DMSG_AUX_MAX) {
			kdio_printf(iocom, 1,
				    "illegal msg payload size %zd\n",
				    msg->aux_size);
			error = EINVAL;
			break;
		}
		if (msg->aux_size) {
			abytes = DMSG_DOALIGN(msg->aux_size);
			msg->aux_data = kmalloc(abytes, iocom->mmsg, M_WAITOK);
			msg->flags |= KDMSG_FLAG_AUXALLOC;
			error = fp_read(iocom->msg_fp, msg->aux_data,
					abytes, NULL, 1, UIO_SYSSPACE);
			if (error) {
				kdio_printf(iocom, 1, "%s\n",
					    "short msg payload received");
				break;
			}
		}

		error = kdmsg_msg_receive_handling(msg);
		msg = NULL;
	}

#if 0
	kdio_printf(iocom, 1, "read thread terminating error=%d\n", error);
#endif

	lockmgr(&iocom->msglk, LK_EXCLUSIVE);
	if (msg)
		kdmsg_msg_free(msg);

	/*
	 * Shutdown the socket and set KILLRX for consistency in case the
	 * shutdown was not commanded.  Signal the transmit side to shutdown
	 * by setting KILLTX and waking it up.
	 */
	fp_shutdown(iocom->msg_fp, SHUT_RDWR);
	atomic_set_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILLRX |
					KDMSG_CLUSTERCTL_KILLTX);
	iocom->msgrd_td = NULL;
	lockmgr(&iocom->msglk, LK_RELEASE);
	wakeup(&iocom->msg_ctl);

	/*
	 * iocom can be ripped out at any time once the lock is
	 * released with msgrd_td set to NULL.  The wakeup()s are safe but
	 * that is all.
	 */
	wakeup(iocom);
	lwkt_exit();
}

static
void
kdmsg_iocom_thread_wr(void *arg)
{
	kdmsg_iocom_t *iocom = arg;
	kdmsg_msg_t *msg;
	ssize_t res;
	size_t abytes;
	int error = 0;
	int save_ticks;
	int didwarn;

	/*
	 * Transmit loop
	 */
	msg = NULL;
	lockmgr(&iocom->msglk, LK_EXCLUSIVE);

	while ((iocom->msg_ctl & KDMSG_CLUSTERCTL_KILLTX) == 0 && error == 0) {
		/*
		 * Sleep if no messages pending.  Interlock with flag while
		 * holding msglk.
		 */
		if (TAILQ_EMPTY(&iocom->msgq)) {
			atomic_set_int(&iocom->msg_ctl,
				       KDMSG_CLUSTERCTL_SLEEPING);
			lksleep(&iocom->msg_ctl, &iocom->msglk, 0, "msgwr", hz);
			atomic_clear_int(&iocom->msg_ctl,
					 KDMSG_CLUSTERCTL_SLEEPING);
		}

		while ((msg = TAILQ_FIRST(&iocom->msgq)) != NULL) {
			/*
			 * Remove msg from the transmit queue and do
			 * persist and half-closed state handling.
			 */
			TAILQ_REMOVE(&iocom->msgq, msg, qentry);

			error = kdmsg_state_msgtx(msg);
			if (error == EALREADY) {
				error = 0;
				kdmsg_msg_free(msg);
				continue;
			}
			if (error) {
				kdmsg_msg_free(msg);
				break;
			}

			/*
			 * Dump the message to the pipe or socket.
			 *
			 * We have to clean up the message as if the transmit
			 * succeeded even if it failed.
			 */
			lockmgr(&iocom->msglk, LK_RELEASE);
			error = fp_write(iocom->msg_fp, &msg->any,
					 msg->hdr_size, &res, UIO_SYSSPACE);
			if (error || res != msg->hdr_size) {
				if (error == 0)
					error = EINVAL;
				lockmgr(&iocom->msglk, LK_EXCLUSIVE);
				kdmsg_state_cleanuptx(msg);
				break;
			}
			if (msg->aux_size) {
				abytes = DMSG_DOALIGN(msg->aux_size);
				error = fp_write(iocom->msg_fp,
						 msg->aux_data, abytes,
						 &res, UIO_SYSSPACE);
				if (error || res != abytes) {
					if (error == 0)
						error = EINVAL;
					lockmgr(&iocom->msglk, LK_EXCLUSIVE);
					kdmsg_state_cleanuptx(msg);
					break;
				}
			}
			lockmgr(&iocom->msglk, LK_EXCLUSIVE);
			kdmsg_state_cleanuptx(msg);
		}
	}

#if 0
	kdio_printf(iocom, 1, "write thread terminating error=%d\n", error);
#endif

	/*
	 * Shutdown the socket and set KILLTX for consistency in case the
	 * shutdown was not commanded.  Signal the receive side to shutdown
	 * by setting KILLRX and waking it up.
	 */
	fp_shutdown(iocom->msg_fp, SHUT_RDWR);
	atomic_set_int(&iocom->msg_ctl, KDMSG_CLUSTERCTL_KILLRX |
					KDMSG_CLUSTERCTL_KILLTX);
	wakeup(&iocom->msg_ctl);

	/*
	 * The transmit thread is responsible for final cleanups, wait
	 * for the receive side to terminate to prevent new received
	 * states from interfering with our cleanup.
	 *
	 * Do not set msgwr_td to NULL until we actually exit.
	 */
	while (iocom->msgrd_td) {
		wakeup(&iocom->msg_ctl);
		lksleep(iocom, &iocom->msglk, 0, "clstrkt", hz);
	}

	/*
	 * We can no longer receive new messages.  We must drain the transmit
	 * message queue and simulate received messages to close anay remaining
	 * states.
	 *
	 * Loop until all the states are gone and there are no messages
	 * pending transmit.
	 */
	save_ticks = ticks;
	didwarn = 0;
	iocom->flags |= KDMSG_IOCOMF_EXITNOACC;

	while (TAILQ_FIRST(&iocom->msgq) ||
	       RB_ROOT(&iocom->staterd_tree) ||
	       RB_ROOT(&iocom->statewr_tree) ||
	       iocom->conn_state) {
		/*
		 * Simulate failure for all sub-states of state0.
		 */
		kdmsg_drain_msgq(iocom);
		kdmsg_simulate_failure(&iocom->state0, 0, DMSG_ERR_LOSTLINK);

		lksleep(iocom, &iocom->msglk, 0, "clstrtk", hz / 2);

		if ((int)(ticks - save_ticks) > hz*2 && didwarn == 0) {
			didwarn = 1;
			kdio_printf(iocom, 0,
				    "Warning, write thread on %p "
				    "still terminating\n",
				    iocom);
		}
		if ((int)(ticks - save_ticks) > hz*15 && didwarn == 1) {
			didwarn = 2;
			kdio_printf(iocom, 0,
				    "Warning, write thread on %p "
				    "still terminating\n",
				    iocom);
		}
		if ((int)(ticks - save_ticks) > hz*60) {
			kdio_printf(iocom, 0,
				    "Can't terminate: msgq %p "
				    "rd_tree %p wr_tree %p\n",
				    TAILQ_FIRST(&iocom->msgq),
				    RB_ROOT(&iocom->staterd_tree),
				    RB_ROOT(&iocom->statewr_tree));
			lksleep(iocom, &iocom->msglk, 0, "clstrtk", hz * 10);
		}
	}

	/*
	 * Exit handling is done by the write thread.
	 */
	lockmgr(&iocom->msglk, LK_RELEASE);

	/*
	 * The state trees had better be empty now
	 */
	KKASSERT(RB_EMPTY(&iocom->staterd_tree));
	KKASSERT(RB_EMPTY(&iocom->statewr_tree));
	KKASSERT(iocom->conn_state == NULL);

	if (iocom->exit_func) {
		/*
		 * iocom is invalid after we call the exit function.
		 */
		iocom->msgwr_td = NULL;
		iocom->exit_func(iocom);
	} else {
		/*
		 * iocom can be ripped out from under us once msgwr_td is
		 * set to NULL.  The wakeup is safe.
		 */
		iocom->msgwr_td = NULL;
		wakeup(iocom);
	}
	lwkt_exit();
}

/*
 * This cleans out the pending transmit message queue, adjusting any
 * persistent states properly in the process.
 *
 * Called with iocom locked.
 */
void
kdmsg_drain_msgq(kdmsg_iocom_t *iocom)
{
	kdmsg_msg_t *msg;

	/*
	 * Clean out our pending transmit queue, executing the
	 * appropriate state adjustments as if the messages were
	 * sent.
	 */
	while ((msg = TAILQ_FIRST(&iocom->msgq)) != NULL) {
		TAILQ_REMOVE(&iocom->msgq, msg, qentry);
		kdmsg_drain_msg(msg);
	}
}

/*
 * Drain one message by simulating transmission and also simulating a
 * receive failure.
 */
static void
kdmsg_drain_msg(kdmsg_msg_t *msg)
{
	if (kdmsg_state_msgtx(msg)) {
		kdmsg_msg_free(msg);
	} else {
		if (msg->state) {
			kdmsg_simulate_failure(msg->state,
					       0, DMSG_ERR_LOSTLINK);
		}
		kdmsg_state_cleanuptx(msg);
	}
}

/*
 * Do all processing required to handle a freshly received message
 * after its low level header has been validated.
 *
 * iocom is not locked.
 */
static
int
kdmsg_msg_receive_handling(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	int error;

	/*
	 * State machine tracking, state assignment for msg,
	 * returns error and discard status.  Errors are fatal
	 * to the connection except for EALREADY which forces
	 * a discard without execution.
	 */
	error = kdmsg_state_msgrx(msg);
	if (msg->state->flags & KDMSG_STATE_ABORTING) {
		kdio_printf(iocom, 5,
			    "kdmsg_state_abort(b): state %p rxcmd=%08x "
			    "txcmd=%08x msgrx error %d\n",
			    msg->state, msg->state->rxcmd,
			    msg->state->txcmd, error);
	}
	if (error) {
		/*
		 * Raw protocol or connection error
		 */
		if (msg->state->flags & KDMSG_STATE_ABORTING)
			kdio_printf(iocom, 5,
				    "X1 state %p error %d\n",
				    msg->state, error);
		kdmsg_msg_free(msg);
		if (error == EALREADY)
			error = 0;
	} else if (msg->state && msg->state->func) {
		/*
		 * Message related to state which already has a
		 * handling function installed for it.
		 */
		if (msg->state->flags & KDMSG_STATE_ABORTING)
			kdio_printf(iocom, 5,
				    "X2 state %p func %p\n",
				    msg->state, msg->state->func);
		error = msg->state->func(msg->state, msg);
		kdmsg_state_cleanuprx(msg);
	} else if (iocom->flags & KDMSG_IOCOMF_AUTOANY) {
		if (msg->state->flags & KDMSG_STATE_ABORTING)
			kdio_printf(iocom, 5,
				    "X3 state %p\n", msg->state);
		error = kdmsg_autorxmsg(msg);
		kdmsg_state_cleanuprx(msg);
	} else {
		if (msg->state->flags & KDMSG_STATE_ABORTING)
			kdio_printf(iocom, 5,
				    "X4 state %p\n", msg->state);
		error = iocom->rcvmsg(msg);
		kdmsg_state_cleanuprx(msg);
	}
	return error;
}

/*
 * Process state tracking for a message after reception and dequeueing,
 * prior to execution of the state callback.  The state is updated and
 * will be removed from the RBTREE if completely closed, but the state->parent
 * and subq linkage is not cleaned up until after the callback (see
 * cleanuprx()).
 *
 * msglk is not held.
 *
 * NOTE: A message transaction can consist of several messages in either
 *	 direction.
 *
 * NOTE: The msgid is unique to the initiator, not necessarily unique for
 *	 us or for any relay or for the return direction for that matter.
 *	 That is, two sides sending a new message can use the same msgid
 *	 without colliding.
 *
 * --
 *
 * ABORT sequences work by setting the ABORT flag along with normal message
 * state.  However, ABORTs can also be sent on half-closed messages, that is
 * even if the command or reply side has already sent a DELETE, as long as
 * the message has not been fully closed it can still send an ABORT+DELETE
 * to terminate the half-closed message state.
 *
 * Since ABORT+DELETEs can race we silently discard ABORT's for message
 * state which has already been fully closed.  REPLY+ABORT+DELETEs can
 * also race, and in this situation the other side might have already
 * initiated a new unrelated command with the same message id.  Since
 * the abort has not set the CREATE flag the situation can be detected
  * and the message will also be discarded.
 *
 * Non-blocking requests can be initiated with ABORT+CREATE[+DELETE].
 * The ABORT request is essentially integrated into the command instead
 * of being sent later on.  In this situation the command implementation
 * detects that CREATE and ABORT are both set (vs ABORT alone) and can
 * special-case non-blocking operation for the command.
 *
 * NOTE!  Messages with ABORT set without CREATE or DELETE are considered
 *	  to be mid-stream aborts for command/reply sequences.  ABORTs on
 *	  one-way messages are not supported.
 *
 * NOTE!  If a command sequence does not support aborts the ABORT flag is
 *	  simply ignored.
 *
 * --
 *
 * One-off messages (no reply expected) are sent with neither CREATE or DELETE
 * set.  One-off messages cannot be aborted and typically aren't processed
 * by these routines.  The REPLY bit can be used to distinguish whether a
 * one-off message is a command or reply.  For example, one-off replies
 * will typically just contain status updates.
 */
static
int
kdmsg_state_msgrx(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	kdmsg_state_t *state;
	kdmsg_state_t *pstate;
	kdmsg_state_t sdummy;
	int error;

	bzero(&sdummy, sizeof(sdummy));	/* avoid gcc warnings */

	/*
	 * Make sure a state structure is ready to go in case we need a new
	 * one.  This is the only routine which uses freerd_state so no
	 * races are possible.
	 */
	if ((state = iocom->freerd_state) == NULL) {
		state = kmalloc(sizeof(*state), iocom->mmsg, M_WAITOK | M_ZERO);
		state->flags = KDMSG_STATE_DYNAMIC;
		state->iocom = iocom;
		state->refs = 1;
		TAILQ_INIT(&state->subq);
		iocom->freerd_state = state;
	}
	state = NULL;	/* safety */

	/*
	 * Lock RB tree and locate existing persistent state, if any.
	 *
	 * If received msg is a command state is on staterd_tree.
	 * If received msg is a reply state is on statewr_tree.
	 */
	lockmgr(&iocom->msglk, LK_EXCLUSIVE);

again:
	if (msg->state == &iocom->state0) {
		sdummy.msgid = msg->any.head.msgid;
		sdummy.iocom = iocom;
		if (msg->any.head.cmd & DMSGF_REVTRANS) {
			state = RB_FIND(kdmsg_state_tree, &iocom->statewr_tree,
					&sdummy);
		} else {
			state = RB_FIND(kdmsg_state_tree, &iocom->staterd_tree,
					&sdummy);
		}

		/*
		 * Set message state unconditionally.  If this is a CREATE
		 * message this state will become the parent state and new
		 * state will be allocated for the message state.
		 */
		if (state == NULL)
			state = &iocom->state0;
		if (state->flags & KDMSG_STATE_INTERLOCK) {
			state->flags |= KDMSG_STATE_SIGNAL;
			lksleep(state, &iocom->msglk, 0, "dmrace", hz);
			goto again;
		}
		kdmsg_state_hold(state);
		kdmsg_state_drop(msg->state);	/* iocom->state0 */
		msg->state = state;
	} else {
		state = msg->state;
	}

	/*
	 * Short-cut one-off or mid-stream messages.
	 */
	if ((msg->any.head.cmd & (DMSGF_CREATE | DMSGF_DELETE |
				  DMSGF_ABORT)) == 0) {
		error = 0;
		goto done;
	}

	/*
	 * Switch on CREATE, DELETE, REPLY, and also handle ABORT from
	 * inside the case statements.
	 */
	switch(msg->any.head.cmd & (DMSGF_CREATE|DMSGF_DELETE|DMSGF_REPLY)) {
	case DMSGF_CREATE:
	case DMSGF_CREATE | DMSGF_DELETE:
		/*
		 * New persistent command received.
		 */
		if (state != &iocom->state0) {
			kdio_printf(iocom, 1, "%s\n",
				    "duplicate transaction");
			error = EINVAL;
			break;
		}

		/*
		 * Lookup the circuit.  The circuit is an open transaction.
		 * the REVCIRC bit in the message tells us which side
		 * initiated the transaction representing the circuit.
		 */
		if (msg->any.head.circuit) {
			sdummy.msgid = msg->any.head.circuit;

			if (msg->any.head.cmd & DMSGF_REVCIRC) {
				pstate = RB_FIND(kdmsg_state_tree,
						 &iocom->statewr_tree,
						 &sdummy);
			} else {
				pstate = RB_FIND(kdmsg_state_tree,
						 &iocom->staterd_tree,
						 &sdummy);
			}
			if (pstate == NULL) {
				kdio_printf(iocom, 1, "%s\n",
					    "missing parent in "
					    "stacked trans");
				error = EINVAL;
				break;
			}
		} else {
			pstate = &iocom->state0;
		}

		/*
		 * Allocate new state.
		 *
		 * msg->state becomes the owner of the ref we inherit from
		 * freerd_stae.
		 */
		kdmsg_state_drop(state);
		state = iocom->freerd_state;
		iocom->freerd_state = NULL;

		msg->state = state;		/* inherits freerd ref */
		state->parent = pstate;
		KKASSERT(state->iocom == iocom);
		state->flags |= KDMSG_STATE_RBINSERTED |
				KDMSG_STATE_SUBINSERTED |
			        KDMSG_STATE_OPPOSITE;
		if (TAILQ_EMPTY(&pstate->subq))
			kdmsg_state_hold(pstate);/* states on pstate->subq */
		kdmsg_state_hold(state);	/* state on pstate->subq */
		kdmsg_state_hold(state);	/* state on rbtree */
		state->icmd = msg->any.head.cmd & DMSGF_BASECMDMASK;
		state->rxcmd = msg->any.head.cmd & ~DMSGF_DELETE;
		state->txcmd = DMSGF_REPLY;
		state->msgid = msg->any.head.msgid;
		state->flags &= ~KDMSG_STATE_NEW;
		RB_INSERT(kdmsg_state_tree, &iocom->staterd_tree, state);
		TAILQ_INSERT_TAIL(&pstate->subq, state, entry);
		error = 0;
		break;
	case DMSGF_DELETE:
		/*
		 * Persistent state is expected but might not exist if an
		 * ABORT+DELETE races the close.
		 */
		if (state == &iocom->state0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				kdio_printf(iocom, 1, "%s\n",
					    "msgrx: "
					    "state already A");
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgrx: no state for DELETE");
				error = EINVAL;
			}
			break;
		}

		/*
		 * Handle another ABORT+DELETE case if the msgid has already
		 * been reused.
		 */
		if ((state->rxcmd & DMSGF_CREATE) == 0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				kdio_printf(iocom, 1, "%s\n",
					    "msgrx: state already B");
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgrx: state reused for DELETE");
				error = EINVAL;
			}
			break;
		}
		error = 0;
		break;
	default:
		/*
		 * Check for mid-stream ABORT command received, otherwise
		 * allow.
		 */
		if (msg->any.head.cmd & DMSGF_ABORT) {
			if (state == &iocom->state0 ||
			    (state->rxcmd & DMSGF_CREATE) == 0) {
				error = EALREADY;
				break;
			}
		}
		error = 0;
		break;
	case DMSGF_REPLY | DMSGF_CREATE:
	case DMSGF_REPLY | DMSGF_CREATE | DMSGF_DELETE:
		/*
		 * When receiving a reply with CREATE set the original
		 * persistent state message should already exist.
		 */
		if (state == &iocom->state0) {
			kdio_printf(iocom, 1,
				    "msgrx: no state match for "
				    "REPLY cmd=%08x msgid=%016jx\n",
				    msg->any.head.cmd,
				    (intmax_t)msg->any.head.msgid);
			error = EINVAL;
			break;
		}
		state->rxcmd = msg->any.head.cmd & ~DMSGF_DELETE;
		error = 0;
		break;
	case DMSGF_REPLY | DMSGF_DELETE:
		/*
		 * Received REPLY+ABORT+DELETE in case where msgid has
		 * already been fully closed, ignore the message.
		 */
		if (state == &iocom->state0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgrx: no state match "
					    "for REPLY|DELETE");
				error = EINVAL;
			}
			break;
		}

		/*
		 * Received REPLY+ABORT+DELETE in case where msgid has
		 * already been reused for an unrelated message,
		 * ignore the message.
		 */
		if ((state->rxcmd & DMSGF_CREATE) == 0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgrx: state reused "
					    "for REPLY|DELETE");
				error = EINVAL;
			}
			break;
		}
		error = 0;
		break;
	case DMSGF_REPLY:
		/*
		 * Check for mid-stream ABORT reply received to sent command.
		 */
		if (msg->any.head.cmd & DMSGF_ABORT) {
			if (state == &iocom->state0 ||
			    (state->rxcmd & DMSGF_CREATE) == 0) {
				error = EALREADY;
				break;
			}
		}
		error = 0;
		break;
	}

	/*
	 * Calculate the easy-switch() transactional command.  Represents
	 * the outer-transaction command for any transaction-create or
	 * transaction-delete, and the inner message command for any
	 * non-transaction or inside-transaction command.  tcmd will be
	 * set to 0 if the message state is illegal.
	 *
	 * The two can be told apart because outer-transaction commands
	 * always have a DMSGF_CREATE and/or DMSGF_DELETE flag.
	 */
done:
	if (msg->any.head.cmd & (DMSGF_CREATE | DMSGF_DELETE)) {
		if (state != &iocom->state0) {
			msg->tcmd = (msg->state->icmd & DMSGF_BASECMDMASK) |
				    (msg->any.head.cmd & (DMSGF_CREATE |
							  DMSGF_DELETE |
							  DMSGF_REPLY));
		} else {
			msg->tcmd = 0;
		}
	} else {
		msg->tcmd = msg->any.head.cmd & DMSGF_CMDSWMASK;
	}

	/*
	 * Adjust the state for DELETE handling now, before making the
	 * callback so we are atomic with other state updates.
	 *
	 * Subq/parent linkages are cleaned up after the callback.
	 * If an error occurred the message is ignored and state is not
	 * updated.
	 */
	if ((state = msg->state) == NULL || error != 0) {
		kdio_printf(iocom, 1,
			    "msgrx: state=%p error %d\n",
			    state, error);
	} else if (msg->any.head.cmd & DMSGF_DELETE) {
		KKASSERT((state->rxcmd & DMSGF_DELETE) == 0);
		state->rxcmd |= DMSGF_DELETE;
		if (state->txcmd & DMSGF_DELETE) {
			KKASSERT(state->flags & KDMSG_STATE_RBINSERTED);
			if (state->rxcmd & DMSGF_REPLY) {
				KKASSERT(msg->any.head.cmd &
					 DMSGF_REPLY);
				RB_REMOVE(kdmsg_state_tree,
					  &iocom->statewr_tree, state);
			} else {
				KKASSERT((msg->any.head.cmd &
					  DMSGF_REPLY) == 0);
				RB_REMOVE(kdmsg_state_tree,
					  &iocom->staterd_tree, state);
			}
			state->flags &= ~KDMSG_STATE_RBINSERTED;
			kdmsg_state_drop(state);	/* state on rbtree */
		}
	}
	lockmgr(&iocom->msglk, LK_RELEASE);

	return (error);
}

/*
 * Called instead of iocom->rcvmsg() if any of the AUTO flags are set.
 * This routine must call iocom->rcvmsg() for anything not automatically
 * handled.
 */
static int
kdmsg_autorxmsg(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	kdmsg_msg_t *rep;
	int error = 0;
	uint32_t cmd;

	/*
	 * Main switch processes transaction create/delete sequences only.
	 * Use icmd (DELETEs use DMSG_LNK_ERROR
	 *
	 * NOTE: If processing in-transaction messages you generally want
	 *	 an inner switch on msg->any.head.cmd.
	 */
	if (msg->state) {
		cmd = (msg->state->icmd & DMSGF_BASECMDMASK) |
		      (msg->any.head.cmd & (DMSGF_CREATE |
					    DMSGF_DELETE |
					    DMSGF_REPLY));
	} else {
		cmd = 0;
	}

	switch(cmd) {
	case DMSG_LNK_PING:
		/*
		 * Received ping, send reply
		 */
		rep = kdmsg_msg_alloc(msg->state, DMSG_LNK_PING | DMSGF_REPLY,
				      NULL, NULL);
		kdmsg_msg_write(rep);
		break;
	case DMSG_LNK_PING | DMSGF_REPLY:
		/* ignore replies */
		break;
	case DMSG_LNK_CONN | DMSGF_CREATE:
	case DMSG_LNK_CONN | DMSGF_CREATE | DMSGF_DELETE:
		/*
		 * Received LNK_CONN transaction.  Transmit response and
		 * leave transaction open, which allows the other end to
		 * start to the SPAN protocol.
		 *
		 * Handle shim after acknowledging the CONN.
		 */
		if ((msg->any.head.cmd & DMSGF_DELETE) == 0) {
			if (iocom->flags & KDMSG_IOCOMF_AUTOCONN) {
				kdmsg_msg_result(msg, 0);
				if (iocom->auto_callback)
					iocom->auto_callback(msg);
			} else {
				error = iocom->rcvmsg(msg);
			}
			break;
		}
		/* fall through */
	case DMSG_LNK_CONN | DMSGF_DELETE:
		/*
		 * This message is usually simulated after a link is lost
		 * to clean up the transaction.
		 */
		if (iocom->flags & KDMSG_IOCOMF_AUTOCONN) {
			if (iocom->auto_callback)
				iocom->auto_callback(msg);
			kdmsg_msg_reply(msg, 0);
		} else {
			error = iocom->rcvmsg(msg);
		}
		break;
	case DMSG_LNK_SPAN | DMSGF_CREATE:
	case DMSG_LNK_SPAN | DMSGF_CREATE | DMSGF_DELETE:
		/*
		 * Received LNK_SPAN transaction.  We do not have to respond
		 * (except on termination), but we must leave the transaction
		 * open.
		 *
		 * Handle shim after acknowledging the SPAN.
		 */
		if (iocom->flags & KDMSG_IOCOMF_AUTORXSPAN) {
			if ((msg->any.head.cmd & DMSGF_DELETE) == 0) {
				if (iocom->auto_callback)
					iocom->auto_callback(msg);
				break;
			}
			/* fall through */
		} else {
			error = iocom->rcvmsg(msg);
			break;
		}
		/* fall through */
	case DMSG_LNK_SPAN | DMSGF_DELETE:
		/*
		 * Process shims (auto_callback) before cleaning up the
		 * circuit structure and closing the transactions.  Device
		 * driver should ensure that the circuit is not used after
		 * the auto_callback() returns.
		 *
		 * Handle shim before closing the SPAN transaction.
		 */
		if (iocom->flags & KDMSG_IOCOMF_AUTORXSPAN) {
			if (iocom->auto_callback)
				iocom->auto_callback(msg);
			kdmsg_msg_reply(msg, 0);
		} else {
			error = iocom->rcvmsg(msg);
		}
		break;
	default:
		/*
		 * Anything unhandled goes into rcvmsg.
		 *
		 * NOTE: Replies to link-level messages initiated by our side
		 *	 are handled by the state callback, they are NOT
		 *	 handled here.
		 */
		error = iocom->rcvmsg(msg);
		break;
	}
	return (error);
}

/*
 * Post-receive-handling message and state cleanup.  This routine is called
 * after the state function handling/callback to properly dispose of the
 * message and unlink the state's parent/subq linkage if the state is
 * completely closed.
 *
 * msglk is not held.
 */
static
void
kdmsg_state_cleanuprx(kdmsg_msg_t *msg)
{
	kdmsg_state_t *state = msg->state;
	kdmsg_iocom_t *iocom = state->iocom;

	lockmgr(&iocom->msglk, LK_EXCLUSIVE);
	if (state != &iocom->state0) {
		/*
		 * When terminating a transaction (in either direction), all
		 * sub-states are aborted.
		 */
		if ((msg->any.head.cmd & DMSGF_DELETE) &&
		    TAILQ_FIRST(&msg->state->subq)) {
			kdio_printf(iocom, 2,
				    "simulate failure for substates of "
				    "state %p cmd %08x/%08x\n",
				    msg->state,
				    msg->state->rxcmd,
				    msg->state->txcmd);
			kdmsg_simulate_failure(msg->state,
					       0, DMSG_ERR_LOSTLINK);
		}

		/*
		 * Once the state is fully closed we can (try to) remove it
		 * from the subq topology.
		 */
		if ((state->flags & KDMSG_STATE_SUBINSERTED) &&
		    (state->rxcmd & DMSGF_DELETE) &&
		    (state->txcmd & DMSGF_DELETE)) {
			/* 
			 * Remove parent linkage if state is completely closed.
			 */
			kdmsg_subq_delete(state);
		}
	}
	kdmsg_msg_free(msg);

	lockmgr(&iocom->msglk, LK_RELEASE);
}

/*
 * Remove state from its parent's subq.  This can wind up recursively
 * dropping the parent upward.
 *
 * NOTE: Once we drop the parent, our pstate pointer may become invalid.
 */
static
void
kdmsg_subq_delete(kdmsg_state_t *state)
{
	kdmsg_state_t *pstate;

	if (state->flags & KDMSG_STATE_SUBINSERTED) {
		pstate = state->parent;
		KKASSERT(pstate);
		if (pstate->scan == state)
			pstate->scan = NULL;
		TAILQ_REMOVE(&pstate->subq, state, entry);
		state->flags &= ~KDMSG_STATE_SUBINSERTED;
		state->parent = NULL;
		if (TAILQ_EMPTY(&pstate->subq)) {
			kdmsg_state_drop(pstate);/* pstate->subq */
		}
		pstate = NULL;			 /* safety */
		kdmsg_state_drop(state);  	 /* pstate->subq */
	} else {
		KKASSERT(state->parent == NULL);
	}
}

/*
 * Simulate receiving a message which terminates an active transaction
 * state.  Our simulated received message must set DELETE and may also
 * have to set CREATE.  It must also ensure that all fields are set such
 * that the receive handling code can find the state (kdmsg_state_msgrx())
 * or an endless loop will ensue.
 *
 * This is used when the other end of the link is dead so the device driver
 * gets a completed transaction for all pending states.
 *
 * Called with iocom locked.
 */
static
void
kdmsg_simulate_failure(kdmsg_state_t *state, int meto, int error)
{
	kdmsg_state_t *substate;

	kdmsg_state_hold(state);		/* aborting */

	/*
	 * Abort parent state first. Parent will not actually disappear
	 * until children are gone.  Device drivers must handle the situation.
	 * The advantage of this is that device drivers can flag the situation
	 * as an interlock against new operations on dying states.  And since
	 * device operations are often asynchronous anyway, this sequence of
	 * events works out better.
	 */
	if (meto)
		kdmsg_state_abort(state);

	/*
	 * Recurse through any children.
	 */
again:
	TAILQ_FOREACH(substate, &state->subq, entry) {
		if (substate->flags & KDMSG_STATE_ABORTING)
			continue;
		state->scan = substate;
		kdmsg_simulate_failure(substate, 1, error);
		if (state->scan != substate)
			goto again;
	}
	kdmsg_state_drop(state);		/* aborting */
}

static
void
kdmsg_state_abort(kdmsg_state_t *state)
{
	kdmsg_msg_t *msg;

	/*
	 * Set ABORTING and DYING, return if already set.  If the state was
	 * just allocated we defer the abort operation until the related
	 * message is processed.
	 */
	KKASSERT((state->flags & KDMSG_STATE_ABORTING) == 0);
	if (state->flags & KDMSG_STATE_ABORTING)
		return;
	state->flags |= KDMSG_STATE_ABORTING;
	kdmsg_state_dying(state);
	if (state->flags & KDMSG_STATE_NEW) {
		kdio_printf(iocom, 5,
			    "kdmsg_state_abort(0): state %p rxcmd %08x "
			    "txcmd %08x flags %08x - in NEW state\n",
			    state, state->rxcmd,
			    state->txcmd, state->flags);
		return;
	}

	/*
	 * NOTE: The DELETE flag might already be set due to an early
	 *	 termination.
	 *
	 * NOTE: Args to kdmsg_msg_alloc() to avoid dynamic state allocation.
	 *
	 * NOTE: We are simulating a received message using our state
	 *	 (vs a message generated by the other side using its state),
	 *	 so we must invert DMSGF_REVTRANS and DMSGF_REVCIRC.
	 */
	kdio_printf(iocom, 5, 
		    "kdmsg_state_abort(1): state %p rxcmd %08x txcmd %08x\n",
		    state, state->rxcmd, state->txcmd);
	if ((state->rxcmd & DMSGF_DELETE) == 0) {
		msg = kdmsg_msg_alloc(state, DMSG_LNK_ERROR, NULL, NULL);
		if ((state->rxcmd & DMSGF_CREATE) == 0)
			msg->any.head.cmd |= DMSGF_CREATE;
		msg->any.head.cmd |= DMSGF_DELETE |
				     (state->rxcmd & DMSGF_REPLY);
		msg->any.head.cmd ^= (DMSGF_REVTRANS | DMSGF_REVCIRC);
		msg->any.head.error = DMSG_ERR_LOSTLINK;
		kdio_printf(iocom, 5,
			    "kdmsg_state_abort(a): state %p msgcmd %08x\n",
			    state, msg->any.head.cmd);
		/* circuit not initialized */
		lockmgr(&state->iocom->msglk, LK_RELEASE);
		kdmsg_msg_receive_handling(msg);
		lockmgr(&state->iocom->msglk, LK_EXCLUSIVE);
		msg = NULL;
	}
	kdio_printf(iocom, 5,
		    "kdmsg_state_abort(2): state %p rxcmd %08x txcmd %08x\n",
		    state, state->rxcmd, state->txcmd);
}

/*
 * Recursively sets KDMSG_STATE_DYING on state and all sub-states, preventing
 * the transmission of any new messages on these states.  This is done
 * atomically when parent state is terminating, whereas setting ABORTING is
 * not atomic and can leak races.
 */
static
void
kdmsg_state_dying(kdmsg_state_t *state)
{
	kdmsg_state_t *scan;

	if ((state->flags & KDMSG_STATE_DYING) == 0) {
		state->flags |= KDMSG_STATE_DYING;
		TAILQ_FOREACH(scan, &state->subq, entry)
			kdmsg_state_dying(scan);
	}
}

/*
 * Process state tracking for a message prior to transmission.
 *
 * Called with msglk held and the msg dequeued.  Returns non-zero if
 * the message is bad and should be deleted by the caller.
 *
 * One-off messages are usually with dummy state and msg->state may be NULL
 * in this situation.
 *
 * New transactions (when CREATE is set) will insert the state.
 *
 * May request that caller discard the message by setting *discardp to 1.
 * A NULL state may be returned in this case.
 */
static
int
kdmsg_state_msgtx(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	kdmsg_state_t *state;
	int error;

	/*
	 * Make sure a state structure is ready to go in case we need a new
	 * one.  This is the only routine which uses freewr_state so no
	 * races are possible.
	 */
	if ((state = iocom->freewr_state) == NULL) {
		state = kmalloc(sizeof(*state), iocom->mmsg, M_WAITOK | M_ZERO);
		state->flags = KDMSG_STATE_DYNAMIC;
		state->iocom = iocom;
		state->refs = 1;
		TAILQ_INIT(&state->subq);
		iocom->freewr_state = state;
	}

	/*
	 * Lock RB tree.  If persistent state is present it will have already
	 * been assigned to msg.
	 */
	state = msg->state;

	/*
	 * Short-cut one-off or mid-stream messages (state may be NULL).
	 */
	if ((msg->any.head.cmd & (DMSGF_CREATE | DMSGF_DELETE |
				  DMSGF_ABORT)) == 0) {
		return(0);
	}


	/*
	 * Switch on CREATE, DELETE, REPLY, and also handle ABORT from
	 * inside the case statements.
	 */
	switch(msg->any.head.cmd & (DMSGF_CREATE | DMSGF_DELETE |
				    DMSGF_REPLY)) {
	case DMSGF_CREATE:
	case DMSGF_CREATE | DMSGF_DELETE:
		/*
		 * Insert the new persistent message state and mark
		 * half-closed if DELETE is set.  Since this is a new
		 * message it isn't possible to transition into the fully
		 * closed state here.
		 *
		 * XXX state must be assigned and inserted by
		 *     kdmsg_msg_write().  txcmd is assigned by us
		 *     on-transmit.
		 */
		KKASSERT(state != NULL);
		state->icmd = msg->any.head.cmd & DMSGF_BASECMDMASK;
		state->txcmd = msg->any.head.cmd & ~DMSGF_DELETE;
		state->rxcmd = DMSGF_REPLY;
		state->flags &= ~KDMSG_STATE_NEW;
		error = 0;
		break;
	case DMSGF_DELETE:
		/*
		 * Sent ABORT+DELETE in case where msgid has already
		 * been fully closed, ignore the message.
		 */
		if (state == &iocom->state0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1,
					"msgtx: no state match "
					"for DELETE cmd=%08x msgid=%016jx\n",
					msg->any.head.cmd,
					(intmax_t)msg->any.head.msgid);
				error = EINVAL;
			}
			break;
		}

		/*
		 * Sent ABORT+DELETE in case where msgid has
		 * already been reused for an unrelated message,
		 * ignore the message.
		 */
		if ((state->txcmd & DMSGF_CREATE) == 0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgtx: state reused "
					    "for DELETE");
				error = EINVAL;
			}
			break;
		}
		error = 0;
		break;
	default:
		/*
		 * Check for mid-stream ABORT command sent
		 */
		if (msg->any.head.cmd & DMSGF_ABORT) {
			if (state == &state->iocom->state0 ||
			    (state->txcmd & DMSGF_CREATE) == 0) {
				error = EALREADY;
				break;
			}
		}
		error = 0;
		break;
	case DMSGF_REPLY | DMSGF_CREATE:
	case DMSGF_REPLY | DMSGF_CREATE | DMSGF_DELETE:
		/*
		 * When transmitting a reply with CREATE set the original
		 * persistent state message should already exist.
		 */
		if (state == &state->iocom->state0) {
			kdio_printf(iocom, 1, "%s\n",
				    "msgtx: no state match "
				    "for REPLY | CREATE");
			error = EINVAL;
			break;
		}
		state->txcmd = msg->any.head.cmd & ~DMSGF_DELETE;
		error = 0;
		break;
	case DMSGF_REPLY | DMSGF_DELETE:
		/*
		 * When transmitting a reply with DELETE set the original
		 * persistent state message should already exist.
		 *
		 * This is very similar to the REPLY|CREATE|* case except
		 * txcmd is already stored, so we just add the DELETE flag.
		 *
		 * Sent REPLY+ABORT+DELETE in case where msgid has
		 * already been fully closed, ignore the message.
		 */
		if (state == &state->iocom->state0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgtx: no state match "
					    "for REPLY | DELETE");
				error = EINVAL;
			}
			break;
		}

		/*
		 * Sent REPLY+ABORT+DELETE in case where msgid has already
		 * been reused for an unrelated message, ignore the message.
		 */
		if ((state->txcmd & DMSGF_CREATE) == 0) {
			if (msg->any.head.cmd & DMSGF_ABORT) {
				error = EALREADY;
			} else {
				kdio_printf(iocom, 1, "%s\n",
					    "msgtx: state reused "
					    "for REPLY | DELETE");
				error = EINVAL;
			}
			break;
		}
		error = 0;
		break;
	case DMSGF_REPLY:
		/*
		 * Check for mid-stream ABORT reply sent.
		 *
		 * One-off REPLY messages are allowed for e.g. status updates.
		 */
		if (msg->any.head.cmd & DMSGF_ABORT) {
			if (state == &state->iocom->state0 ||
			    (state->txcmd & DMSGF_CREATE) == 0) {
				error = EALREADY;
				break;
			}
		}
		error = 0;
		break;
	}

	/*
	 * Set interlock (XXX hack) in case the send side blocks and a
	 * response is returned before kdmsg_state_cleanuptx() can be
	 * run.
	 */
	if (state && error == 0)
		state->flags |= KDMSG_STATE_INTERLOCK;

	return (error);
}

/*
 * Called with iocom locked.
 */
static
void
kdmsg_state_cleanuptx(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	kdmsg_state_t *state;

	if ((state = msg->state) == NULL) {
		kdmsg_msg_free(msg);
		return;
	}

	/*
	 * Clear interlock (XXX hack) in case the send side blocks and a
	 * response is returned in the other thread before
	 * kdmsg_state_cleanuptx() can be run.  We maintain our hold on
	 * iocom->msglk so we can do this before completing our task.
	 */
	if (state->flags & KDMSG_STATE_SIGNAL) {
		kdio_printf(iocom, 1, "state %p interlock!\n", state);
		wakeup(state);
	}
	state->flags &= ~(KDMSG_STATE_INTERLOCK | KDMSG_STATE_SIGNAL);
	kdmsg_state_hold(state);

	if (msg->any.head.cmd & DMSGF_DELETE) {
		KKASSERT((state->txcmd & DMSGF_DELETE) == 0);
		state->txcmd |= DMSGF_DELETE;
		if (state->rxcmd & DMSGF_DELETE) {
			KKASSERT(state->flags & KDMSG_STATE_RBINSERTED);
			if (state->txcmd & DMSGF_REPLY) {
				KKASSERT(msg->any.head.cmd &
					 DMSGF_REPLY);
				RB_REMOVE(kdmsg_state_tree,
					  &iocom->staterd_tree, state);
			} else {
				KKASSERT((msg->any.head.cmd &
					  DMSGF_REPLY) == 0);
				RB_REMOVE(kdmsg_state_tree,
					  &iocom->statewr_tree, state);
			}
			state->flags &= ~KDMSG_STATE_RBINSERTED;

			/*
			 * The subq recursion is used for parent linking and
			 * scanning the topology for aborts, we can only
			 * remove leafs.  The circuit is effectively dead now,
			 * but topology won't be torn down until all of its
			 * children have finished/aborted.
			 *
			 * This is particularly important for end-point
			 * devices which might need to access private data
			 * in parent states.  Out of order disconnects can
			 * occur if an end-point device is processing a
			 * message transaction asynchronously because abort
			 * requests are basically synchronous and it probably
			 * isn't convenient (or possible) for the end-point
			 * to abort an asynchronous operation.
			 */
			if (TAILQ_EMPTY(&state->subq))
				kdmsg_subq_delete(state);
			kdmsg_msg_free(msg);
			kdmsg_state_drop(state);   /* state on rbtree */
		} else {
			kdmsg_msg_free(msg);
		}
	} else {
		kdmsg_msg_free(msg);
	}

	/*
	 * Deferred abort after transmission.
	 */
	if ((state->flags & (KDMSG_STATE_ABORTING | KDMSG_STATE_DYING)) &&
	    (state->rxcmd & DMSGF_DELETE) == 0) {
		kdio_printf(iocom, 5,
			    "kdmsg_state_cleanuptx: state=%p "
			    "executing deferred abort\n",
			    state);
		state->flags &= ~KDMSG_STATE_ABORTING;
		kdmsg_state_abort(state);
	}
	kdmsg_state_drop(state);
}

static
void
_kdmsg_state_hold(kdmsg_state_t *state KDMSG_DEBUG_ARGS)
{
	atomic_add_int(&state->refs, 1);
#if KDMSG_DEBUG
	kd_printf(4, "state %p +%d\t%s:%d\n", state, state->refs, file, line);
#endif
}

static
void
_kdmsg_state_drop(kdmsg_state_t *state KDMSG_DEBUG_ARGS)
{
	KKASSERT(state->refs > 0);
#if KDMSG_DEBUG
	kd_printf(4, "state %p -%d\t%s:%d\n", state, state->refs, file, line);
#endif
	if (atomic_fetchadd_int(&state->refs, -1) == 1)
		kdmsg_state_free(state);
}

static
void
kdmsg_state_free(kdmsg_state_t *state)
{
	kdmsg_iocom_t *iocom = state->iocom;

	KKASSERT((state->flags & KDMSG_STATE_RBINSERTED) == 0);
	KKASSERT((state->flags & KDMSG_STATE_SUBINSERTED) == 0);
	KKASSERT(TAILQ_EMPTY(&state->subq));

	if (state != &state->iocom->state0)
		kfree(state, iocom->mmsg);
}

kdmsg_msg_t *
kdmsg_msg_alloc(kdmsg_state_t *state, uint32_t cmd,
		int (*func)(kdmsg_state_t *, kdmsg_msg_t *), void *data)
{
	kdmsg_iocom_t *iocom = state->iocom;
	kdmsg_state_t *pstate;
	kdmsg_msg_t *msg;
	size_t hbytes;

	KKASSERT(iocom != NULL);
	hbytes = (cmd & DMSGF_SIZE) * DMSG_ALIGN;
	msg = kmalloc(offsetof(struct kdmsg_msg, any) + hbytes,
		      iocom->mmsg, M_WAITOK | M_ZERO);
	msg->hdr_size = hbytes;

	if ((cmd & (DMSGF_CREATE | DMSGF_REPLY)) == DMSGF_CREATE) {
		/*
		 * New transaction, requires tracking state and a unique
		 * msgid to be allocated.
		 *
		 * It is possible to race a circuit failure, inherit the
		 * parent's STATE_DYING flag to trigger an abort sequence
		 * in the transmit path.  By not inheriting ABORTING the
		 * abort sequence can recurse.
		 *
		 * NOTE: The transactions has not yet been initiated so we
		 *	 cannot set DMSGF_CREATE/DELETE bits in txcmd or rxcmd.
		 *	 We have to properly setup DMSGF_REPLY, however.
		 */
		pstate = state;
		state = kmalloc(sizeof(*state), iocom->mmsg, M_WAITOK | M_ZERO);
		TAILQ_INIT(&state->subq);
		state->iocom = iocom;
		state->parent = pstate;
		state->flags = KDMSG_STATE_DYNAMIC |
			       KDMSG_STATE_NEW;
		state->func = func;
		state->any.any = data;
		state->msgid = (uint64_t)(uintptr_t)state;
		/*msg->any.head.msgid = state->msgid;XXX*/

		lockmgr(&iocom->msglk, LK_EXCLUSIVE);
		if (RB_INSERT(kdmsg_state_tree, &iocom->statewr_tree, state))
			panic("duplicate msgid allocated");
		if (TAILQ_EMPTY(&pstate->subq))
			kdmsg_state_hold(pstate);/* pstate->subq */
		TAILQ_INSERT_TAIL(&pstate->subq, state, entry);
		state->flags |= KDMSG_STATE_RBINSERTED |
				KDMSG_STATE_SUBINSERTED;
		state->flags |= pstate->flags & KDMSG_STATE_DYING;
		kdmsg_state_hold(state);	/* pstate->subq */
		kdmsg_state_hold(state);	/* state on rbtree */
		kdmsg_state_hold(state);	/* msg->state */
		lockmgr(&iocom->msglk, LK_RELEASE);
	} else {
		pstate = state->parent;
		KKASSERT(pstate != NULL);
		kdmsg_state_hold(state);	/* msg->state */
	}

	if (state->flags & KDMSG_STATE_OPPOSITE)
		cmd |= DMSGF_REVTRANS;
	if (pstate->flags & KDMSG_STATE_OPPOSITE)
		cmd |= DMSGF_REVCIRC;

	msg->any.head.magic = DMSG_HDR_MAGIC;
	msg->any.head.cmd = cmd;
	msg->any.head.msgid = state->msgid;
	msg->any.head.circuit = pstate->msgid;
	msg->state = state;

	return (msg);
}

void
kdmsg_msg_free(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;
	kdmsg_state_t *state;

	if ((msg->flags & KDMSG_FLAG_AUXALLOC) &&
	    msg->aux_data && msg->aux_size) {
		kfree(msg->aux_data, iocom->mmsg);
		msg->aux_data = NULL;
		msg->flags &= ~KDMSG_FLAG_AUXALLOC;
	}
	if ((state = msg->state) != NULL) {
		msg->state = NULL;
		kdmsg_state_drop(state);	/* msg->state */
	}
	msg->aux_data = NULL;
	msg->aux_size = 0;

	kfree(msg, iocom->mmsg);
}

void
kdmsg_detach_aux_data(kdmsg_msg_t *msg, kdmsg_data_t *data)
{
	if (msg->flags & KDMSG_FLAG_AUXALLOC) {
		data->aux_data = msg->aux_data;
		data->aux_size = msg->aux_size;
		data->iocom = msg->state->iocom;
		msg->flags &= ~KDMSG_FLAG_AUXALLOC;
	} else {
		data->aux_data = NULL;
		data->aux_size = 0;
		data->iocom = msg->state->iocom;
	}
}

void
kdmsg_free_aux_data(kdmsg_data_t *data)
{
	if (data->aux_data) {
		kfree(data->aux_data, data->iocom->mmsg);
		data->aux_data = NULL;
	}
}

/*
 * Indexed messages are stored in a red-black tree indexed by their
 * msgid.  Only persistent messages are indexed.
 */
int
kdmsg_state_cmp(kdmsg_state_t *state1, kdmsg_state_t *state2)
{
	if (state1->iocom < state2->iocom)
		return(-1);
	if (state1->iocom > state2->iocom)
		return(1);
	if (state1->msgid < state2->msgid)
		return(-1);
	if (state1->msgid > state2->msgid)
		return(1);
	return(0);
}

/*
 * Write a message.  All requisit command flags have been set.
 *
 * If msg->state is non-NULL the message is written to the existing
 * transaction.  msgid will be set accordingly.
 *
 * If msg->state is NULL and CREATE is set new state is allocated and
 * (func, data) is installed.  A msgid is assigned.
 *
 * If msg->state is NULL and CREATE is not set the message is assumed
 * to be a one-way message.  The originator must assign the msgid
 * (or leave it 0, which is typical.
 *
 * This function merely queues the message to the management thread, it
 * does not write to the message socket/pipe.
 */
void
kdmsg_msg_write(kdmsg_msg_t *msg)
{
	kdmsg_iocom_t *iocom = msg->state->iocom;

	lockmgr(&iocom->msglk, LK_EXCLUSIVE);
	kdmsg_msg_write_locked(iocom, msg);
	lockmgr(&iocom->msglk, LK_RELEASE);
}

static void
kdmsg_msg_write_locked(kdmsg_iocom_t *iocom, kdmsg_msg_t *msg)
{
	kdmsg_state_t *state;

	if (msg->state) {
		/*
		 * Continuance or termination of existing transaction.
		 * The transaction could have been initiated by either end.
		 *
		 * (Function callback and aux data for the receive side can
		 * be replaced or left alone).
		 */
		state = msg->state;
		msg->any.head.msgid = state->msgid;
	} else {
		/*
		 * One-off message (always uses msgid 0 to distinguish
		 * between a possibly lost in-transaction message due to
		 * competing aborts and a real one-off message?)
		 */
		state = NULL;
		msg->any.head.msgid = 0;
	}

	/*
	 * For stateful messages, if the circuit is dead or dying we have
	 * to abort the potentially newly-created state and discard the
	 * message.
	 *
	 * - We must discard the message because the other end will not
	 *   be expecting any more messages over the dead or dying circuit
	 *   and might not be able to receive them.
	 *
	 * - We abort the state by simulating a failure to generate a fake
	 *   incoming DELETE.  This will trigger the state callback and allow
	 *   the device to clean things up and reply, closing the outgoing
	 *   direction and allowing the state to be freed.
	 *
	 * This situation occurs quite often, particularly as SPANs stabilize.
	 * End-points must do the right thing.
	 */
	if (state) {
		KKASSERT((state->txcmd & DMSGF_DELETE) == 0);
		if (state->flags & KDMSG_STATE_DYING) {
#if 0
		if ((state->flags & KDMSG_STATE_DYING) ||
		    (state->parent->txcmd & DMSGF_DELETE) ||
		    (state->parent->flags & KDMSG_STATE_DYING)) {
#endif
			kdio_printf(iocom, 4,
				    "kdmsg_msg_write: Write to dying circuit "
				    "state=%p "
				    "ptxcmd=%08x prxcmd=%08x flags=%08x\n",
				    state,
				    state->parent->rxcmd,
				    state->parent->txcmd,
				    state->parent->flags);
			kdmsg_state_hold(state);
			kdmsg_state_msgtx(msg);
			kdmsg_state_cleanuptx(msg);
			kdmsg_state_drop(state);
			return;
		}
	}

	/*
	 * Finish up the msg fields.  Note that msg->aux_size and the
	 * aux_bytes stored in the message header represent the unaligned
	 * (actual) bytes of data, but the buffer is sized to an aligned
	 * size and the CRC is generated over the aligned length.
	 */
	msg->any.head.salt = /* (random << 8) | */ (iocom->msg_seq & 255);
	++iocom->msg_seq;

	if (msg->aux_data && msg->aux_size) {
		uint32_t abytes = DMSG_DOALIGN(msg->aux_size);

		msg->any.head.aux_bytes = msg->aux_size;
		msg->any.head.aux_crc = iscsi_crc32(msg->aux_data, abytes);
	}
	msg->any.head.hdr_crc = 0;
	msg->any.head.hdr_crc = iscsi_crc32(msg->any.buf, msg->hdr_size);

	/*
	 * If termination races new message senders we must drain the
	 * message immediately instead of queue it.
	 */
	if (iocom->flags & KDMSG_IOCOMF_EXITNOACC)
		kdmsg_drain_msg(msg);
	else
		TAILQ_INSERT_TAIL(&iocom->msgq, msg, qentry);

	if (iocom->msg_ctl & KDMSG_CLUSTERCTL_SLEEPING) {
		atomic_clear_int(&iocom->msg_ctl,
				 KDMSG_CLUSTERCTL_SLEEPING);
		wakeup(&iocom->msg_ctl);
	}
}

/*
 * Reply to a message and terminate our side of the transaction.
 *
 * If msg->state is non-NULL we are replying to a one-way message.
 */
void
kdmsg_msg_reply(kdmsg_msg_t *msg, uint32_t error)
{
	kdmsg_state_t *state = msg->state;
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	/*
	 * Reply with a simple error code and terminate the transaction.
	 */
	cmd = DMSG_LNK_ERROR;

	/*
	 * Check if our direction has even been initiated yet, set CREATE.
	 *
	 * Check what direction this is (command or reply direction).  Note
	 * that txcmd might not have been initiated yet.
	 *
	 * If our direction has already been closed we just return without
	 * doing anything.
	 */
	if (state != &state->iocom->state0) {
		if (state->txcmd & DMSGF_DELETE)
			return;
		if ((state->txcmd & DMSGF_CREATE) == 0)
			cmd |= DMSGF_CREATE;
		if (state->txcmd & DMSGF_REPLY)
			cmd |= DMSGF_REPLY;
		cmd |= DMSGF_DELETE;
	} else {
		if ((msg->any.head.cmd & DMSGF_REPLY) == 0)
			cmd |= DMSGF_REPLY;
	}

	nmsg = kdmsg_msg_alloc(state, cmd, NULL, NULL);
	nmsg->any.head.error = error;
	kdmsg_msg_write(nmsg);
}

/*
 * Reply to a message and continue our side of the transaction.
 *
 * If msg->state is non-NULL we are replying to a one-way message and this
 * function degenerates into the same as kdmsg_msg_reply().
 */
void
kdmsg_msg_result(kdmsg_msg_t *msg, uint32_t error)
{
	kdmsg_state_t *state = msg->state;
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	/*
	 * Return a simple result code, do NOT terminate the transaction.
	 */
	cmd = DMSG_LNK_ERROR;

	/*
	 * Check if our direction has even been initiated yet, set CREATE.
	 *
	 * Check what direction this is (command or reply direction).  Note
	 * that txcmd might not have been initiated yet.
	 *
	 * If our direction has already been closed we just return without
	 * doing anything.
	 */
	if (state != &state->iocom->state0) {
		if (state->txcmd & DMSGF_DELETE)
			return;
		if ((state->txcmd & DMSGF_CREATE) == 0)
			cmd |= DMSGF_CREATE;
		if (state->txcmd & DMSGF_REPLY)
			cmd |= DMSGF_REPLY;
		/* continuing transaction, do not set MSGF_DELETE */
	} else {
		if ((msg->any.head.cmd & DMSGF_REPLY) == 0)
			cmd |= DMSGF_REPLY;
	}

	nmsg = kdmsg_msg_alloc(state, cmd, NULL, NULL);
	nmsg->any.head.error = error;
	kdmsg_msg_write(nmsg);
}

/*
 * Reply to a message and terminate our side of the transaction.
 *
 * If msg->state is non-NULL we are replying to a one-way message.
 */
void
kdmsg_state_reply(kdmsg_state_t *state, uint32_t error)
{
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	/*
	 * Reply with a simple error code and terminate the transaction.
	 */
	cmd = DMSG_LNK_ERROR;

	/*
	 * Check if our direction has even been initiated yet, set CREATE.
	 *
	 * Check what direction this is (command or reply direction).  Note
	 * that txcmd might not have been initiated yet.
	 *
	 * If our direction has already been closed we just return without
	 * doing anything.
	 */
	KKASSERT(state);
	if (state->txcmd & DMSGF_DELETE)
		return;
	if ((state->txcmd & DMSGF_CREATE) == 0)
		cmd |= DMSGF_CREATE;
	if (state->txcmd & DMSGF_REPLY)
		cmd |= DMSGF_REPLY;
	cmd |= DMSGF_DELETE;

	nmsg = kdmsg_msg_alloc(state, cmd, NULL, NULL);
	nmsg->any.head.error = error;
	kdmsg_msg_write(nmsg);
}

/*
 * Reply to a message and continue our side of the transaction.
 *
 * If msg->state is non-NULL we are replying to a one-way message and this
 * function degenerates into the same as kdmsg_msg_reply().
 */
void
kdmsg_state_result(kdmsg_state_t *state, uint32_t error)
{
	kdmsg_msg_t *nmsg;
	uint32_t cmd;

	/*
	 * Return a simple result code, do NOT terminate the transaction.
	 */
	cmd = DMSG_LNK_ERROR;

	/*
	 * Check if our direction has even been initiated yet, set CREATE.
	 *
	 * Check what direction this is (command or reply direction).  Note
	 * that txcmd might not have been initiated yet.
	 *
	 * If our direction has already been closed we just return without
	 * doing anything.
	 */
	KKASSERT(state);
	if (state->txcmd & DMSGF_DELETE)
		return;
	if ((state->txcmd & DMSGF_CREATE) == 0)
		cmd |= DMSGF_CREATE;
	if (state->txcmd & DMSGF_REPLY)
		cmd |= DMSGF_REPLY;
	/* continuing transaction, do not set MSGF_DELETE */

	nmsg = kdmsg_msg_alloc(state, cmd, NULL, NULL);
	nmsg->any.head.error = error;
	kdmsg_msg_write(nmsg);
}
