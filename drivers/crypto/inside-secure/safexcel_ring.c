// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017 Marvell
 *
 * Antoine Tenart <antoine.tenart@free-electrons.com>
 */

#include <linux/dma-mapping.h>
#include <linux/spinlock.h>

#include "safexcel.h"

int safexcel_init_ring_descriptors(struct safexcel_crypto_priv *priv,
				   struct safexcel_desc_ring *cdr,
				   struct safexcel_desc_ring *rdr)
{
	int i;
	struct safexcel_command_desc *cdesc;
	dma_addr_t atok;

	/* Actual command descriptor ring */
	cdr->offset = priv->config.cd_offset;
	cdr->base = dmam_alloc_coherent(priv->dev,
					cdr->offset * EIP197_DEFAULT_RING_SIZE,
					&cdr->base_dma, GFP_KERNEL);
	if (!cdr->base)
		return -ENOMEM;
	cdr->write = cdr->base;
	cdr->base_end = cdr->base + cdr->offset * (EIP197_DEFAULT_RING_SIZE - 1);
	cdr->read = cdr->base;

	/* Command descriptor shadow ring for storing additional token data */
	cdr->shoffset = priv->config.cdsh_offset;
	cdr->shbase = dmam_alloc_coherent(priv->dev,
					  cdr->shoffset *
					  EIP197_DEFAULT_RING_SIZE,
					  &cdr->shbase_dma, GFP_KERNEL);
	if (!cdr->shbase)
		return -ENOMEM;
	cdr->shwrite = cdr->shbase;
	cdr->shbase_end = cdr->shbase + cdr->shoffset *
					(EIP197_DEFAULT_RING_SIZE - 1);

	/*
	 * Populate command descriptors with physical pointers to shadow descs.
	 * Note that we only need to do this once if we don't overwrite them.
	 */
	cdesc = cdr->base;
	atok = cdr->shbase_dma;
	for (i = 0; i < EIP197_DEFAULT_RING_SIZE; i++) {
		cdesc->atok_lo = lower_32_bits(atok);
		cdesc->atok_hi = upper_32_bits(atok);
		cdesc = (void *)cdesc + cdr->offset;
		atok += cdr->shoffset;
	}

	rdr->offset = priv->config.rd_offset;
	/* Use shoffset for result token offset here */
	rdr->shoffset = priv->config.res_offset;
	/* rd_offset is an integer power of 2, get that power here */
	rdr->offsshft = __fls(priv->config.rd_offset);
	rdr->base = dmam_alloc_coherent(priv->dev,
					rdr->offset * EIP197_DEFAULT_RING_SIZE,
					&rdr->base_dma, GFP_KERNEL);
	if (!rdr->base)
		return -ENOMEM;
	rdr->write = rdr->base;
	rdr->base_end = rdr->base + rdr->offset  * (EIP197_DEFAULT_RING_SIZE - 1);
	rdr->read = rdr->base;

	return 0;
}

static inline void *safexcel_ring_next_cwptr(struct safexcel_desc_ring *ring,
					     struct safexcel_token **atoken)
{
	void *ptr = ring->write;

	if ((ptr == ring->read - ring->offset) ||
	    (ring->read == ring->base && ptr == ring->base_end))
		return ERR_PTR(-ENOMEM);

	/* Return shadow ring ptr to atoken as well */
	*atoken = ring->shwrite;

	if (ptr == ring->base_end) {
		ring->write = ring->base;
		ring->shwrite = ring->shbase;
	} else {
		ring->write = ptr + ring->offset;
		ring->shwrite += ring->shoffset;
	}

	return ptr;
}

static inline void *safexcel_ring_next_rwptr(struct safexcel_desc_ring *ring,
					     struct result_data_desc **rtoken)
{
	void *ptr = ring->write;

	if ((ptr == ring->read - ring->offset) ||
	    (ring->read == ring->base && ptr == ring->base_end))
		return ERR_PTR(-ENOMEM);

	/* Result token at relative offset shoffset */
	*rtoken = ptr + ring->shoffset;

	if (ptr == ring->base_end)
		ring->write = ring->base;
	else
		ring->write = ptr + ring->offset;

	return ptr;
}

static inline void *safexcel_ring_next_rptr(struct safexcel_desc_ring *ring)
{
	void *ptr = ring->read;

	if (ring->write == ptr)
		return ERR_PTR(-ENOENT);

	if (ptr == ring->base_end)
		ring->read = ring->base;
	else
		ring->read = ptr + ring->offset;

	return ptr;
}

void *safexcel_rdr_next_rptr(struct safexcel_desc_ring *ring)
{
	void *ptr = ring->read;
	void *nxt = ptr + ring->offset;
	u32 *own = nxt - 4; /* Last dword written */
	int cnt, ownok = *own == EIP197_OWNERSHIP_MAGIC;

have_rdesc:
	if (likely(ownok && ptr != ring->base_end)) {
		ring->read = nxt;
		/* Clear the ownership word to avoid biting our tail later! */
		*own = ~EIP197_OWNERSHIP_MAGIC;
		return ptr;
	}
	if (ownok) {
		/* Ownership word there, but need to wrap the read pointer */
		ring->read = ring->base;
		/* Clear the ownership word to avoid biting our tail later! */
		*own = ~EIP197_OWNERSHIP_MAGIC;
		return ptr;
	}

	/* If the ownership word is not there yet, then wait for it a bit */
	cnt = EIP197_OWN_POLL_COUNT;

	/* Poll ring for ownership word */
	do {
		if (likely(*own == EIP197_OWNERSHIP_MAGIC))
			goto have_rdesc;
		cpu_relax();
	} while (--cnt);

	/* If polling failed then return a 'try again' error code */
	return ERR_PTR(-EAGAIN);
}

/* Verify if next full packet is available already, using ownership words */
int safexcel_rdr_scan_next(struct safexcel_desc_ring *ring)
{
	struct safexcel_result_desc *rdesc;
	u32 *own = ring->read + ring->offset - 4;
	int pktcnt = 0;

	rdesc = ring->read;
	while (*own == EIP197_OWNERSHIP_MAGIC) {
		pktcnt += rdesc->last_seg;

		/* Move to next desc in ring, wrapping as required */
		if (unlikely((void *)rdesc == ring->base_end)) {
			rdesc = ring->base;
			own   = ring->base + ring->offset - 4;
		} else {
			rdesc = (void *)own + 4;
			own   = (void *)own + ring->offset;
		}
	}
	return pktcnt;
}

void safexcel_complete(struct safexcel_crypto_priv *priv, int ring)
{
	struct safexcel_command_desc *cdesc;

	/* Acknowledge the command descriptors */
	do {
		cdesc = safexcel_ring_next_rptr(&priv->ring[ring].cdr);
		if (IS_ERR(cdesc)) {
			dev_err(priv->dev,
				"Could not retrieve the command descriptor\n");
			return;
		}
	} while (!cdesc->last_seg);
}

void safexcel_ring_rollback_wptr(struct safexcel_desc_ring *ring)
{
	void *ptr = ring->write;

	if (unlikely(ptr == ring->read))
		return;

	if (unlikely(ptr == ring->base)) {
		ring->write = ring->base_end;
		ring->shwrite = ring->shbase_end;
	} else {
		ring->write = ptr - ring->offset;
		ring->shwrite -= ring->shoffset;
	}
}

struct safexcel_command_desc *safexcel_add_cdesc(struct safexcel_desc_ring *ring,
						 bool first, bool last,
						 dma_addr_t data, u32 data_len,
						 u32 full_data_len,
						 dma_addr_t context,
						 struct safexcel_token **atoken)
{
	struct safexcel_command_desc *cdesc;
	struct safexcel_token *atoktmp;

	cdesc = safexcel_ring_next_cwptr(ring, &atoktmp);
	if (IS_ERR(cdesc))
		return cdesc;

	/* build_desc(*desc, partsize, first, last, extrasize, data) */
	build_desc(cdesc, data_len, first, last, 0, data);

	if (first) {
		/*
		 * Note that the length here MUST be >0 or else the EIP(1)97
		 * may hang. Newer EIP197 firmware actually incorporates this
		 * fix already, but that doesn't help the EIP97 and we may
		 * also be running older firmware.
		 */
		/* build_tokhdr(*tokhdr, packet_length, options, type, ctxt) */
		build_tokhdr(&cdesc->control_data, full_data_len ?: 1,
			     EIP197_OPTION_MAGIC_VALUE |
			     EIP197_OPTION_64BIT_CTX |
			     EIP197_OPTION_CTX_CTRL_IN_CMD |
			     EIP197_OPTION_RC_AUTO,
			     EIP197_TYPE_BCLA, context);
		*atoken = atoktmp;
	}

	return cdesc;
}

struct safexcel_result_desc *safexcel_add_rdesc(struct safexcel_desc_ring *ring,
						bool first, bool last,
						dma_addr_t data, u32 len)
{
	struct safexcel_result_desc *rdesc;
	struct result_data_desc *rtoken;

	rdesc = safexcel_ring_next_rwptr(ring, &rtoken);
	if (IS_ERR(rdesc))
		return rdesc;

	/* build_desc(*desc, partsize, first, last, extrasize, data) */
	build_desc(rdesc, len, first, last, EIP197_RD64_RESULT_SIZE, data);

	/* Clear length & error code in result token */
	rtoken->packet_length = 0;
	rtoken->error_code = 0;

	return rdesc;
}
