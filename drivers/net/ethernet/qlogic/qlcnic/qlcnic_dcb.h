/*
 * QLogic qlcnic NIC Driver
 * Copyright (c)  2009-2013 QLogic Corporation
 *
 * See LICENSE.qlcnic for copyright and licensing details.
 */

#ifndef __QLCNIC_DCBX_H
#define __QLCNIC_DCBX_H

void qlcnic_clear_dcb_ops(struct qlcnic_adapter *);

#ifdef CONFIG_QLCNIC_DCB
int __qlcnic_register_dcb(struct qlcnic_adapter *);
#else
static inline int __qlcnic_register_dcb(struct qlcnic_adapter *adapter)
{ return 0; }
#endif

struct qlcnic_dcb_ops {
	void (*init_dcbnl_ops) (struct qlcnic_adapter *);
	void (*free) (struct qlcnic_adapter *);
	int (*attach) (struct qlcnic_adapter *);
	int (*query_hw_capability) (struct qlcnic_adapter *, char *);
	int (*get_hw_capability) (struct qlcnic_adapter *);
	void (*get_info) (struct qlcnic_adapter *);
	int (*query_cee_param) (struct qlcnic_adapter *, char *, u8);
	int (*get_cee_cfg) (struct qlcnic_adapter *);
	int (*register_aen) (struct qlcnic_adapter *, bool);
	void (*handle_aen) (struct qlcnic_adapter *, void *);
};

struct qlcnic_dcb {
	struct qlcnic_dcb_mbx_params	*param;
	struct qlcnic_adapter		*adapter;
	struct delayed_work		aen_work;
	struct workqueue_struct		*wq;
	struct qlcnic_dcb_ops		*ops;
	struct qlcnic_dcb_cfg		*cfg;
};
#endif
