/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2009 HNR Consulting.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id$
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "perftest_parameters.h"
#include "perftest_resources.h"
#include "perftest_communication.h"

/******************************************************************************
 ******************************************************************************/
int main(int argc, char *argv[])
{
	int				ret_parser, i = 0, rc;
	struct ibv_device		*ib_dev = NULL;
	struct pingpong_context		ctx;
	struct pingpong_dest		*my_dest,*rem_dest;
	struct perftest_parameters	user_param;
	struct perftest_comm		user_comm;
	struct bw_report_data		my_bw_rep, rem_bw_rep;
	int rdma_cm_flow_destroyed = 0;

	/* init default values to user's parameters */
	memset(&user_param,0,sizeof(struct perftest_parameters));
	memset(&user_comm,0,sizeof(struct perftest_comm));
	memset(&ctx,0,sizeof(struct pingpong_context));

	user_param.verb    = WRITE;
	user_param.tst     = BW;
	strncpy(user_param.version, VERSION, sizeof(user_param.version));

	/* Configure the parameters values according to user arguments or default values.
	 * 解析命令行参数，包括：
	 * -R: 使用 RDMA CM (work_rdma_cm = ON)
	 * -D: 设置测试持续时间(duration)，单位秒，同时设置 test_type = DURATION
	 */
	ret_parser = parser(&user_param,argv,argc);
	if (ret_parser) {
		if (ret_parser != VERSION_EXIT && ret_parser != HELP_EXIT)
			fprintf(stderr," Parser function exited with Error\n");
		goto return_error;
	}

	/* DEBUG: 打印关键参数 - RDMA CM 和测试持续时间
	 * machine 角色说明：
	 * - SERVER: 被动端，等待连接，提供远程内存供 WRITE 操作写入
	 * - CLIENT: 主动端，发起连接，执行 RDMA WRITE 操作到 SERVER 的内存
	 */
	fprintf(stderr, "[DEBUG] write_bw: Role=%s, work_rdma_cm=%d, test_type=%s, duration=%d seconds\n",
		user_param.machine == SERVER ? "SERVER (passive, provides remote memory)" :
		user_param.machine == CLIENT ? "CLIENT (active, performs WRITE)" : "UNCHOSEN",
		user_param.work_rdma_cm,
		user_param.test_type == DURATION ? "DURATION" : "ITERATIONS",
		user_param.duration);

	if((user_param.connection_type == DC || user_param.use_xrc) && user_param.duplex) {
		user_param.num_of_qps *= 2;
	}

	/* Finding the IB device selected (or default if none is selected). */
	ib_dev = ctx_find_dev(&user_param.ib_devname);
	if (!ib_dev) {
		fprintf(stderr," Unable to find the Infiniband/RoCE device\n");
		goto return_error;
	}

	/* Getting the relevant context from the device */
	ctx.context = ctx_open_device(ib_dev, &user_param);
	if (!ctx.context) {
		fprintf(stderr, " Couldn't get context for the device\n");
		goto free_devname;
	}

	/* Verify user parameters that require the device context,
	 * the function will print the relevent error info. */
	if (verify_params_with_device_context(ctx.context, &user_param))
	{
		fprintf(stderr, " Couldn't get context for the device\n");
		goto free_devname;
	}

	/* See if link type is valid and supported. */
	if (check_link(ctx.context,&user_param)) {
		fprintf(stderr, " Couldn't get context for the device\n");
		goto free_devname;
	}

	/* copy the relevant user parameters to the comm struct + creating rdma_cm resources. */
	if (create_comm_struct(&user_comm,&user_param)) {
		fprintf(stderr," Unable to create RDMA_CM resources\n");
		goto free_devname;
	}

	if (user_param.output == FULL_VERBOSITY && user_param.machine == SERVER) {
		printf("\n************************************\n");
		printf("* Waiting for client to connect... *\n");
		printf("************************************\n");
	}

	/* Initialize the connection and print the local data. */
	if (establish_connection(&user_comm)) {
		fprintf(stderr," Unable to init the socket connection\n");
		dealloc_comm_struct(&user_comm,&user_param);
		goto free_devname;
	}
	sleep(1);
	exchange_versions(&user_comm, &user_param);
	check_version_compatibility(&user_param);
	check_sys_data(&user_comm, &user_param);

	/* See if MTU is valid and supported. */
	if (check_mtu(ctx.context,&user_param, &user_comm)) {
		fprintf(stderr, " Couldn't get context for the device\n");
		dealloc_comm_struct(&user_comm,&user_param);
		goto free_devname;
	}

	MAIN_ALLOC(my_dest , struct pingpong_dest , user_param.num_of_qps , free_rdma_params);
	memset(my_dest, 0, sizeof(struct pingpong_dest)*user_param.num_of_qps);
	MAIN_ALLOC(rem_dest , struct pingpong_dest , user_param.num_of_qps , free_my_dest);
	memset(rem_dest, 0, sizeof(struct pingpong_dest)*user_param.num_of_qps);

	/* Allocating arrays needed for the test. */
	if(alloc_ctx(&ctx,&user_param)){
		fprintf(stderr, "Couldn't allocate context\n");
		goto free_mem;
	}

	/* Create RDMA CM resources and connect through CM. */
	if (user_param.work_rdma_cm == ON) {
		rc = create_rdma_cm_connection(&ctx, &user_param, &user_comm,
			my_dest, rem_dest);
		if (rc) {
			fprintf(stderr,
				"Failed to create RDMA CM connection with resources.\n");
			dealloc_ctx(&ctx, &user_param);
			goto free_mem;
		}
	} else {
		/* create all the basic IB resources (data buffer, PD, MR, CQ and events channel)
		 * 创建基础IB资源（SERVER 和 CLIENT 都需要）：
		 * - 分配数据缓冲区 (data buffer)
		 *   - CLIENT: 源数据缓冲区，存放要写入的数据
		 *   - SERVER: 目标内存缓冲区，接收 RDMA WRITE 的数据
		 * - 创建保护域 (Protection Domain, PD)
		 * - 注册内存区域 (Memory Region, MR)
		 *   - SERVER: 注册 MR 后会生成 rkey，通过握手传给 CLIENT
		 *   - CLIENT: 使用 SERVER 提供的 rkey 来访问远程内存
		 * - 创建完成队列 (Completion Queue, CQ)
		 *   - CLIENT: 需要 send CQ 来接收 WRITE 完成通知
		 *   - SERVER: 对于普通 WRITE，不需要 recv CQ（单边操作）
		 * - 创建事件通道 (events channel，如果使用事件模式)
		 */
		fprintf(stderr, "[DEBUG] write_bw [%s]: Creating IB resources (PD, MR, CQ)...\n",
			user_param.machine == SERVER ? "SERVER" : "CLIENT");
		if (ctx_init(&ctx, &user_param)) {
			fprintf(stderr, " Couldn't create IB resources\n");
			dealloc_ctx(&ctx, &user_param);
			goto free_mem;
		}
		fprintf(stderr, "[DEBUG] write_bw [%s]: IB resources created successfully\n",
			user_param.machine == SERVER ? "SERVER" : "CLIENT");
	}

	/* Set up the Connection. */
	if (set_up_connection(&ctx,&user_param,my_dest)) {
		fprintf(stderr," Unable to set up socket connection\n");
		goto destroy_context;
	}

	/* Print basic test information. */
	ctx_print_test_info(&user_param);

	for (i=0; i < user_param.num_of_qps; i++) {

		if (ctx_hand_shake(&user_comm,&my_dest[i],&rem_dest[i])) {
			fprintf(stderr," Failed to exchange data between server and clients\n");
			goto destroy_context;
		}
	}

	if (user_param.work_rdma_cm == OFF) {
		if (ctx_check_gid_compatibility(&my_dest[0], &rem_dest[0])) {
			fprintf(stderr,"\n Found Incompatibility issue with GID types.\n");
			fprintf(stderr," Please Try to use a different IP version.\n\n");
			goto destroy_context;
		}
	}

	if (user_param.work_rdma_cm == OFF) {
		if (ctx_connect(&ctx,rem_dest,&user_param,my_dest)) {
			fprintf(stderr," Unable to Connect the HCA's through the link\n");
			goto destroy_context;
		}
	}

	if (user_param.connection_type == DC)
	{
		/* Set up connection one more time to send qpn properly for DC */
		if (set_up_connection(&ctx, &user_param, my_dest))
		{
			fprintf(stderr," Unable to set up socket connection\n");
			goto destroy_context;
		}
	}

	/* Print this machine QP information */
	for (i=0; i < user_param.num_of_qps; i++)
		ctx_print_pingpong_data(&my_dest[i],&user_comm);

	user_comm.rdma_params->side = REMOTE;

	for (i=0; i < user_param.num_of_qps; i++) {
		if (ctx_hand_shake(&user_comm,&my_dest[i],&rem_dest[i])) {
			fprintf(stderr," Failed to exchange data between server and clients\n");
			goto destroy_context;
		}

		ctx_print_pingpong_data(&rem_dest[i],&user_comm);
	}

	if (user_param.use_event) {
		if (ibv_req_notify_cq(ctx.send_cq, 0)) {
			fprintf(stderr, " Couldn't request CQ notification\n");
			goto destroy_context;
		}
		if (ibv_req_notify_cq(ctx.recv_cq, 0)) {
			fprintf(stderr, " Couldn't request CQ notification\n");
			goto destroy_context;
		}
	}

	/* An additional handshake is required after moving qp to RTR. */
	if (ctx_hand_shake(&user_comm,&my_dest[0],&rem_dest[0])) {
		fprintf(stderr," Failed to exchange data between server and clients\n");
		goto destroy_context;
	}

	if (user_param.output == FULL_VERBOSITY) {
		if (user_param.report_per_port) {
			printf(RESULT_LINE_PER_PORT);
			printf((user_param.report_fmt == MBS ? RESULT_FMT_PER_PORT : RESULT_FMT_G_PER_PORT));
		}
		else {
			printf(RESULT_LINE);
			printf((user_param.report_fmt == MBS ? RESULT_FMT : RESULT_FMT_G));
		}

		printf((user_param.cpu_util_data.enable ? RESULT_EXT_CPU_UTIL : RESULT_EXT));
	}

	/* For half duplex write tests, server just waits for client to exit
	 *
	 * SERVER 端在 RDMA WRITE 测试中的行为：
	 * 1. 初始化阶段：创建 IB 资源，注册 MR，发送 vaddr 和 rkey 给 CLIENT
	 * 2. 测试阶段：什么都不做！
	 *    - 不需要 post receive
	 *    - 不需要 poll CQ
	 *    - 数据由 CLIENT 的 RDMA WRITE 直接写入内存
	 *    - HCA 硬件自动处理，CPU 完全无感知
	 * 3. 结束阶段：等待 CLIENT 完成测试，交换性能数据
	 *
	 * 这就是 RDMA 单边操作的优势：SERVER 端零 CPU 开销！
	 */
	if (user_param.machine == SERVER && user_param.verb == WRITE && !user_param.duplex) {

		fprintf(stderr, "[DEBUG] write_bw [SERVER]: Waiting for CLIENT to complete test...\n");
		fprintf(stderr, "[DEBUG] write_bw [SERVER]: (No RDMA operations needed on SERVER side)\n");

		if (ctx_hand_shake(&user_comm,&my_dest[0],&rem_dest[0])) {
			fprintf(stderr," Failed to exchange data between server and clients\n");
			goto free_mem;
		}

		xchg_bw_reports(&user_comm, &my_bw_rep,&rem_bw_rep,atof(user_param.rem_version));

		if (user_param.test_method != RUN_INFINITELY) {
			print_full_bw_report(&user_param, &rem_bw_rep, NULL);
		} else {
			printf(" Client closed connection\n");
		}

		if (ctx_close_connection(&user_comm,&my_dest[0],&rem_dest[0])) {
			fprintf(stderr,"Failed to close connection between server and client\n");
			goto free_mem;
		}

		if (user_param.output == FULL_VERBOSITY) {
			if (user_param.report_per_port)
				printf(RESULT_LINE_PER_PORT);
			else
				printf(RESULT_LINE);
		}

		if (user_param.work_rdma_cm == ON) {
			if (destroy_ctx(&ctx,&user_param)) {
				fprintf(stderr, "Failed to destroy resources\n");
				goto destroy_cm_context;
			}
			user_comm.rdma_params->work_rdma_cm = OFF;
			free(my_dest);
			free(rem_dest);
			free(user_param.ib_devname);
			if(destroy_ctx(user_comm.rdma_ctx, user_comm.rdma_params)) {
				free(user_comm.rdma_params);
				free(user_comm.rdma_ctx);
				return FAILURE;
			}
			free(user_comm.rdma_params);
			free(user_comm.rdma_ctx);
			return SUCCESS;
		}

		free(my_dest);
		free(rem_dest);
		free(user_param.ib_devname);
		if(destroy_ctx(&ctx, &user_param)) {
			free(user_comm.rdma_params);
			return FAILURE;
		}
		free(user_comm.rdma_params);
		return SUCCESS;
	}

	if (user_param.test_method == RUN_ALL) {

		for (i = 1; i < 24 ; ++i) {

			user_param.size = (uint64_t)1 << i;

			if (user_param.machine == CLIENT || user_param.duplex)
				ctx_set_send_wqes(&ctx,&user_param,rem_dest);

			if (user_param.verb == WRITE_IMM && !user_param.use_unsolicited_write &&
			    (user_param.machine == SERVER || user_param.duplex)) {
				if (ctx_set_recv_wqes(&ctx,&user_param)) {
					fprintf(stderr," Failed to post receive recv_wqes\n");
					goto free_mem;
				}
			}

			if (user_param.perform_warm_up) {

				if (user_param.verb == WRITE_IMM) {
					fprintf(stderr, "Warm up not supported for WRITE_IMM verb.\n");
					fprintf(stderr, "Skipping\n");
				} else if(perform_warm_up(&ctx, &user_param)) {
					fprintf(stderr, "Problems with warm up\n");
					goto free_mem;
				}
			}

			if(user_param.duplex || user_param.verb == WRITE_IMM) {
				if (ctx_hand_shake(&user_comm,&my_dest[0],&rem_dest[0])) {
					fprintf(stderr,"Failed to sync between server and client between different msg sizes\n");
					goto free_mem;
				}
			}

			if (user_param.duplex && user_param.verb == WRITE_IMM) {

				if(run_iter_bi(&ctx,&user_param)){
					fprintf(stderr," Failed to complete run_iter_bi function successfully\n");
					goto free_mem;
				}

			} else if (user_param.machine == CLIENT || user_param.verb != WRITE_IMM) {

				if(run_iter_bw(&ctx,&user_param)) {
					fprintf(stderr," Failed to complete run_iter_bw function successfully\n");
					goto free_mem;
				}

			} else if (user_param.machine == SERVER) {

				if(run_iter_bw_server(&ctx,&user_param)) {
					fprintf(stderr," Failed to complete run_iter_bw_server function successfully\n");
					goto free_mem;
				}
			}

			if (user_param.verb == WRITE_IMM || (user_param.duplex && (atof(user_param.version) >= 4.6))) {
				if (ctx_hand_shake(&user_comm,&my_dest[0],&rem_dest[0])) {
					fprintf(stderr,"Failed to sync between server and client between different msg sizes\n");
					goto free_mem;
				}
			}

			print_report_bw(&user_param,&my_bw_rep);

			if (user_param.duplex && (user_param.verb != WRITE_IMM || user_param.test_type != DURATION)) {
				xchg_bw_reports(&user_comm, &my_bw_rep,&rem_bw_rep,atof(user_param.rem_version));
				print_full_bw_report(&user_param, &my_bw_rep, &rem_bw_rep);
			}
		}

	} else if (user_param.test_method == RUN_REGULAR) {

		/* RUN_REGULAR 模式：单次测试，固定消息大小
		 *
		 * 角色分工（对于普通 RDMA WRITE）：
		 * - CLIENT (主动端):
		 *   1. 准备本地数据缓冲区
		 *   2. 配置 WQE，指定远程内存地址和 rkey
		 *   3. 执行 run_iter_bw 循环 post RDMA WRITE
		 *   4. poll send CQ 获取完成状态
		 *   5. 计算和输出性能数据
		 *
		 * - SERVER (被动端):
		 *   1. 注册内存区域，生成 rkey
		 *   2. 通过握手将 vaddr 和 rkey 发送给 CLIENT
		 *   3. 等待测试完成（无需任何 RDMA 操作）
		 *   4. 数据会自动被 CLIENT 的 WRITE 操作写入内存
		 *   5. CPU 和软件完全无感知（零拷贝、单边操作）
		 */
		fprintf(stderr, "[DEBUG] write_bw [%s]: RUN_REGULAR mode, verb=%s\n",
			user_param.machine == CLIENT ? "CLIENT" : "SERVER",
			user_param.verb == WRITE ? "WRITE" : "WRITE_IMM");

		if (user_param.machine == CLIENT || user_param.duplex) {
			/* CLIENT 端：设置发送工作请求 (Send Work Queue Entries)
			 *
			 * 配置 RDMA WRITE 操作的 WQE，包含：
			 * - 本地内存地址 (sge_list[].addr): CLIENT 本地的数据源
			 * - 本地 lkey (sge_list[].lkey): CLIENT 的 MR key
			 * - 远程内存地址 (wr.rdma.remote_addr): SERVER 提供的目标地址
			 * - 远程 rkey (wr.rdma.rkey): SERVER 提供的 MR key
			 * - 操作码 (wr.opcode): IBV_WR_RDMA_WRITE（非 immediate 模式）
			 *
			 * rem_dest[] 数组包含从 SERVER 获取的信息：
			 * - vaddr: SERVER 端内存的虚拟地址
			 * - rkey: SERVER 端 MR 注册时生成的 remote key
			 */
			fprintf(stderr, "[DEBUG] write_bw [CLIENT]: Setting up send WQEs for WRITE operations\n");
			ctx_set_send_wqes(&ctx,&user_param,rem_dest);
			fprintf(stderr, "[DEBUG] write_bw [CLIENT]: Send WQEs configured\n");
			fprintf(stderr, "[DEBUG]   - Local buffer: %p (source data from CLIENT)\n", ctx.buf[0]);
			fprintf(stderr, "[DEBUG]   - Remote addr: %p (target memory on SERVER)\n",
				(void*)rem_dest[0].vaddr);
			fprintf(stderr, "[DEBUG]   - Remote rkey: 0x%x (from SERVER's MR)\n", rem_dest[0].rkey);
		}

		if (user_param.verb == WRITE_IMM && (user_param.machine == SERVER || user_param.duplex)) {
			/* WRITE_IMM 需要接收 WQE，普通 WRITE 不需要 */
			if (ctx_set_recv_wqes(&ctx,&user_param)) {
				fprintf(stderr," Failed to post receive recv_wqes\n");
				goto free_mem;
			}
		}

		if (user_param.verb != SEND && user_param.verb != WRITE_IMM) {

			if (user_param.perform_warm_up) {
				fprintf(stderr, "[DEBUG] write_bw: Performing warm-up phase\n");
				if(perform_warm_up(&ctx, &user_param)) {
					fprintf(stderr, "Problems with warm up\n");
					goto free_mem;
				}
			}
		}

		if(user_param.duplex || user_param.verb == WRITE_IMM) {
			if (ctx_hand_shake(&user_comm,&my_dest[0],&rem_dest[0])) {
				fprintf(stderr,"Failed to sync between server and client between different msg sizes\n");
				goto free_mem;
			}
		}

		if (user_param.duplex && user_param.verb == WRITE_IMM) {

			if(run_iter_bi(&ctx,&user_param)){
				fprintf(stderr," Failed to complete run_iter_bi function successfully\n");
				goto free_mem;
			}

		} else if (user_param.machine == CLIENT || user_param.verb != WRITE_IMM) {

			/* CLIENT 端：执行带宽测试（普通 RDMA WRITE）
			 *
			 * run_iter_bw 函数执行流程：
			 * 1. 初始化定时器（DURATION 模式）或设置迭代次数
			 * 2. 主循环：
			 *    a. post RDMA WRITE 请求到 QP
			 *       - 调用 ibv_post_send()
			 *       - HCA 硬件执行 DMA，将数据写入 SERVER 的远程内存
			 *    b. poll send CQ 获取完成状态
			 *       - 调用 ibv_poll_cq(ctx->send_cq)
			 *       - 检查 wc.status 确认 WRITE 成功
			 *    c. 更新计数器和时间戳
			 * 3. 收集性能数据（带宽、消息速率、延迟等）
			 *
			 * 注意：SERVER 端在此期间完全无需操作，数据会自动到达
			 */
			fprintf(stderr, "[DEBUG] write_bw [CLIENT]: Starting bandwidth test via run_iter_bw\n");
			fprintf(stderr, "[DEBUG] write_bw [CLIENT]: Test mode = %s\n",
				user_param.test_type == DURATION ? "DURATION (time-based)" : "ITERATIONS (count-based)");
			if (user_param.test_type == DURATION) {
				fprintf(stderr, "[DEBUG] write_bw [CLIENT]: Will run for %d seconds\n",
					user_param.duration);
			} else {
				fprintf(stderr, "[DEBUG] write_bw [CLIENT]: Will run for %lu iterations\n",
					user_param.iters);
			}

			if(run_iter_bw(&ctx,&user_param)) {
				fprintf(stderr," Failed to complete run_iter_bw function successfully\n");
				goto free_mem;
			}

			fprintf(stderr, "[DEBUG] write_bw [CLIENT]: Bandwidth test completed\n");

		} else if (user_param.machine == SERVER) {

			/* SERVER 端：对于 WRITE_IMM 需要接收数据
			 * 注意：对于普通 RDMA WRITE，SERVER 不会执行到这里
			 * SERVER 在 WRITE 操作期间只是等待，数据会直接写入内存
			 */
			fprintf(stderr, "[DEBUG] write_bw [SERVER]: Running server-side receive loop for WRITE_IMM\n");
			if(run_iter_bw_server(&ctx,&user_param)) {
				fprintf(stderr," Failed to complete run_iter_bw_server function successfully\n");
				goto free_mem;
			}
		}

		print_report_bw(&user_param,&my_bw_rep);

		if (user_param.duplex && (user_param.verb != WRITE_IMM || user_param.test_type != DURATION)) {
			xchg_bw_reports(&user_comm, &my_bw_rep,&rem_bw_rep,atof(user_param.rem_version));
			print_full_bw_report(&user_param, &my_bw_rep, &rem_bw_rep);
		}

		if (user_param.report_both && user_param.duplex) {
			printf(RESULT_LINE);
			printf("\n Local results: \n");
			printf(RESULT_LINE);
			printf((user_param.report_fmt == MBS ? RESULT_FMT : RESULT_FMT_G));
			printf((user_param.cpu_util_data.enable ? RESULT_EXT_CPU_UTIL : RESULT_EXT));
			print_full_bw_report(&user_param, &my_bw_rep, NULL);
			printf(RESULT_LINE);

			printf("\n Remote results: \n");
			printf(RESULT_LINE);
			printf((user_param.report_fmt == MBS ? RESULT_FMT : RESULT_FMT_G));
			printf((user_param.cpu_util_data.enable ? RESULT_EXT_CPU_UTIL : RESULT_EXT));
			print_full_bw_report(&user_param, &rem_bw_rep, NULL);
		}
	} else if (user_param.test_method == RUN_INFINITELY) {

		if (user_param.machine == CLIENT || user_param.duplex)
			ctx_set_send_wqes(&ctx,&user_param,rem_dest);

		else if (user_param.machine == SERVER && user_param.verb == WRITE_IMM) {
			if (ctx_set_recv_wqes(&ctx,&user_param)) {
				fprintf(stderr," Failed to post receive recv_wqes\n");
				goto free_mem;
			}
		}

		if (user_param.verb == WRITE_IMM) {
			if (ctx_hand_shake(&user_comm,&my_dest[0],&rem_dest[0])) {
				fprintf(stderr,"Failed to exchange data between server and clients\n");
				goto free_mem;
			}
		}

		if (user_param.machine == CLIENT || user_param.verb == WRITE) {
			if(run_iter_bw_infinitely(&ctx,&user_param)) {
				fprintf(stderr," Error occurred while running infinitely! aborting ...\n");
				goto free_mem;
			}
		} else if (user_param.machine == SERVER && user_param.verb == WRITE_IMM) {
			if(run_iter_bw_infinitely_server(&ctx,&user_param)) {
				fprintf(stderr," Error occurred while running infinitely on server! aborting ...\n");
				goto free_mem;
			}
		}
	}

	if (user_param.output == FULL_VERBOSITY) {
		if (user_param.report_per_port)
			printf(RESULT_LINE_PER_PORT);
		else
			printf(RESULT_LINE);
	}

	/* For half duplex write tests, server just waits for client to exit */
	if (user_param.machine == CLIENT && user_param.verb == WRITE && !user_param.duplex) {
		if (ctx_hand_shake(&user_comm,&my_dest[0],&rem_dest[0])) {
			fprintf(stderr," Failed to exchange data between server and clients\n");
			goto free_mem;
		}

		xchg_bw_reports(&user_comm, &my_bw_rep,&rem_bw_rep,atof(user_param.rem_version));
	}

	/* Closing connection. */
	if (ctx_close_connection(&user_comm,&my_dest[0],&rem_dest[0])) {
		fprintf(stderr,"Failed to close connection between server and client\n");
		goto free_mem;
	}

	if (!user_param.is_bw_limit_passed && (user_param.is_limit_bw == ON ) ) {
		fprintf(stderr,"Error: BW result is below bw limit\n");
		goto destroy_context;
	}

	if (!user_param.is_msgrate_limit_passed && (user_param.is_limit_bw == ON )) {
		fprintf(stderr,"Error: Msg rate  is below msg_rate limit\n");
		goto destroy_context;
	}
	if (user_param.work_rdma_cm == ON) {
		if (destroy_ctx(&ctx,&user_param)) {
			fprintf(stderr, "Failed to destroy resources\n");
			goto destroy_cm_context;
		}

		user_comm.rdma_params->work_rdma_cm = OFF;
		free(rem_dest);
		free(my_dest);
		free(user_param.ib_devname);
		if(destroy_ctx(user_comm.rdma_ctx, user_comm.rdma_params)) {
			free(user_comm.rdma_params);
			free(user_comm.rdma_ctx);
			return FAILURE;
		}
		free(user_comm.rdma_params);
		free(user_comm.rdma_ctx);
		return SUCCESS;
	}

	free(rem_dest);
	free(my_dest);
	free(user_param.ib_devname);
	if(destroy_ctx(&ctx, &user_param)){
		free(user_comm.rdma_params);
		return FAILURE;
	}
	free(user_comm.rdma_params);
	return SUCCESS;

destroy_context:
	if (destroy_ctx(&ctx,&user_param))
		fprintf(stderr, "Failed to destroy resources\n");
destroy_cm_context:
	if (user_param.work_rdma_cm == ON) {
		rdma_cm_flow_destroyed = 1;
		user_comm.rdma_params->work_rdma_cm = OFF;
		destroy_ctx(user_comm.rdma_ctx,user_comm.rdma_params);
	}
free_mem:
	free(rem_dest);
free_my_dest:
	free(my_dest);
free_rdma_params:
	if (user_param.use_rdma_cm == ON && rdma_cm_flow_destroyed == 0)
		dealloc_comm_struct(&user_comm, &user_param);

	else {
		if(user_param.use_rdma_cm == ON)
			free(user_comm.rdma_ctx);
		free(user_comm.rdma_params);
	}
free_devname:
	free(user_param.ib_devname);
return_error:
	//coverity[leaked_storage]
	return FAILURE;
}
