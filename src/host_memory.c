/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "host_memory.h"
#include "perftest_parameters.h"


struct host_memory_ctx {
	struct memory_ctx base;
	int use_hugepages;
};


#define HUGEPAGE_ALIGN  (2*1024*1024)
#define SHMAT_ADDR (void *)(0x0UL)
#define SHMAT_FLAGS (0)
#define SHMAT_INVALID_PTR ((void *)-1)

#if !defined(__FreeBSD__)
int alloc_hugepage_region(int alignment, uint64_t size, void **addr)
{
	int huge_shmid;
	uint64_t buf_size;
	uint64_t buf_alignment = (((alignment + HUGEPAGE_ALIGN -1) / HUGEPAGE_ALIGN) * HUGEPAGE_ALIGN);
	buf_size = (((size + buf_alignment -1 ) / buf_alignment ) * buf_alignment);

	/* create hugepage shared region */
	huge_shmid = shmget(IPC_PRIVATE, buf_size, SHM_HUGETLB | IPC_CREAT | SHM_R | SHM_W);
	if (huge_shmid < 0) {
		fprintf(stderr, "Failed to allocate hugepages. Please configure hugepages\n");
		return FAILURE;
	}

	/* attach shared memory */
	*addr = (void *)shmat(huge_shmid, SHMAT_ADDR, SHMAT_FLAGS);
	if (*addr == SHMAT_INVALID_PTR) {
		fprintf(stderr, "Failed to attach shared memory region\n");
		return FAILURE;
	}

	/* Mark shmem for removal */
	if (shmctl(huge_shmid, IPC_RMID, 0) != 0) {
		fprintf(stderr, "Failed to mark shm for removal\n");
		return FAILURE;
	}

	return SUCCESS;
}
#endif

int host_memory_init(struct memory_ctx *ctx) {
	return SUCCESS;
}

int host_memory_destroy(struct memory_ctx *ctx) {
	struct host_memory_ctx *host_ctx = container_of(ctx, struct host_memory_ctx, base);

	free(host_ctx);
	return SUCCESS;
}

/* host_memory_allocate_buffer 函数: 分配主机内存缓冲区
 *
 * 这是实际分配物理内存的地方（对于标准主机内存类型）
 *
 * 参数：
 * - alignment: 内存对齐要求（通常是缓存行大小，如 64 字节）
 * - size: 要分配的字节数（由 alloc_ctx 计算得出）
 * - addr: 输出参数，返回分配的内存地址
 *
 * 分配方式：
 * 1. 如果启用 hugepages（大页内存）：
 *    - 使用 shmget() + shmat() 分配 2MB 或 1GB 大页
 *    - 好处：减少 TLB miss，提高大内存访问性能
 *    - 适合：大缓冲区的 RDMA 传输
 * 2. 否则使用标准内存：
 *    - 使用 memalign() 或 posix_memalign() 分配对齐内存
 *    - 对齐到缓存行避免 false sharing
 *
 * 分配后会清零（memset），然后这块内存会：
 * 1. 被保存到 ctx->buf[qp_index]
 * 2. 通过 ibv_reg_mr() 注册为 MR
 * 3. 变成 RDMA 硬件可以直接访问的内存
 *
 * 在 RDMA WRITE 场景中：
 * - CLIENT: 这块内存是源数据缓冲区，ibv_post_send() 会从这里读取
 * - SERVER: 这块内存是目标缓冲区，CLIENT 的 RDMA WRITE 会直接写入这里
 */
int host_memory_allocate_buffer(struct memory_ctx *ctx, int alignment, uint64_t size, int *dmabuf_fd,
				uint64_t *dmabuf_offset, void **addr, bool *can_init) {
	fprintf(stderr, "[DEBUG] host_memory_allocate_buffer: Starting memory allocation\n");
	fprintf(stderr, "[DEBUG]   - Requested size: %lu bytes (%.2f KB, %.2f MB)\n",
		size, size / 1024.0, size / (1024.0 * 1024.0));
	fprintf(stderr, "[DEBUG]   - Alignment: %d bytes\n", alignment);

#if defined(__FreeBSD__)
	/* FreeBSD: 使用 POSIX 标准的对齐内存分配 */
	fprintf(stderr, "[DEBUG]   - Using posix_memalign() on FreeBSD\n");
	posix_memalign(addr, alignment, size);
#else
	struct host_memory_ctx *host_ctx = container_of(ctx, struct host_memory_ctx, base);
	if (host_ctx->use_hugepages) {
		/* 使用大页内存（Hugepages）分配
		 * - 大页通常是 2MB 或 1GB，而不是标准的 4KB 页
		 * - 减少页表项数量，降低 TLB（Translation Lookaside Buffer）miss
		 * - 对于大型 RDMA 缓冲区性能提升明显
		 */
		fprintf(stderr, "[DEBUG]   - Using hugepages (2MB or 1GB pages)\n");
		if (alloc_hugepage_region(alignment, size, addr) != 0){
			fprintf(stderr, "[ERROR] Failed to allocate hugepage region.\n");
			return FAILURE;
		}
		fprintf(stderr, "[DEBUG]   - Hugepage allocated at: %p\n", *addr);
	} else {
		/* 标准对齐内存分配
		 * memalign() 确保内存地址按 alignment 对齐
		 * 通常 alignment = 64 字节（缓存行大小）
		 * 对齐的好处：
		 * - 避免跨缓存行访问，提高访问效率
		 * - 避免 false sharing（多核 CPU 的缓存一致性问题）
		 * - RDMA DMA 操作通常要求对齐内存
		 */
		fprintf(stderr, "[DEBUG]   - Using memalign() for standard aligned memory\n");
		*addr = memalign(alignment, size);
		fprintf(stderr, "[DEBUG]   - Memory allocated at: %p\n", *addr);
	}
#endif
	if (!*addr) {
		/* 内存分配失败 */
		fprintf(stderr, "[ERROR] Couldn't allocate work buf.\n");
		return FAILURE;
	}

	/* 将分配的内存清零
	 * - 确保初始状态一致
	 * - 避免读取未初始化的数据
	 * - 在测试中，某些场景会检查数据内容的正确性
	 */
	fprintf(stderr, "[DEBUG]   - Zeroing memory with memset()...\n");
	memset(*addr, 0, size);
	*can_init = true;
	fprintf(stderr, "[DEBUG] host_memory_allocate_buffer: Memory allocation completed successfully\n");
	return SUCCESS;
}

int host_memory_free_buffer(struct memory_ctx *ctx, int dmabuf_fd, void *addr, uint64_t size) {
	struct host_memory_ctx *host_ctx = container_of(ctx, struct host_memory_ctx, base);

	if (host_ctx->use_hugepages) {
		shmdt(addr);
	} else {
		free(addr);
	}
	return SUCCESS;
}

/* host_memory_create 函数: 创建主机内存管理上下文
 *
 * 这是 memory_create 回调的实现（对于标准主机内存类型）
 *
 * 创建流程：
 * 1. 分配 host_memory_ctx 结构体
 * 2. 设置函数指针回调：
 *    - init: 初始化函数（host_memory_init，当前为空操作）
 *    - destroy: 销毁函数（host_memory_destroy，释放上下文）
 *    - allocate_buffer: 分配缓冲区（host_memory_allocate_buffer）
 *                       这是实际调用 memalign() 的地方
 *    - free_buffer: 释放缓冲区（host_memory_free_buffer）
 *    - copy 函数：数据拷贝操作，使用标准 memcpy
 * 3. 保存 hugepages 配置
 *
 * 返回的 memory_ctx 对象会被保存到 ctx->memory
 * 后续通过 ctx->memory->allocate_buffer() 分配实际物理内存
 *
 * 调用链路：
 * 1. alloc_ctx() 调用 user_param->memory_create(user_param)
 * 2. memory_create 指向 host_memory_create（在 parser 中设置）
 * 3. host_memory_create 返回 memory_ctx 对象
 * 4. 后续调用 ctx->memory->allocate_buffer() 分配物理内存
 * 5. 物理内存地址保存到 ctx->buf[i]
 * 6. 调用 ibv_reg_mr(ctx->buf[i]) 注册为 MR
 */
struct memory_ctx *host_memory_create(struct perftest_parameters *params) {
	struct host_memory_ctx *ctx;

	ALLOCATE(ctx, struct host_memory_ctx, 1);
	ctx->base.init = host_memory_init;
	ctx->base.destroy = host_memory_destroy;
	ctx->base.allocate_buffer = host_memory_allocate_buffer;
	ctx->base.free_buffer = host_memory_free_buffer;
	ctx->base.copy_host_to_buffer = memcpy;
	ctx->base.copy_buffer_to_host = memcpy;
	ctx->base.copy_buffer_to_buffer = memcpy;
	ctx->use_hugepages = params->use_hugepages;
	return &ctx->base;
}
