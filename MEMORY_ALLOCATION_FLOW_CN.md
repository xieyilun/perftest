# RDMA 内存分配流程详解

本文档详细说明 perftest 中内存分配的完整流程，从用户参数到实际物理内存的分配和注册。

## 目录
1. [内存分配概览](#内存分配概览)
2. [完整调用链路](#完整调用链路)
3. [关键函数详解](#关键函数详解)
4. [CLIENT vs SERVER 内存使用](#client-vs-server-内存使用)
5. [内存到 MR 的转换](#内存到-mr-的转换)

---

## 内存分配概览

### 为什么需要分配内存？

在 RDMA WRITE 测试中，需要两个角色的内存缓冲区：

- **CLIENT（主动端）**：
  - 需要**源数据缓冲区**，存放要通过 RDMA WRITE 发送的数据
  - 这块内存会被 `ibv_post_send()` 读取，通过 DMA 传输到 SERVER

- **SERVER（被动端）**：
  - 需要**目标内存缓冲区**，接收 CLIENT 的 RDMA WRITE
  - 这块内存会被 CLIENT 的 RDMA 操作直接写入
  - **关键**：SERVER 的 CPU 完全不参与这个过程（零拷贝）

### 内存分配的三个层次

```
1. 指针数组分配     ctx->buf = malloc(sizeof(void*) * num_qps)
   └─> 只分配指针，不分配实际内存

2. 物理内存分配     ctx->buf[i] = memalign(alignment, size)
   └─> 分配实际的物理内存缓冲区

3. RDMA 注册        ctx->mr[i] = ibv_reg_mr(pd, ctx->buf[i], size, flags)
   └─> 将内存注册到 RDMA 硬件，使其可被 DMA 访问
```

---

## 完整调用链路

### 主调用链

```
write_bw.c:main()
  |
  ├─> parser()  [perftest_parameters.c]
  |   └─> 设置 user_param->memory_create = host_memory_create
  |       (根据 memory_type 参数选择不同的 memory_create 函数)
  |
  ├─> alloc_ctx()  [perftest_resources.c, line 1169]
  |   |
  |   ├─> 【第1层】分配缓冲区指针数组
  |   |   ALLOC(ctx->buf, void*, user_param->num_of_qps);  [line 1225]
  |   |   └─> ctx->buf[0], ctx->buf[1], ... 现在只是指针，还未指向实际内存
  |   |
  |   ├─> 【第2层】计算缓冲区大小
  |   |   ctx->buff_size = INC(BUFF_SIZE(size, cycle_buffer),
  |   |                         cache_line_size) * 2 * num_qps_factor * flows;
  |   |   [line 1300-1301]
  |   |   |
  |   |   └─> 计算公式说明：
  |   |       - BUFF_SIZE: 取 max(size, cycle_buffer)
  |   |       - INC: 向上对齐到缓存行大小（通常 64 字节）
  |   |       - * 2: 发送缓冲区 + 接收缓冲区
  |   |       - * num_qps_factor: QP 数量因子
  |   |       - * flows: 流数量
  |   |
  |   └─> 【第3层】创建内存管理上下文
  |       ctx->memory = user_param->memory_create(user_param);  [line 1339]
  |       |
  |       └─> 调用 host_memory_create()  [host_memory.c, line 178]
  |           |
  |           ├─> 分配 host_memory_ctx 结构体
  |           ├─> 设置回调函数指针：
  |           |   - allocate_buffer = host_memory_allocate_buffer
  |           |   - free_buffer = host_memory_free_buffer
  |           |   - copy 函数 = memcpy
  |           └─> 返回 memory_ctx 对象
  |
  ├─> ctx_init()  [perftest_resources.c, line 2354]
  |   |
  |   ├─> 分配 Protection Domain (PD)
  |   |   ctx->pd = ibv_alloc_pd(ctx->context);  [line 2403]
  |   |
  |   └─> create_single_mr()  [line 2548]
  |       |
  |       └─> 【第4层】实际分配物理内存
  |           ctx->memory->allocate_buffer(ctx->memory, alignment, size,
  |                                         &dmabuf_fd, &dmabuf_offset,
  |                                         &ctx->buf[qp_index], &can_init);
  |           |
  |           └─> 调用 host_memory_allocate_buffer()  [host_memory.c, line 96]
  |               |
  |               ├─> if (use_hugepages) {
  |               |       alloc_hugepage_region();  // 2MB 或 1GB 大页
  |               |   } else {
  |               |       ctx->buf[i] = memalign(alignment, size);  // 标准对齐内存
  |               |   }
  |               |
  |               ├─> memset(ctx->buf[i], 0, size);  // 清零
  |               └─> return SUCCESS;
  |
  └─> 【第5层】注册为 Memory Region (MR)
      ctx->mr[i] = register_mr(ctx, user_param, i, flags, ...);
      [perftest_resources.c, line 1936]
      |
      └─> ibv_reg_mr(ctx->pd, ctx->buf[i], ctx->buff_size, flags);
          |
          └─> 返回 ibv_mr 结构体，包含：
              - lkey: 本地访问密钥
              - rkey: 远程访问密钥（SERVER 的 rkey 会发送给 CLIENT）
```

---

## 关键函数详解

### 1. alloc_ctx() - 内存分配总入口

**位置**: `perftest_resources.c:1169`

**作用**:
- 分配测试所需的所有资源（指针数组、时间戳、计数器等）
- 计算缓冲区大小
- 调用 memory_create 创建内存管理上下文

**关键代码**:
```c
/* 分配缓冲区指针数组 */
ALLOC(ctx->buf, void*, user_param->num_of_qps);  // line 1225

/* 计算缓冲区大小 */
ctx->buff_size = INC(BUFF_SIZE(ctx->size, ctx->cycle_buffer),
                     ctx->cache_line_size) * 2 * num_of_qps_factor * user_param->flows;
// line 1300-1301

/* 创建内存管理上下文 */
ctx->memory = user_param->memory_create(user_param);  // line 1339
```

**示例（-s 64K）**:
```
user_param->size = 65536 字节 (64KB)
cache_line_size = 64 字节
num_of_qps = 1
flows = 1

计算过程：
1. BUFF_SIZE(65536, 0) = 65536
2. INC(65536, 64) = 65536 (已对齐)
3. 65536 * 2 = 131072 (发送 + 接收)
4. 131072 * 1 * 1 = 131072 字节

结果: ctx->buff_size = 131072 字节 (128 KB)
```

### 2. host_memory_create() - 创建内存上下文

**位置**: `host_memory.c:178`

**作用**:
- 创建 host_memory_ctx 结构体
- 设置函数指针回调（allocate_buffer, free_buffer, copy 等）
- 返回 memory_ctx 对象供后续使用

**关键代码**:
```c
ALLOCATE(ctx, struct host_memory_ctx, 1);
ctx->base.allocate_buffer = host_memory_allocate_buffer;  // 设置分配函数
ctx->base.free_buffer = host_memory_free_buffer;          // 设置释放函数
ctx->base.copy_host_to_buffer = memcpy;                   // 设置拷贝函数
ctx->use_hugepages = params->use_hugepages;
return &ctx->base;
```

### 3. host_memory_allocate_buffer() - 实际分配内存

**位置**: `host_memory.c:96`

**作用**:
- 实际调用 memalign() 或 hugepages API 分配物理内存
- 清零内存内容
- 返回内存地址

**关键代码**:
```c
if (host_ctx->use_hugepages) {
    /* 大页内存：2MB 或 1GB 页 */
    alloc_hugepage_region(alignment, size, addr);
} else {
    /* 标准对齐内存：按 64 字节对齐 */
    *addr = memalign(alignment, size);
}

/* 清零内存 */
memset(*addr, 0, size);
```

**内存对齐的好处**:
- 避免跨缓存行访问，提高 CPU 访问效率
- 避免 false sharing（多核 CPU 缓存一致性问题）
- RDMA DMA 操作通常要求对齐内存

### 4. register_mr() - 注册为 Memory Region

**位置**: `perftest_resources.c:1936`

**作用**:
- 调用 `ibv_reg_mr()` 将内存注册到 RDMA 硬件
- 获取 lkey 和 rkey
- 使内存可被 RDMA DMA 访问

**关键代码**:
```c
return ibv_reg_mr(ctx->pd, ctx->buf[qp_index], ctx->buff_size, flags);
```

**flags 参数**:
- `IBV_ACCESS_LOCAL_WRITE`: 本地写权限
- `IBV_ACCESS_REMOTE_WRITE`: 远程写权限（SERVER 需要，供 CLIENT RDMA WRITE）
- `IBV_ACCESS_REMOTE_READ`: 远程读权限

---

## CLIENT vs SERVER 内存使用

### CLIENT（主动端）

```
1. 内存分配
   ├─> alloc_ctx() 分配 131072 字节（128KB，假设 -s 64K）
   ├─> host_memory_allocate_buffer() 实际分配物理内存
   └─> ctx->buf[0] = 0x7f1234567000 (示例地址)

2. MR 注册
   ├─> register_mr() 调用 ibv_reg_mr()
   ├─> flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ
   └─> ctx->mr[0] = {
           lkey: 0xabcd1234,  // CLIENT 本地使用
           rkey: 0xabcd1234   // (CLIENT 通常不需要 remote 权限)
       }

3. 数据使用
   ├─> 测试开始前：填充 ctx->buf[0] 的数据（如果需要）
   ├─> 配置 WQE：
   |   - sge_list.addr = ctx->buf[0]  // 本地缓冲区地址
   |   - sge_list.lkey = ctx->mr[0]->lkey  // 本地访问密钥
   |   - wr.rdma.remote_addr = rem_dest[0].vaddr  // SERVER 的地址
   |   - wr.rdma.rkey = rem_dest[0].rkey  // SERVER 的 rkey
   |
   └─> ibv_post_send() 从 ctx->buf[0] 读取数据，DMA 到 SERVER

4. 内存角色
   - 源数据缓冲区（Source Buffer）
   - 被 RDMA 硬件读取（DMA Read）
   - CPU 参与：需要 post_send 和 poll_cq
```

### SERVER（被动端）

```
1. 内存分配
   ├─> alloc_ctx() 分配 131072 字节（128KB，假设 -s 64K）
   ├─> host_memory_allocate_buffer() 实际分配物理内存
   └─> ctx->buf[0] = 0x7f9876543000 (示例地址)

2. MR 注册
   ├─> register_mr() 调用 ibv_reg_mr()
   ├─> flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE  // 关键！
   └─> ctx->mr[0] = {
           lkey: 0x5678efab,
           rkey: 0x5678efab  // 这个 rkey 需要发送给 CLIENT！
       }

3. 参数交换
   ├─> my_dest[0].vaddr = ctx->buf[0]  // 0x7f9876543000
   ├─> my_dest[0].rkey = ctx->mr[0]->rkey  // 0x5678efab
   └─> ctx_hand_shake() 发送给 CLIENT
       └─> CLIENT 收到 rem_dest[0].vaddr 和 rem_dest[0].rkey

4. 测试阶段
   ├─> SERVER 什么都不做！
   ├─> 不需要 post receive
   ├─> 不需要 poll CQ
   ├─> CLIENT 的 RDMA WRITE 直接写入 ctx->buf[0]
   └─> RDMA 硬件自动 DMA 写入，CPU 无感知

5. 内存角色
   - 目标内存缓冲区（Target Buffer）
   - 被 RDMA 硬件写入（DMA Write）
   - CPU 参与：零！（这就是 RDMA 的优势）
```

### 对比表

| 特性 | CLIENT | SERVER |
|------|--------|--------|
| **内存分配大小** | 131072 字节 (128KB) | 131072 字节 (128KB) |
| **MR flags** | LOCAL_WRITE | LOCAL_WRITE + REMOTE_WRITE |
| **rkey 用途** | 接收 SERVER 的 rkey | 发送给 CLIENT |
| **vaddr 用途** | 接收 SERVER 的 vaddr | 发送给 CLIENT |
| **内存角色** | 源数据缓冲区 | 目标内存缓冲区 |
| **CPU 参与** | 高（post_send + poll_cq）| 零（单边操作）|
| **测试阶段操作** | 循环 post WRITE + poll CQ | 等待（无操作）|

---

## 内存到 MR 的转换

### 为什么需要 MR（Memory Region）？

普通内存是虚拟地址，CPU 通过 MMU 和页表访问。RDMA 硬件需要**直接访问物理内存**，因此必须：

1. **固定（Pin）内存页**：防止操作系统将内存页换出（swap out）
2. **获取物理地址映射**：RDMA 硬件需要物理地址进行 DMA
3. **设置访问权限**：通过 lkey 和 rkey 控制访问

### ibv_reg_mr() 做了什么？

```c
struct ibv_mr *ibv_reg_mr(
    struct ibv_pd *pd,       // Protection Domain（隔离容器）
    void *addr,              // 虚拟内存地址（ctx->buf[i]）
    size_t length,           // 内存大小
    int access_flags         // 访问权限
);
```

**内部操作**:
1. 锁定内存页（mlock），防止被换出
2. 建立虚拟地址到物理地址的映射表
3. 将映射信息注册到 RDMA 网卡
4. 生成 lkey 和 rkey（内存访问密钥）
5. 返回 ibv_mr 结构体

**返回的 ibv_mr**:
```c
struct ibv_mr {
    struct ibv_context *context;  // 设备上下文
    struct ibv_pd *pd;            // Protection Domain
    void *addr;                   // 内存起始地址
    size_t length;                // 内存大小
    uint32_t lkey;                // 本地访问密钥
    uint32_t rkey;                // 远程访问密钥
};
```

### lkey vs rkey

| 密钥 | 用途 | 使用场景 |
|------|------|----------|
| **lkey** | 本地操作密钥 | 本地 RDMA 操作（SEND, RECV） |
| **rkey** | 远程操作密钥 | 远程 RDMA 操作（WRITE, READ） |

**在 RDMA WRITE 中**:
- **CLIENT**:
  - 使用自己的 lkey 访问本地缓冲区（读取源数据）
  - 使用 SERVER 的 rkey 访问 SERVER 的远程内存（写入目标）

- **SERVER**:
  - 提供 rkey 给 CLIENT
  - 自己不使用 rkey（单边操作，SERVER 不参与）

### MR 注册流程图

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. 分配内存                                                       │
│    ctx->buf[0] = memalign(64, 131072)                           │
│    ├─> 虚拟地址: 0x7f1234567000                                  │
│    └─> 物理地址: 由操作系统管理（多个物理页）                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. 注册为 MR                                                      │
│    ctx->mr[0] = ibv_reg_mr(pd, ctx->buf[0], 131072, flags)      │
│    ├─> mlock() 锁定内存页                                        │
│    ├─> 建立虚拟地址 → 物理地址映射                                │
│    ├─> 注册到 RDMA 网卡                                           │
│    └─> 生成 lkey=0xabcd1234, rkey=0xabcd1234                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. RDMA 硬件可访问                                                │
│    - RDMA 网卡可以通过 DMA 直接访问物理内存                        │
│    - 不需要 CPU 参与                                              │
│    - 绕过内核和操作系统                                            │
│    - 零拷贝（Zero-Copy）                                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 完整示例：write_bw -R -D 60 -s 64K

### CLIENT 端内存分配流程

```bash
$ ./write_bw -R -D 60 -s 64K <server_ip>
```

```
[DEBUG] parser: -s 64K parsed, size=65536 bytes
[DEBUG] parser: memory_create set to host_memory_create

=== alloc_ctx() 开始 ===
[DEBUG] alloc_ctx [CLIENT]: Calculating buffer size...
[DEBUG]   - Message size (-s): 65536 bytes
[DEBUG]   - Cache line size: 64 bytes
[DEBUG]   - Number of QPs: 1
[DEBUG]   - Calculated total buffer size: 131072 bytes (128.00 KB)

[DEBUG] alloc_ctx [CLIENT]: Allocating physical memory via memory_create callback...
[DEBUG]   - Memory type: HOST

=== host_memory_create() ===
[DEBUG] Creating host_memory_ctx
[DEBUG] Setting allocate_buffer = host_memory_allocate_buffer

=== host_memory_allocate_buffer() ===
[DEBUG] Allocating 131072 bytes aligned to 64 bytes
[DEBUG] Using memalign() for standard memory
[DEBUG] Memory allocated at address: 0x7f1234567000
[DEBUG] Zeroing memory with memset()

[DEBUG] alloc_ctx [CLIENT]: Memory allocation completed successfully
[DEBUG]   - Total allocated: 131072 bytes (128.00 KB, 0.12 MB)

=== ctx_init() - 创建 PD 和 CQ ===
[DEBUG] ctx_init [CLIENT]: Allocating Protection Domain (PD)...
[DEBUG] PD allocated successfully

=== create_single_mr() - 注册 MR ===
[DEBUG] register_memory_region [CLIENT]: Starting MR registration
[DEBUG] register_mr [CLIENT]: Registering MR with ibv_reg_mr()
[DEBUG] register_mr: addr=0x7f1234567000, size=131072, flags=0x7
[DEBUG] MR registered: lkey=0xabcd1234, rkey=0xabcd1234

=== 配置 WQE ===
[DEBUG] ctx_set_send_reg_wqes [CLIENT]: Configuring WQE #0
[DEBUG]   - Local buffer: 0x7f1234567000 (source data from CLIENT)
[DEBUG]   - Local lkey: 0xabcd1234
[DEBUG]   - Remote addr: 0x7f9876543000 (target memory on SERVER)
[DEBUG]   - Remote rkey: 0x5678efab (from SERVER's MR)

=== 开始测试 ===
[DEBUG] run_iter_bw [CLIENT]: Entering main loop
[DEBUG] CLIENT posting RDMA WRITE #0
  - 从 ctx->buf[0] (0x7f1234567000) 读取 65536 字节
  - DMA 传输到 SERVER 的 0x7f9876543000
  - 使用 SERVER 的 rkey: 0x5678efab
```

### SERVER 端内存分配流程

```bash
$ ./write_bw -R -D 60 -s 64K
```

```
[DEBUG] parser: -s 64K parsed, size=65536 bytes

=== alloc_ctx() 开始 ===
[DEBUG] alloc_ctx [SERVER]: Calculating buffer size...
[DEBUG]   - Message size (-s): 65536 bytes
[DEBUG]   - Cache line size: 64 bytes
[DEBUG]   - Number of QPs: 1
[DEBUG]   - Calculated total buffer size: 131072 bytes (128.00 KB)

[DEBUG] alloc_ctx [SERVER]: Allocating physical memory via memory_create callback...
[DEBUG]   - Memory type: HOST

=== host_memory_allocate_buffer() ===
[DEBUG] Memory allocated at address: 0x7f9876543000

[DEBUG] alloc_ctx [SERVER]: Memory allocation completed successfully

=== register_mr() - 注册 MR（带 REMOTE_WRITE 权限）===
[DEBUG] register_mr [SERVER]: Registering MR with ibv_reg_mr()
[DEBUG] register_mr: addr=0x7f9876543000, size=131072, flags=0xF
[DEBUG]   - flags includes: IBV_ACCESS_REMOTE_WRITE (允许 CLIENT 写入)
[DEBUG] MR registered: lkey=0x5678efab, rkey=0x5678efab

=== 参数交换 ===
[DEBUG] Sending to CLIENT:
  - vaddr: 0x7f9876543000
  - rkey: 0x5678efab

=== 测试阶段 ===
[DEBUG] write_bw [SERVER]: Waiting for CLIENT to complete test...
[DEBUG] write_bw [SERVER]: (No RDMA operations needed on SERVER side)

(SERVER 等待 60 秒，CPU 空闲，内存被 CLIENT 的 RDMA WRITE 直接写入)
```

---

## 总结

### 内存分配的关键点

1. **三层分配结构**：
   - 指针数组分配（ctx->buf）
   - 物理内存分配（memalign/hugepages）
   - RDMA 注册（ibv_reg_mr）

2. **CLIENT 和 SERVER 的区别**：
   - CLIENT: 源数据缓冲区，CPU 密集
   - SERVER: 目标内存缓冲区，CPU 零占用

3. **MR 的作用**：
   - 固定内存页，防止换出
   - 建立虚拟地址到物理地址映射
   - 生成 lkey 和 rkey 控制访问权限

4. **rkey 的传递**：
   - SERVER 注册 MR 时生成 rkey
   - 通过 ctx_hand_shake() 发送给 CLIENT
   - CLIENT 在 WQE 中使用 SERVER 的 rkey

5. **单边操作的优势**：
   - SERVER 不需要 post receive
   - SERVER 不需要 poll CQ
   - SERVER CPU 零占用
   - 数据直接 DMA 到目标内存

### 调用顺序总结

```
1. parser() 设置 memory_create = host_memory_create
2. alloc_ctx() 分配指针数组 + 计算大小 + 创建 memory_ctx
3. host_memory_create() 返回 memory_ctx 对象
4. ctx_init() 分配 PD
5. create_single_mr() → host_memory_allocate_buffer() 分配物理内存
6. register_mr() → ibv_reg_mr() 注册为 MR
7. ctx_hand_shake() 交换 vaddr 和 rkey
8. ctx_set_send_wqes() 配置 WQE（使用 remote_addr 和 rkey）
9. run_iter_bw() 执行测试（CLIENT post WRITE，SERVER 等待）
```
