# RDMA WRITE 带宽测试代码流程说明

## 概述

本文档详细说明 perftest 工具中 `write_bw` 程序的执行流程，重点关注：
- `-R` 参数：使用 RDMA CM 进行连接管理
- `-D 60` 参数：持续测试 60 秒（DURATION 模式）
- 非 immediate 模式的 RDMA WRITE 操作

## 命令行参数解析

### 关键参数

#### `-R`: RDMA CM 模式
- **位置**: `perftest_parameters.c:3016`
- **作用**: 设置 `user_param->work_rdma_cm = ON`
- **说明**:
  - 启用 RDMA CM (Connection Manager) 进行连接建立
  - RDMA CM 提供类似 socket 的高层连接接口
  - 自动处理 QP 状态转换 (INIT → RTR → RTS)
  - 使用 `rdma_create_id`, `rdma_resolve_addr`, `rdma_resolve_route` 等 API

#### `-D 60`: 持续时间模式
- **位置**: `perftest_parameters.c:2989`
- **作用**:
  - 设置 `user_param->duration = 60` 秒
  - 设置 `user_param->test_type = DURATION`
- **说明**:
  - DURATION 模式下测试运行指定时间而非固定迭代次数
  - 使用 SIGALRM 信号控制测试阶段
  - 测试分为三个阶段：
    1. **START_STATE**: 预热阶段 (margin 秒)
    2. **SAMPLE_STATE**: 数据采集阶段 (duration - 2*margin 秒)
    3. **STOP_SAMPLE_STATE** → **END_STATE**: 结束阶段 (margin 秒)

## 主要执行流程

### 1. 初始化阶段 (`write_bw.c:main()`)

#### 1.1 参数解析
```c
// write_bw.c:73
ret_parser = parser(&user_param, argv, argc);
```
- 解析 `-R` 和 `-D` 参数
- 打印调试信息：`work_rdma_cm`, `test_type`, `duration`

#### 1.2 设备初始化
```c
// write_bw.c:81-93
ib_dev = ctx_find_dev(&user_param.ib_devname);
ctx.context = ctx_open_device(ib_dev, &user_param);
```
- 查找并打开 IB 设备
- 获取设备上下文 (context)

#### 1.3 创建 IB 资源
```c
// write_bw.c:179
ctx_init(&ctx, &user_param);
```

**`ctx_init()` 函数**（`perftest_resources.c:2354`）创建：
- **Protection Domain (PD)**: 保护域，隔离不同应用的内存
  ```c
  ctx->pd = ibv_alloc_pd(ctx->context);
  ```
- **Memory Region (MR)**: 注册内存区域，获取 lkey 和 rkey
  ```c
  ctx->mr[i] = ibv_reg_mr(ctx->pd, ctx->buf[i], size, access_flags);
  ```
  - `lkey`: 本地操作使用
  - `rkey`: 远程 RDMA 操作使用
- **Completion Queue (CQ)**: 完成队列，接收操作完成通知
  ```c
  ctx->send_cq = ibv_create_cq(ctx->context, ...);
  ctx->recv_cq = ibv_create_cq(ctx->context, ...);
  ```

### 2. 连接建立阶段

#### 2.1 QP 创建和连接
```c
// write_bw.c:194
ctx_connect(&ctx, rem_dest, &user_param, my_dest);
```
- 创建 Queue Pair (QP)
- 交换连接信息（QPN, LID, GID, vaddr, rkey）
- QP 状态转换：
  - RESET → INIT → RTR (Ready to Receive) → RTS (Ready to Send)

#### 2.2 握手同步
```c
// write_bw.c:237
ctx_hand_shake(&user_comm, &my_dest[0], &rem_dest[0]);
```
- 在 RTR 状态后进行额外握手
- 确保双方准备就绪

### 3. WQE 配置阶段

#### 3.1 配置发送 WQE
```c
// write_bw.c:422
ctx_set_send_wqes(&ctx, &user_param, rem_dest);
```

**`ctx_set_send_wqes()` → `ctx_set_send_reg_wqes()`**（`perftest_resources.c:3560`）：

为每个 QP 配置发送工作请求：

```c
// 设置本地内存 SGE (Scatter-Gather Entry)
ctx->sge_list[i].addr = (uintptr_t)ctx->buf[i];        // 本地缓冲区地址
ctx->sge_list[i].length = user_param->size;             // 传输大小
ctx->sge_list[i].lkey = ctx->mr[i]->lkey;              // 本地 key

// 设置远程 RDMA 参数
ctx->wr[i].wr.rdma.remote_addr = rem_dest[i].vaddr;    // 远程内存地址
ctx->wr[i].wr.rdma.rkey = rem_dest[i].rkey;            // 远程 key
ctx->wr[i].opcode = IBV_WR_RDMA_WRITE;                 // 操作码：RDMA WRITE
ctx->wr[i].send_flags = IBV_SEND_SIGNALED;             // 请求完成通知
```

**关键 RDMA WRITE 参数**:
- **remote_addr**: 目标内存地址（从 `rem_dest` 获取）
- **rkey**: 远程内存区域的保护 key（必须匹配对端的 MR）
- **本地 buffer**: 要发送的数据源
- **操作码**: `IBV_WR_RDMA_WRITE`（非 immediate 模式）

### 4. 带宽测试主循环

#### 4.1 进入测试循环
```c
// write_bw.c:473
run_iter_bw(&ctx, &user_param);
```

**`run_iter_bw()` 函数**（`perftest_resources.c:4014`）：

##### 4.1.1 DURATION 模式初始化
```c
if (user_param->test_type == DURATION) {
    duration_param = user_param;
    duration_param->state = START_STATE;
    signal(SIGALRM, catch_alarm);      // 注册信号处理
    alarm(user_param->margin);          // margin 秒后触发
    user_param->iters = 0;              // 用作计数器
}
```

**信号处理流程**:
```
时间轴:
0s ────── margin ────── (duration-margin) ────── duration
|         |             |                         |
START  → SAMPLE  →  STOP_SAMPLE  →           END_STATE
(预热)    (采样)        (结束)
```

##### 4.1.2 主循环
```c
// perftest_resources.c:4127
while (totscnt < tot_iters || totccnt < tot_iters ||
       (user_param->test_type == DURATION && user_param->state != END_STATE)) {
```

**循环内操作**:

1. **Post 发送请求**:
```c
// perftest_resources.c:4168
err = post_send_method(ctx, index, user_param);
```
- 调用 `ibv_post_send()` 提交 WQE 到 QP
- HCA 硬件处理 RDMA WRITE 操作
- 数据通过 RDMA 直接写入远程内存

2. **Poll 完成队列**:
```c
// perftest_resources.c:4238
ne = poll_completions(ctx->send_cq, wc, dyn_ctx, totccnt, ...);
```
- 调用 `ibv_poll_cq()` 从 send CQ 获取完成事件
- 检查 `wc[i].status` 确认操作成功
- **注意**: RDMA WRITE 只需 poll send CQ，不需要 poll recv CQ

3. **更新计数器**:
```c
ctx->scnt[index] += user_param->post_list;  // 发送计数
totscnt += user_param->post_list;            // 总发送计数
totccnt += ne;                               // 总完成计数
```

4. **DURATION 模式的计数**:
```c
if (user_param->test_type == DURATION &&
    user_param->state == SAMPLE_STATE) {
    user_param->iters += user_param->cq_mod;  // 只在采样阶段计数
}
```

### 5. 性能统计和报告

#### 5.1 收集性能数据
```c
// write_bw.c:489
print_report_bw(&user_param, &my_bw_rep);
```

**计算指标** (`perftest_parameters.c:4233`):
- **带宽 (Bandwidth)**:
  ```
  BW = (iters * size * 8) / (测试时间 * 1e9) Gb/s
  ```
- **消息速率 (Message Rate)**:
  ```
  MsgRate = iters / 测试时间 Mpps
  ```
- **测试时间** (DURATION 模式):
  ```
  测试时间 = duration - 2*margin  (只统计采样阶段)
  ```

#### 5.2 输出报告
```
 #bytes     #iterations    BW peak[Gb/sec]    BW average[Gb/sec]   MsgRate[Mpps]
 65536      X              XX.XX              XX.XX                X.XXXXXX
```

## RDMA WRITE 特点

### 与 SEND 操作的区别

| 特性 | RDMA WRITE | SEND |
|------|------------|------|
| 接收端 WQE | **不需要** post receive | 需要 post receive |
| 接收端 CQ polling | **不需要** poll recv CQ | 需要 poll recv CQ |
| 内存地址 | 发送方指定远程地址 | 接收方决定接收位置 |
| 目标内存 | 直接写入指定地址 | 写入接收 WQE 指定的 buffer |
| CPU 参与 | 接收端 CPU 无感知 | 接收端需要处理完成事件 |

### CLIENT 和 SERVER 角色分工

#### CLIENT (主动端，发起 WRITE 操作)
- **初始化阶段**:
  - 创建 IB 资源（PD, MR, CQ, QP）
  - 分配本地数据缓冲区（源数据）
  - 从 SERVER 获取远程内存信息（vaddr, rkey）

- **测试阶段**:
  - 配置 WQE，设置远程地址和 rkey
  - 循环调用 `ibv_post_send()` 发起 RDMA WRITE
  - 调用 `ibv_poll_cq(send_cq)` 检查完成状态
  - 收集性能数据（时间戳、计数器）

- **特点**: CPU 密集，不断 post 和 poll

#### SERVER (被动端，提供远程内存)
- **初始化阶段**:
  - 创建 IB 资源（PD, MR, CQ, QP）
  - 分配目标内存缓冲区
  - 注册 MR，生成 rkey
  - 通过握手发送 vaddr 和 rkey 给 CLIENT

- **测试阶段**:
  - **什么都不做！**
  - 不需要 post receive
  - 不需要 poll CQ
  - 数据自动被 CLIENT 写入内存
  - CPU 完全空闲，零开销

- **特点**: 零 CPU 占用，完全由硬件处理

### RDMA WRITE 操作流程（标注角色）

```
CLIENT (发送方/主动端)                    SERVER (接收方/被动端)
┌─────────────────────┐                  ┌─────────────────────┐
│  初始化阶段          │                  │  初始化阶段          │
│  1. 创建 PD/MR/CQ   │◀────握手交换────▶│  1. 创建 PD/MR/CQ   │
│  2. 获取 SERVER 的   │    连接信息       │  2. 注册 MR 生成    │
│     vaddr 和 rkey   │                  │     vaddr 和 rkey   │
├─────────────────────┤                  ├─────────────────────┤
│  测试阶段            │                  │  测试阶段            │
│                     │                  │                     │
│  3. 准备数据到本地   │                  │  3. 等待...         │
│     buffer (源)     │                  │     (无任何操作)     │
│                     │                  │                     │
│  4. 配置 WQE:       │                  │                     │
│     - local: buf    │                  │                     │
│     - remote: vaddr │                  │                     │
│     - rkey          │                  │                     │
│                     │                  │                     │
│  5. ibv_post_send() │                  │                     │
│     提交 WRITE 请求  ├──RDMA 网络传输──▶│  4. 数据自动到达     │
│                     │   HCA DMA 写入   │     目标 buffer     │
│                     │   远程内存        │     (硬件处理)      │
│                     │                  │     CPU 无感知！     │
│  6. ibv_poll_cq()   │                  │                     │
│     send_cq         │                  │  5. 继续等待...     │
│     检查完成状态     │                  │     (仍无操作)      │
│                     │                  │                     │
│  7. 重复 4-6        │                  │                     │
│     直到测试完成     │                  │                     │
├─────────────────────┤                  ├─────────────────────┤
│  结束阶段            │                  │  结束阶段            │
│  8. 交换性能数据     │◀────握手同步────▶│  6. 接收 CLIENT     │
│  9. 计算并输出结果   │                  │     的性能报告       │
└─────────────────────┘                  └─────────────────────┘

关键点：
- CLIENT: 主动执行 post_send + poll_cq，CPU 忙碌
- SERVER: 完全被动，测试期间 CPU 空闲，零开销
- 这就是 RDMA 单边操作的核心优势！
```

## 关键数据结构

### `perftest_parameters` 结构体
```c
struct perftest_parameters {
    int work_rdma_cm;        // -R 参数，使用 RDMA CM
    int duration;            // -D 参数，测试持续时间（秒）
    TestMethod test_type;    // DURATION 或 ITERATIONS
    VerbType verb;           // WRITE, WRITE_IMM, READ, SEND, ATOMIC
    int margin;              // 预热/结束边界时间
    DurationStates state;    // DURATION 模式的状态机
    uint64_t size;           // 消息大小
    int tx_depth;            // 发送队列深度
    int num_of_qps;          // QP 数量
    ...
};
```

### `pingpong_context` 结构体
```c
struct pingpong_context {
    struct ibv_context *context;      // 设备上下文
    struct ibv_pd *pd;                // Protection Domain
    struct ibv_mr **mr;               // Memory Regions
    struct ibv_cq *send_cq;           // 发送完成队列
    struct ibv_cq *recv_cq;           // 接收完成队列
    struct ibv_qp **qp;               // Queue Pairs
    void **buf;                       // 数据缓冲区
    struct ibv_sge *sge_list;         // Scatter-Gather 列表
    struct ibv_send_wr *wr;           // 发送工作请求
    uint64_t *my_addr;                // 本地内存地址
    uint64_t *rem_addr;               // 远程内存地址
    uint64_t *scnt;                   // 发送计数（每个QP）
    uint64_t *ccnt;                   // 完成计数（每个QP）
    ...
};
```

### `pingpong_dest` 结构体
```c
struct pingpong_dest {
    uint32_t lid;       // Local Identifier (IB)
    uint32_t qpn;       // QP Number
    uint32_t psn;       // Packet Sequence Number
    uint64_t vaddr;     // Virtual Address (远程内存地址)
    uint32_t rkey;      // Remote Key (MR的保护key)
    union ibv_gid gid;  // Global Identifier (RoCE)
    ...
};
```

## 调试日志示例

### CLIENT 端日志
启用调试日志后，CLIENT 输出示例：
```bash
# 命令: ./write_bw -R -D 60 <server_ip>

[DEBUG] parser: -R enabled, using RDMA CM for connection
[DEBUG] parser: -D 60 seconds, test_type set to DURATION
[DEBUG] write_bw: Role=CLIENT (active, performs WRITE), work_rdma_cm=1, test_type=DURATION, duration=60 seconds
[DEBUG] write_bw [CLIENT]: Creating IB resources (PD, MR, CQ)...
[DEBUG] write_bw [CLIENT]: IB resources created successfully
[DEBUG] write_bw [CLIENT]: RUN_REGULAR mode, verb=WRITE
[DEBUG] write_bw [CLIENT]: Setting up send WQEs for WRITE operations
[DEBUG] ctx_set_send_reg_wqes: Configuring WQEs for 1 QPs
[DEBUG] ctx_set_send_reg_wqes: verb=1 (WRITE=1), size=65536, post_list=1
[DEBUG] ctx_set_send_reg_wqes: QP[0] remote_addr=0x7f1234567000
[DEBUG] ctx_set_send_reg_wqes: QP[0] WR[0] rkey=0x1234abcd
[DEBUG] write_bw [CLIENT]: Send WQEs configured
[DEBUG]   - Local buffer: 0x7f9876543000 (source data from CLIENT)
[DEBUG]   - Remote addr: 0x7f1234567000 (target memory on SERVER)
[DEBUG]   - Remote rkey: 0x1234abcd (from SERVER's MR)
[DEBUG] write_bw [CLIENT]: Starting bandwidth test via run_iter_bw
[DEBUG] write_bw [CLIENT]: Test mode = DURATION (time-based)
[DEBUG] write_bw [CLIENT]: Will run for 60 seconds
[DEBUG] run_iter_bw: DURATION mode, duration=60 seconds, margin=15 seconds
[DEBUG] run_iter_bw: Started timing, will warm up for 15 seconds
[DEBUG] run_iter_bw [CLIENT]: Entering main loop, tot_iters=0
[DEBUG] run_iter_bw [CLIENT]: Will post WRITE requests and poll send CQ
... (CLIENT 持续 post WRITE + poll send CQ，运行 60 秒) ...
[DEBUG] write_bw [CLIENT]: Bandwidth test completed

 #bytes     #iterations    BW peak[Gb/sec]    BW average[Gb/sec]   MsgRate[Mpps]
 65536      12345678       95.23              94.87                0.182145
```

### SERVER 端日志
启用调试日志后，SERVER 输出示例：
```bash
# 命令: ./write_bw -R -D 60

[DEBUG] parser: -R enabled, using RDMA CM for connection
[DEBUG] parser: -D 60 seconds, test_type set to DURATION
[DEBUG] write_bw: Role=SERVER (passive, provides remote memory), work_rdma_cm=1, test_type=DURATION, duration=60 seconds
[DEBUG] write_bw [SERVER]: Creating IB resources (PD, MR, CQ)...
[DEBUG] write_bw [SERVER]: IB resources created successfully

************************************
* Waiting for client to connect... *
************************************

[DEBUG] write_bw [SERVER]: Waiting for CLIENT to complete test...
[DEBUG] write_bw [SERVER]: (No RDMA operations needed on SERVER side)
... (SERVER 等待 60 秒，CPU 完全空闲，无任何 RDMA 操作) ...

 #bytes     #iterations    BW peak[Gb/sec]    BW average[Gb/sec]   MsgRate[Mpps]
 65536      12345678       95.23              94.87                0.182145
```

### 关键区别对比
| 阶段 | CLIENT 日志 | SERVER 日志 |
|------|------------|------------|
| 初始化 | 创建资源 + 配置 WQE + 设置远程地址 | 创建资源 + 等待连接 |
| 测试 | 大量 post_send/poll_cq 日志 | **无日志**（什么都不做）|
| 结束 | 输出性能报告 | 接收并显示报告 |
| CPU | 忙碌 | **空闲** |

## 重要函数调用链

```
write_bw.c:main()
│
├─ parser()                              # 解析 -R, -D 参数
│
├─ ctx_init()                            # 创建 IB 资源
│   ├─ ibv_alloc_pd()                    # 分配 PD
│   ├─ ibv_reg_mr()                      # 注册 MR
│   └─ ibv_create_cq()                   # 创建 CQ
│
├─ ctx_connect()                         # 建立连接
│   ├─ create_qp()                       # 创建 QP
│   └─ modify_qp_to_rts()               # QP状态转换
│
├─ ctx_set_send_wqes()                   # 配置发送 WQE
│   └─ ctx_set_send_reg_wqes()
│       └─ 设置 remote_addr, rkey, opcode
│
└─ run_iter_bw()                         # 主测试循环
    ├─ signal(SIGALRM, catch_alarm)      # DURATION模式初始化
    ├─ while (循环条件)
    │   ├─ post_send_method()            # Post RDMA WRITE
    │   │   └─ ibv_post_send()
    │   └─ poll_completions()            # Poll send CQ
    │       └─ ibv_poll_cq()
    └─ print_report_bw()                 # 输出性能报告
```

## 常见问题

### Q1: 为什么 RDMA WRITE 不需要接收端 post receive？
A: RDMA WRITE 是单边操作，发送方直接指定远程内存地址并写入数据。接收端的 HCA 硬件直接将数据 DMA 到指定内存，无需 CPU 或软件参与。

### Q2: DURATION 模式的 margin 参数有什么作用？
A: margin 是预热和结束阶段的时间。测试开始和结束时性能可能不稳定，只统计中间 `duration - 2*margin` 时间段的数据，确保性能测量的准确性。

### Q3: rkey 是什么？为什么必须匹配？
A: rkey (remote key) 是内存区域的保护密钥。接收端注册 MR 时生成，发送端必须使用正确的 rkey 才能访问远程内存。这是 RDMA 的安全机制，防止未授权的内存访问。

### Q4: 如何查看实际的 RDMA 参数？
A: 查看代码中添加的调试日志：
```bash
./write_bw -R -D 60 2>&1 | grep DEBUG
```
会输出 remote_addr, rkey, duration, test_type 等关键参数。

## 总结

RDMA WRITE 带宽测试的核心流程：
1. **参数解析**: `-R` (RDMA CM), `-D 60` (持续60秒)
2. **资源创建**: PD, MR, CQ, QP
3. **WQE配置**: 设置 remote_addr, rkey, opcode
4. **测试循环**: 循环 post_send + poll_cq
5. **DURATION控制**: 使用 SIGALRM 信号分阶段计时
6. **性能统计**: 计算带宽和消息速率

关键特点：
- **单边操作**: 接收端无需软件参与
- **零拷贝**: 数据直接 DMA 到远程内存
- **低CPU占用**: 接收端 CPU 无感知
- **高性能**: 绕过内核，直接硬件处理
