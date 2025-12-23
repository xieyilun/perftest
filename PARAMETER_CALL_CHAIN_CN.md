# 参数调用链路详解

本文档详细说明 `-R`, `-z`, `-s`, `-D` 四个参数的完整调用链路和作用。

## 参数概览

| 参数 | 含义 | 设置的变量 | 默认值 | 作用 |
|------|------|-----------|--------|------|
| `-R` | 使用 RDMA CM (完整模式) | `work_rdma_cm = ON` | OFF | 启用 RDMA CM 进行连接管理，自动处理 QP 状态转换 |
| `-z` | 使用 RDMA CM (基础模式) | `use_rdma_cm = ON` | OFF | 启用 RDMA CM 进行参数交换 |
| `-s` | 消息大小 | `size` | 65536 (BW) / 2 (LAT) | 设置每次 RDMA 操作传输的数据量 |
| `-D` | 测试持续时间 | `test_type = DURATION`, `duration` | ITERATIONS, 10 | 基于时间而非迭代次数进行测试 |

## 参数区别说明

### -R vs -z

- **`-z` (use_rdma_cm)**：基础 RDMA CM 模式
  - 只用于参数交换（通过 socket）
  - QP 创建和状态转换仍使用传统 Verbs API
  - 较少使用

- **`-R` (work_rdma_cm)**：完整 RDMA CM 工作模式
  - 使用 RDMA CM 管理整个连接过程
  - 自动创建和管理 QP
  - 自动处理 QP 状态转换（INIT→RTR→RTS）
  - 无需手动设置 remote_qpn, dlid, dgid 等参数
  - **推荐使用**

**注意**：`-R` 会自动设置 `use_rdma_cm = ON`

```c
// perftest_parameters.c, line 3025
case 'R':
    user_param->work_rdma_cm = ON;
    // 在 force_dependecies() 中会设置：
    // user_param->use_rdma_cm = ON;
    break;
```

## 1. -R 参数调用链路

### 1.1 命令行解析
**文件**: `perftest_parameters.c`

```
parser() [line 2567]
  └─> case 'R': [line 3025]
      └─> user_param->work_rdma_cm = ON
      └─> [DEBUG] "parser: -R enabled, using RDMA CM for connection"
```

### 1.2 依赖关系强制
**文件**: `perftest_parameters.c`

```
force_dependecies() [line 1247]
  └─> if (user_param->work_rdma_cm) [line 1574]
      └─> user_param->use_rdma_cm = ON  // 自动设置 -z 的效果
      └─> 检查连接类型（UC 不支持）
      └─> 检查 multicast（不支持）
      └─> 检查 dualport（不支持）
```

### 1.3 打印测试信息
**文件**: `perftest_resources.c`

```
ctx_print_test_info() [line 4039]
  └─> printf("rdma_cm QPs : %s", qp_state[user_param->work_rdma_cm])
```

### 1.4 RDMA CM 连接建立
**文件**: `write_bw.c` → `perftest_communication.c`

```
main() [write_bw.c, line 68]
  └─> if (user_param.work_rdma_cm == ON) [line 160]
      └─> create_rdma_cm_connection() [perftest_communication.c, line 2908]
          ├─> rdma_create_event_channel() [line 2929]
          │   └─> 创建事件通道用于接收连接事件
          │
          ├─> rdma_cm_allocate_nodes() [line 2945]
          │   └─> 为每个 QP 创建 rdma_cm_id
          │
          ├─> ctx_hand_shake() [line 2957]
          │   └─> CLIENT 和 SERVER 第一次同步
          │
          ├─> CLIENT 路径: rdma_cm_client_connection() [line 2970]
          │   ├─> rdma_resolve_addr() - 解析 SERVER 地址
          │   ├─> rdma_resolve_route() - 解析路由
          │   ├─> rdma_connect() - 发起连接
          │   └─> 等待 RDMA_CM_EVENT_ESTABLISHED 事件
          │
          ├─> SERVER 路径: rdma_cm_server_connection() [line 2973]
          │   ├─> rdma_bind_addr() - 绑定监听地址
          │   ├─> rdma_listen() - 开始监听
          │   ├─> 等待 RDMA_CM_EVENT_CONNECT_REQUEST 事件
          │   ├─> rdma_accept() - 接受连接
          │   └─> 等待 RDMA_CM_EVENT_ESTABLISHED 事件
          │
          └─> ctx_hand_shake() [line 2990]
              └─> CLIENT 和 SERVER 第二次同步，确认连接建立
```

### 1.5 QP 创建
**文件**: `perftest_resources.c`

使用 RDMA CM 时，QP 由 `rdma_create_qp()` 自动创建：

```
ctx_init() [line 2235]
  └─> if (user_param->work_rdma_cm == OFF)
      └─> 手动创建 QP: ctx_qp_create()
  else
      └─> RDMA CM 自动创建 QP（在 rdma_cm_client/server_connection 中）
```

## 2. -z 参数调用链路

### 2.1 命令行解析
**文件**: `perftest_parameters.c`

```
parser() [line 2567]
  └─> case 'z': [line 3008]
      └─> user_param->use_rdma_cm = ON
      └─> [DEBUG] "parser: -z enabled, use_rdma_cm=ON"
```

### 2.2 参数交换
**文件**: `perftest_communication.c`

```
ctx_hand_shake() [line 453]
  └─> if (use_rdma_cm)
      └─> 使用 RDMA CM 通道交换参数
  else
      └─> 使用传统 socket 交换参数
```

**注意**：单独使用 `-z` 较少见，通常使用 `-R`（会自动包含 `-z` 的功能）。

## 3. -s 参数调用链路

### 3.1 命令行解析
**文件**: `perftest_parameters.c`

```
parser() [line 2567]
  └─> case 's': [line 3034]
      ├─> 解析大小后缀（K/M）
      │   └─> 'K' → size_factor = 1024
      │   └─> 'M' → size_factor = 1024*1024
      │
      ├─> user_param->size = strtol(optarg) * size_factor
      ├─> user_param->req_size = 1  // 标记用户指定了大小
      └─> 范围检查: [1, UINT_MAX/2]
```

### 3.2 大小使用场景

#### A. WQE 配置（CLIENT）
**文件**: `perftest_resources.c`

```
ctx_set_send_reg_wqes() [line 3545]
  └─> sg_list.length = user_param->size  // [line 3579]
      └─> 设置每个 WQE 的数据传输长度
```

#### B. 缓冲区分配
**文件**: `perftest_resources.c`

```
alloc_ctx() [line 1155]
  └─> ctx->buff_size = BUFF_SIZE(user_param->size, ...)
      └─> 根据 size 计算实际需要分配的缓冲区大小
      └─> 考虑对齐、内联、连接类型等因素
```

#### C. 带宽计算
**文件**: `perftest_parameters.c`

```
print_report_bw() [line 4210]
  └─> tsize = user_param->size
      └─> bw_avg = (tsize * iters * cycles_to_units) / (sum_of_test_cycles * format_factor)
          └─> 带宽 = 数据量 / 时间
```

## 4. -D 参数调用链路

### 4.1 命令行解析
**文件**: `perftest_parameters.c`

```
parser() [line 2567]
  └─> case 'D': [line 2989]
      ├─> user_param->duration = optarg  // 持续时间（秒）
      ├─> user_param->test_type = DURATION  // 从 ITERATIONS 切换到 DURATION
      └─> [DEBUG] "parser: -D %d seconds, test_type set to DURATION"
```

### 4.2 依赖关系强制
**文件**: `perftest_parameters.c`

```
force_dependecies() [line 1247]
  └─> if (user_param->test_type == DURATION) [line 1460]
      ├─> user_param->iters = 0  // 清零迭代计数器
      ├─> user_param->noPeak = ON  // 不计算峰值带宽
      ├─> 检查不能使用 use_event（事件模式）
      ├─> 检查不能使用 RUN_ALL（所有大小测试）
      └─> if (user_param->cpu_util)
          └─> user_param->cpu_util_data.enable = 1  // 启用 CPU 利用率统计
```

### 4.3 测试初始化
**文件**: `perftest_resources.c`

```
run_iter_bw() [line 3997]
  └─> if (user_param->test_type == DURATION) [line 4054]
      ├─> set_on_duration_flags(user_param)
      │   └─> 设置 SIGALRM 信号处理器
      │   └─> duration_param = user_param  // 全局变量
      │
      ├─> alarm(user_param->margin)
      │   └─> 设置预热阶段定时器（默认 2 秒）
      │
      └─> user_param->state = START_STATE  // 初始状态
```

### 4.4 DURATION 模式状态机

```
                    SIGALRM
    START_STATE ─────────────> SAMPLE_STATE
         │                           │
         │ margin 秒                  │ duration-2*margin 秒
         │ (预热)                     │ (采样)
         │                           │
         │                      SIGALRM
         └───────────────────────────> END_STATE
                                       (结束)
```

**状态转换**：
```c
// perftest_resources.c, alarm_handler()
void alarm_handler(int signum) {
    switch (duration_param->state) {
    case START_STATE:
        // 预热结束，进入采样阶段
        duration_param->state = SAMPLE_STATE;
        alarm(duration_param->duration - 2*duration_param->margin);
        break;

    case SAMPLE_STATE:
        // 采样结束，进入结束阶段
        duration_param->state = END_STATE;
        alarm(duration_param->margin);
        break;

    case END_STATE:
        // 测试结束
        break;
    }
}
```

### 4.5 主循环控制
**文件**: `perftest_resources.c`

```
run_iter_bw() [line 4120]
  └─> while (1) {
      ├─> if (user_param->test_type == DURATION) {
      │   └─> if (user_param->state == END_STATE)
      │       └─> break  // SIGALRM 信号触发退出
      │   }
      │
      ├─> else {  // ITERATIONS 模式
      │   └─> if (index >= tot_iters)
      │       └─> break  // 迭代次数达到退出
      │   }
      │
      └─> 执行 RDMA 操作 ...
      }
```

## 完整调用链路示例

### CLIENT 端执行：`write_bw -R -D 60 -s 64K <server_ip>`

```
1. 参数解析 (perftest_parameters.c)
   ├─> -R: work_rdma_cm = ON, use_rdma_cm = ON
   ├─> -D 60: test_type = DURATION, duration = 60
   └─> -s 64K: size = 65536

2. main() 初始化 (write_bw.c)
   ├─> ctx_init() - 创建 PD, CQ
   │   └─> [DEBUG] "ctx_init [CLIENT]: Allocating Protection Domain (PD)..."
   │
   ├─> alloc_ctx() - 分配 64KB 缓冲区
   │   └─> ctx->buff_size = BUFF_SIZE(65536, ...)
   │
   ├─> create_single_mr() - 注册内存
   │   ├─> register_memory_region()
   │   │   ├─> [DEBUG] "register_memory_region [CLIENT]: Starting MR registration"
   │   │   ├─> register_mr() - 调用 ibv_reg_mr()
   │   │   │   └─> [DEBUG] "register_mr [CLIENT]: addr=0x..., size=65536, flags=0x7"
   │   │   └─> [DEBUG] "MR registered: lkey=0x..., rkey=0x..."
   │
   ├─> create_rdma_cm_connection() - RDMA CM 建连
   │   ├─> [DEBUG] "create_rdma_cm_connection [CLIENT]: Starting RDMA CM connection"
   │   ├─> rdma_create_event_channel()
   │   ├─> rdma_cm_allocate_nodes() - 创建 rdma_cm_id
   │   ├─> ctx_hand_shake() - 第一次握手
   │   ├─> rdma_cm_client_connection()
   │   │   ├─> rdma_resolve_addr()
   │   │   ├─> rdma_resolve_route()
   │   │   ├─> rdma_connect()
   │   │   └─> 等待 ESTABLISHED 事件
   │   ├─> ctx_hand_shake() - 第二次握手（交换 rkey）
   │   └─> [DEBUG] "RDMA CM connection established successfully"
   │
   └─> ctx_set_send_reg_wqes() - 配置 WQE
       ├─> [DEBUG] "ctx_set_send_reg_wqes [CLIENT]: Configuring WQE #%d"
       ├─> remote_addr = rem_dest->vaddr (SERVER 的远程地址)
       ├─> rkey = rem_dest->rkey (SERVER 的 rkey)
       ├─> sg_list.length = 65536 (每次传输 64KB)
       └─> [DEBUG] "WQE configured: remote_addr=0x..., rkey=0x..., size=65536"

3. run_iter_bw() - 执行测试 (perftest_resources.c)
   ├─> [DEBUG] "run_iter_bw [CLIENT]: Starting BW test in DURATION mode"
   ├─> set_on_duration_flags() - 设置 SIGALRM 处理器
   ├─> alarm(2) - 预热 2 秒
   │
   ├─> while (1) {  // 主循环
   │   ├─> if (state == END_STATE) break  // 60 秒后退出
   │   │
   │   ├─> ibv_post_send() - 发送 RDMA WRITE
   │   │   └─> [DEBUG] "CLIENT posting RDMA WRITE #%d"
   │   │
   │   └─> ibv_poll_cq() - 轮询完成
   │       └─> [DEBUG] "CLIENT polled CQE: status=%s"
   │   }
   │
   └─> print_report_bw() - 打印测试结果
       └─> [DEBUG] "Test completed: iters=%d, BW=%.2f GB/s"
```

### SERVER 端执行：`write_bw -R -D 60 -s 64K`

```
1. 参数解析 (同 CLIENT)

2. main() 初始化 (write_bw.c)
   ├─> ctx_init() - 创建 PD, CQ
   │   └─> [DEBUG] "ctx_init [SERVER]: Allocating Protection Domain (PD)..."
   │
   ├─> alloc_ctx() - 分配 64KB 缓冲区
   │
   ├─> create_single_mr() - 注册内存（带 REMOTE_WRITE 权限）
   │   ├─> [DEBUG] "register_mr [SERVER]: Registering MR with ibv_reg_mr()"
   │   ├─> [DEBUG] "register_mr: addr=0x..., size=65536, flags=0xF"
   │   └─> [DEBUG] "MR registered: lkey=0x..., rkey=0x..."
   │       └─> 这个 rkey 将发送给 CLIENT
   │
   ├─> create_rdma_cm_connection() - RDMA CM 建连
   │   ├─> [DEBUG] "create_rdma_cm_connection [SERVER]: Starting RDMA CM connection"
   │   ├─> rdma_create_event_channel()
   │   ├─> rdma_cm_allocate_nodes()
   │   ├─> ctx_hand_shake() - 第一次握手
   │   ├─> rdma_cm_server_connection()
   │   │   ├─> rdma_bind_addr()
   │   │   ├─> rdma_listen()
   │   │   ├─> 等待 CONNECT_REQUEST 事件
   │   │   ├─> rdma_accept()
   │   │   └─> 等待 ESTABLISHED 事件
   │   ├─> ctx_hand_shake() - 第二次握手（发送 rkey 给 CLIENT）
   │   └─> [DEBUG] "RDMA CM connection established successfully"
   │
   └─> [不配置 WQE] SERVER 不需要发送 WQE

3. 等待测试完成 (write_bw.c)
   ├─> [DEBUG] "write_bw [SERVER]: Waiting for CLIENT to complete test..."
   ├─> sleep(60) - 等待 DURATION 时间
   │   └─> SERVER 的 CPU 使用率为 0%（单边操作）
   │   └─> CLIENT 在后台执行 RDMA WRITE，直接写入 SERVER 内存
   │
   └─> [DEBUG] "write_bw [SERVER]: Test duration completed"
```

## 关键点总结

1. **-R 参数**：
   - 启用 RDMA CM 自动管理连接
   - 简化了 QP 状态转换和参数交换
   - 自动包含 -z 的功能

2. **-z 参数**：
   - 单独使用较少见
   - 只影响参数交换方式
   - -R 会自动启用 -z

3. **-s 参数**：
   - 决定每次 RDMA 操作的数据量
   - 影响 WQE 配置、缓冲区大小、带宽计算
   - 支持 K/M 后缀方便使用

4. **-D 参数**：
   - 切换到基于时间的测试模式
   - 使用 SIGALRM 信号控制测试阶段
   - 包含预热(margin)、采样、结束三个阶段
   - 适合长时间稳定性测试

5. **CLIENT vs SERVER**：
   - **CLIENT**: 主动端，执行 RDMA WRITE，消耗 CPU
   - **SERVER**: 被动端，提供远程内存，CPU 使用率为 0
   - MR 注册：双方都需要，但 SERVER 的 rkey 需要传给 CLIENT
   - 连接建立：CLIENT 主动发起，SERVER 被动监听

6. **RDMA WRITE 的单边特性**：
   - 只需要 CLIENT 执行 `ibv_post_send()` 和 `ibv_poll_cq()`
   - SERVER 不参与任何操作（除了初始连接建立）
   - 这是 RDMA 相比 TCP 的主要优势之一
