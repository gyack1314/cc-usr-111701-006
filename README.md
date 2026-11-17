# ActivityPub 联邦收件箱的撤回与引用采集资料服务

项目接收 activitypub-feed 来源资料。`capture_data.io` 冻结字节和请求来源，`capture_data.domain` 核对本领域记录结构，`capture_data.journal` 封存来源原文、版本与联邦收据，`capture_data.projection` 显示本地引用缺口。本地判断只覆盖已收到的资料，不推断外部服务的连续性或全量完整性。

Python 3.11 以上，无第三方依赖。样例均为合成，不访问真实站点。

```sh
python -m unittest discover -s tests -v
python -m compileall -q capture_data tests
python -m capture_data.cli inspect data/normal.json
```

Dockerfile 提供 Linux 运行环境；`docker build -t source-capture .` 构建，`docker run --rm source-capture python -m unittest discover -s tests -v` 运行测试。

## 联邦采集扩展

针对“同一对象跨实例转发被记成多篇、作者撤回不传播”的档案问题，新增从授权收件箱与对象地址采集 Create、Update、Delete、Announce、Undo 活动的能力：

| 模块 | 职责 |
| --- | --- |
| `capture_data.transport` | 统一的重定向引擎（离线 `ReplayTransport` 与真实 `UrllibTransport` 共用）；异源跳转剥离 `Authorization`/`Cookie`/`Proxy-Authorization`，网络失联返回错误结果而不抛异常 |
| `capture_data.verification` | RFC 3230 风格 `Digest` 字节摘要与 HTTP Signature 风格 `Signature` 核验；内置可插拔 HMAC 验证器，真实部署可换非对称加密后端 |
| `capture_data.federation` | 采集、发送者核验与因果归并；活动 ID、对象 ID、发送者、请求/最终响应地址四者分列 |
| `capture_data.federation_view` | 档案投影：对象显示状态、所依据的已核验活动、悬而未决引用、失联实例 |
| `capture_data.journal` | 新增收据、实例、活动、快照、对象、证据、悬挂引用七张账本表 |

### 关键规则

- **身份不混用**：`activity_id`、`object_id`、`actor`、`requested_url`/`final_url`/`origin` 分别建列。跨实例 Announce 指向同一 `object_id` 时归并为同一档案对象，每次转发各留独立收据，不再产生重复篇目。
- **重定向不带走认证**：同源跳转保留请求头，异源（scheme/host/port 任一不同）跳转在发出下一跳前剥离敏感头；每一跳的剥离事实记入收据 `hops`。
- **缺席不是删除**：实例失联只在 `instances` 表登记 `reachable=0` 与错误原因，绝不把任何对象转为墓碑。
- **作者权限与因果顺序**：只有摘要与签名均通过、且签名密钥来源与 actor 同源的活动才算作者已核验。Update/Delete 必须由对象作者发出，按 `published`（缺失时按接收序）排序生效；墓碑之后的修订记入拒绝原因，越权修订/删除不改变状态。
- **转发证据永久保留**：Announce 与对它的 Undo 都是证据行；Undo 只把转发效果标记为 `forwarded-then-withdrawn`，不删除原始证据。作者对 Delete 的 Undo 可将对象从墓碑恢复为 active。
- **迟到引用可闭合**：跨实例引用先入 `pending_refs`，后续收到作者原文后重新归并即可闭合；投影同时给出 `dangling_refs` 与 `all_refs_resolved`。
- **可追溯性**：每个对象的 `verified_basis` 列出建立显示状态所用的全部已核验活动/快照及其收据 ID，档案人员可逐条回溯到原始字节与验证结果。

### 离线合成演示

```sh
# 重新生成带签名的合成夹具（可选，产物已随仓库提供）
python -I tests/fixture_build.py

# 按抓取计划走冻结重放，输出联邦归并投影
python -m capture_data.cli collect data/federation-plan.json

# 演示授权头如何参与（令牌只从环境变量读取，不写入计划文件）
COLLECTOR_AUTH_TOKEN=demo-token python -m capture_data.cli collect data/federation-plan.json

# 真实网络传输（默认离线重放；仅在显式 --live 时发起网络请求）
python -m capture_data.cli collect plan.json --live --db journal.sqlite3
```

`data/federation-plan.json` 是抓取计划（端点角色与 HMAC 密钥索引），`data/federation-replay.bin` 是逐跳冻结响应，覆盖正常收件箱、坏签名收据、异源 302 镜像、失联实例等场景。

## 边界

- 内置 HMAC 验证器用于合成与离线场景；接入真实联邦时需提供非对称 HTTP Signature 验证后端，验证接口不变。
- 归并只陈述“已核验收据能推出的状态”，不推断远端实例是否仍存在、序列是否完整。
- 账本冲突语义不变：同一身份收到不同内容的收据会中断事务，不产生半成品。
