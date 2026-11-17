# activitypub-feed 来源契约

来源清单中的资产长度与 SHA-256 用于核对本地原文字节。文档的 collection 与 protocol 必须匹配清单，现有冻结记录类型包括 actor, activity, object, undo。每条记录以 kind、id、version 定位，refs 指向同集合的其他记录，payload 原样留存。来源版本冲突会中断接收；本地引用闭合只表示当前收到的引用能定位，不表示远端序列或授权资料已经完整。

## 已接收的协议资料
旧入口区分 actor、活动与对象 ID，保存 Create 和 Announce 的来源对象关系。它不校验 HTTP Signature，也不推断 Update、Delete 或 Undo 的作者权限。

同集合第二次来源接收保存在 data/conflict-case.json。冲突事务必须保持第一份收据和旧投影。

## 联邦采集契约（federation-fetch-plan）

抓取计划（`kind=federation-fetch-plan`）列出端点：每个端点有 `role`（`inbox` 或 `object`）与 `url`，认证令牌只从运行环境读取，不进计划文件。冻结重放文件逐跳保存请求与响应，响应体以 base64 留存。

### 身份分列

账本中以下标识各自独立成列，任何一层都不得互相覆盖：

- `activities.activity_id`：活动全局 ID，活动表主键；
- `activities.object_id` / `objects.object_id`：对象全局 ID，对象表主键；跨实例 Announce 引用同一对象 ID 时归并为同一对象；
- `activities.actor`：活动发送者；
- `receipts.requested_url`：我们请求的地址；
- `receipts.final_url` 与 `receipts.origin`：重定向后的实际响应地址与来源实例；
- `receipts.hops`：每一跳的状态码、Location、来源与是否剥离了敏感头。

### 收据与验证

- `receipts` 保存每个实例每个请求地址的原始字节、隐去敏感值后的响应头、摘要与签名验证结果；重跑同一计划时按请求地址复用收据 ID 与序号，内容不同即版本冲突。
- 验证分两步：`Digest`（RFC 3230 SHA-256）证明字节未变，`Signature` 证明密钥持有者签过 `(request-target)`、host、date、digest。两者都通过且签名密钥来源与 actor 同源，活动才标记 `actor_verified=1`。
- 异源重定向（scheme/host/port 不同）在转发前剥离 `authorization`、`cookie`、`proxy-authorization`；同源重定向保留。
- 网络错误或超时写成 `receipts.error` 与 `instances.reachable=0`，不产生任何对象状态变更——缺席不是删除。

### 归并与投影

- 已核验作者的 Create/Update/Delete 按 `published`（缺失按接收序）构成因果顺序：Update 晚于墓碑不生效，非作者的 Update/Delete 记入 `decision_reasons` 并拒绝。
- Announce 可由任何已核验发送者提交，作为转发证据永久保留；Undo(Announce) 只把证据效果改为 `forwarded-then-withdrawn`。Undo(Delete) 仅在发送者与原 Delete 作者一致时把对象恢复为 active。
- 未核验活动不参与状态归并，只在 `unverified_activities` 与对象的 `decision_reasons` 中列明。
- `pending_refs` 记录每个引用是否已取得作者原文；投影的 `dangling_refs` 是仍悬而未决的子集，迟到收据重新归并后可闭合。
- 每个对象的 `verified_basis` 回指建立其显示状态的全部已核验活动/快照与收据 ID。
