# 遥测隐私聚合链路：隐私语义与配置说明

本服务接收客户端上报的运行事件，按"租户 / 维度 / 时间窗口"输出聚合统计，同时
用**隐私预算（privacy budget）**约束个体数据的暴露程度，并支持用户撤回授权。

## 1. 数据模型与生命周期

```
客户端事件 ──POST /events──▶ raw_events（临时明细）
                                  │  POST /aggregate（折叠）
                                  ▼
              partials（每用户/每桶贡献，仅为撤回而保留）
                                  │  求和
                                  ▼
              aggregates（每桶总量 + 贡献用户数，不含 user_id）
                                  │  GET /aggregates
                                  ▼
              对外发布：固定种子派生的加噪结果（Laplace）
```

- 事件在被折叠进 `partials` 的**同一事务内**从 `raw_events` 删除，聚合完成后
  不保留原始明细（幂等墓碑 `processed_ids` 仅保存不透明的 `event_id`，撤回时也
  一并删除，不含任何载荷、时间戳或属性）。
- `partials` 是唯一的个体级状态，其唯一用途是在用户撤回时精确减去该用户的贡献；
  它永远不会通过对外接口暴露。
- 对外只发布 `aggregates` 的**加噪值**。

## 2. 聚合与可复现性

- 维度由租户配置 `dimensions` 决定（取事件 `attrs` 中对应键，缺失记为空串）。
- 时间窗口为翻滚窗口，窗口起点
  `window_start = (ts_ms // (window_seconds*1000)) * (window_seconds*1000)`。
- 聚合方式：`count`（事件计数，敏感度 1）或 `sum`（对 `value` 求和）。
- **随机化完全确定**：每个桶的 Laplace 噪声由
  `SHA256(master_seed, tenant_id, window_start, 排序后的维度取值, 桶内容摘要)`
  派生，再用该摘要作为种子采样。没有全局 RNG、不依赖处理顺序：
  - 同一份输入、相同配置 ⇒ 噪声与加噪结果逐位相同；
  - 桶的真实值发生变化（例如撤回后）会得到不同的内容摘要，从而得到独立噪声，
    避免"多次发布同一桶时噪声被抵消"。
- 折叠按事件自增序列进行，聚合提交位置写入 `meta.agg_checkpoint:<tenant>`。

## 3. 隐私预算（每租户独立、单调、可查询）

- 每个租户拥有独立的总预算 `epsilon_budget`；账本 `budget_entries` 只追加，
  消耗**只增不减**，可通过 `GET /budget` 查询 `consumed / limit / remaining`。
- 扣价点：
  - `POST /aggregate`：每次成功折叠一批事件扣 `aggregation_cost`；
  - `GET /aggregates`：每次查询扣 `query_cost`。
- 预算检查与扣减在**同一个数据库事务**内完成；超额时抛出 `BudgetExceededError`
  （HTTP `402`），不做任何状态变更，绝不静默放行。
- 查询支持幂等键 `request_id`：同一 `(tenant, request_id)` 的重试只扣一次，
  网络重试不会重复扣预算。
- 超额而无法折叠的事件仍保留在 `raw_events` 中等待后续处理，不丢失、不被重复计入。

## 4. 用户撤回授权

`POST /revoke {tenant_id, user_id}` 在**单个事务内**：

1. 在 `revoked` 中登记（幂等，重复撤回返回 `buckets_changed=0`）；
2. 删除该用户的 `raw_events`、`processed_ids` 墓碑与全部 `partials`；
3. 对受影响的每个桶从剩余用户的部分贡献**重新求和**，空桶删除。

因此撤回后的结果与"该用户从一开始就未被纳入"在数学上一致（见
`tests/test_revocation.py::test_revocation_equivalent_to_never_included`）。
撤回后该用户迟到/重放的事件在聚合时会被直接丢弃。

## 5. 并发收敛

所有对外操作都经过同一把进程内可重入锁 + SQLite `BEGIN IMMEDIATE` 串行事务。
"预算扣减 / 明细折叠 / 撤回删除 / 桶重算"各自原子提交，外部观察只可能看到
操作前或操作后，不会看到中间态。由此保证：

- 同一用户的贡献不会被重复计入；
- 撤回不会留下任何残留（raw / 墓碑 / partials 全部清除）；
- 并发聚合与撤回在静止点收敛，`aggregates` 总和恒等于现存 `partials` 之和。

> 部署为多进程/多副本时，应以单写者方式运行聚合与撤回（SQLite 单库 +
> WAL），或将 `Storage` 替换为提供等价串行事务的外部数据库实现。

## 6. 持久化与重启恢复

全部状态（明细、部分贡献、聚合结果、预算账本、撤回标记、审计、检查点）都在
SQLite 文件中并随事务提交（WAL）。重启后：

- 已折叠窗口不会重复处理，检查点之后无重复扣价、无重复删除；
- 已提交但未折叠的 `raw_events` 继续保留，重启后可再折叠，且只扣一次；
- 撤回标记持久，重启后仍拒绝该用户；重复撤回是无副作用的幂等操作；
- 预算账本与 `request_id` 幂等记录持久，重启后重试同一请求不重复扣费。

## 7. 访问控制与审计

角色（请求头 `X-Role`，生产环境应替换为经过校验的身份令牌）：

| 角色 | 加噪聚合 `/aggregates` | 暂存明细 `/raw-events` | 撤回 `/revoke` | 审计 `/audit` |
|---|---|---|---|---|
| `analyst` | ✅ | ❌ | ❌ | ❌ |
| `support` | ✅ | ✅（仅本租户、仅未折叠明细） | ❌ | ❌ |
| `admin` | ✅ | ✅ | ✅ | ✅ |

撤回是高敏感操作，仅 `admin` 可执行；非 admin 的撤回尝试返回 403、不改动
任何状态，并以脱敏方式记入审计。

- 越权访问返回 `403 {"detail":"access denied"}`，错误信息不含任何个体数据，
  响应体不返回任何事件。
- 所有允许与拒绝的访问都写审计（`actor / role / action / allowed / 时间 /
  租户`）。
- 审计不记录用户标识与取值；涉及个体主体（如撤回）时，仅保存以部署密钥做
  HMAC-SHA256 后的不可逆引用 `u_xxxx`，同一用户映射稳定、不可还原。

## 8. 配置项

`TenantConfig`（`privacy_telemetry/config.py`，可通过 `StaticConfigRegistry`
注册多租户）：

| 配置 | 含义 | 默认值 |
|---|---|---|
| `tenant_id` | 租户标识 | 必填 |
| `dimensions` | 参与聚合的事件属性名（有序） | `("event",)` |
| `window_seconds` | 翻滚窗口长度（秒） | `60` |
| `aggregation` | `count` 或 `sum` | `count` |
| `epsilon_budget` | 租户总隐私预算 | `2.0` |
| `aggregation_cost` | 每次聚合发布扣价 | `0.5` |
| `query_cost` | 每次聚合查询扣价 | `0.1` |
| `noise_epsilon` | Laplace 噪声的 epsilon（尺度 `1/noise_epsilon`） | `1.0` |
| `master_seed` | 随机化主种子，决定可复现性 | `0` |

服务入口 `main.py` 支持环境变量覆盖单租户配置：
`PRIVACY_DB_PATH`、`PRIVACY_TENANT_ID`、`PRIVACY_DIMENSIONS`、
`PRIVACY_WINDOW_SECONDS`、`PRIVACY_EPSILON_BUDGET`、`PRIVACY_AGG_COST`、
`PRIVACY_QUERY_COST`、`PRIVACY_NOISE_EPSILON`、`PRIVACY_MASTER_SEED`。

## 9. HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/events` | 上报一批事件（按 `event_id` 幂等去重），返回 `accepted` |
| POST | `/aggregate?tenant_id=` | 折叠待处理事件并发布；超额返回 402 |
| GET | `/aggregates?tenant_id=&window_start_ms=&request_id=` | 查询加噪聚合，按角色授权、按查询扣价 |
| GET | `/raw-events?tenant_id=` | 查询尚未折叠的明细（support/admin） |
| POST | `/revoke` | 撤回用户授权，原子移除其全部贡献 |
| GET | `/budget?tenant_id=` | 查询预算消耗/剩余 |
| GET | `/audit?tenant_id=` | 查询审计（admin；不含可还原个体数据） |
| GET | `/health` | 健康检查 |

## 10. 隐私语义的边界（须知）

- 噪声为独立桶级 Laplace 机制；跨大量桶/多次查询的累积消耗由预算账本控制，
  但同一桶内容变化后的"新发布"会再次消耗预算——请用较小的 `query_cost` 与
  合理总预算约束总发布次数。
- `support` 角色可看到**尚未折叠**的暂存明细；若要求明细完全不可见，请只授予
  `analyst`，并让聚合紧跟摄入执行。
- 维度高基数、桶内用户过少时，加噪计数仍可能间接暴露小群体；建议配合最小桶
  用户数等上游策略（当前版本以预算 + 加噪为主，不做桶抑制）。
