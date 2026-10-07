# telemetry-privacy-budget-python

面向遥测数据的隐私聚合服务：接收客户端运行事件，按维度/时间窗口输出
**差分隐私加噪**统计，逐租户维护**隐私预算**，支持用户**授权撤回**并从历史
聚合中等价移除，状态持久化、重启可恢复，访问分权限并全程审计。

隐私语义与配置项详见 [docs/PRIVACY.md](docs/PRIVACY.md)。

## 快速开始

```bash
uv sync
uv run uvicorn main:app --reload
# 或: uv run python main.py
```

所有接口需要请求头 `X-Tenant-Id` 与 `X-Role`
（`viewer` / `analyst` / `auditor` / `admin`）。

```bash
T=(-H 'X-Tenant-Id: acme' -H 'X-Role: admin')

# 1) 用户授权
curl -s "${T[@]}" -X POST localhost:8000/consent/grant \
  -H 'Content-Type: application/json' -d '{"user_id":"u1"}'

# 2) 上报事件
curl -s "${T[@]}" -X POST localhost:8000/events \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"u1","event_type":"run","timestamp":1.0,"dimensions":{"os":"linux"}}'

# 3) 发起聚合（固定种子 -> 可复现；成本 1/epsilon）
curl -s "${T[@]/-H 'X-Role: admin'/-H 'X-Role: analyst'}" -X POST \
  localhost:8000/aggregations -H 'Content-Type: application/json' \
  -d '{"dimensions":["os"],"window_start":0,"window_end":10,
       "event_type":"run","epsilon":1.0,"noise_seed":42,"idem_key":"run-001"}'

# 4) 查询预算
curl -s "${T[@]}" localhost:8000/budget

# 5) 撤回授权（历史贡献等价移除，不额外扣费）
curl -s "${T[@]}" -X POST localhost:8000/consent/revoke \
  -H 'Content-Type: application/json' -d '{"user_id":"u1"}'

# 6) 审计（仅 auditor/admin；只含脱敏用户引用）
curl -s -H 'X-Tenant-Id: acme' -H 'X-Role: auditor' localhost:8000/audit
```

## HTTP 接口

| 方法/路径 | 能力 | 说明 |
| --- | --- | --- |
| `POST /events` | `aggregate:write` | 上报遥测事件 |
| `POST /consent/grant` · `/consent/revoke` | `consent:write`（或本人） | 授权 / 撤回 |
| `POST /aggregations` | `aggregate:write` | 运行聚合；超额返回 `402` |
| `GET /aggregations[/{id}]` | `aggregate:read` | 读取加噪结果 |
| `POST /aggregations/{id}/query` | `query:run` | 单元/全量查询（可计费、幂等） |
| `GET /aggregations/{id}/contributions/{user}` | `detail:read` | 个体向量（管理员，返回脱敏引用） |
| `GET` / `PUT /budget` | `aggregate:read` / `consent:write` | 查询 / 设置预算 |
| `GET /audit` | `audit:read` | 审计记录（无明文个体数据） |

## 测试

```bash
uv run pytest
```

覆盖：预算超额拒绝、授权撤回等价移除、并发聚合/撤回收敛、重启恢复不重复扣费
或删除、固定种子可复现、权限隔离与审计脱敏。
