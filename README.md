# telemetry-privacy-budget-python

面向遥测数据的隐私聚合链路：接收带租户/用户标识的运行事件，按维度与时间窗口
输出**加噪聚合统计**，用每租户独立的**隐私预算**约束个体暴露，并支持用户
**撤回授权**。预算与撤回状态持久化，访问区分角色并写脱敏审计。

## 快速开始

```bash
uv sync
uv run python main.py            # 默认 SQLite 落在 ./data/privacy.db
# 或自定义
PRIVACY_DB_PATH=/tmp/p.db PRIVACY_EPSILON_BUDGET=2.0 uv run python main.py
```

```bash
# 上报
curl -s -X POST localhost:8080/events -H 'Content-Type: application/json' -d '{
  "events":[{"event_id":"e1","tenant_id":"default","user_id":"u1",
             "ts_ms":1000,"attrs":{"event":"click"}}]}'
# 聚合（折叠并删除明细）
curl -s -X POST 'localhost:8080/aggregate?tenant_id=default'
# 查询加噪结果（默认 analyst 角色）
curl -s 'localhost:8080/aggregates?tenant_id=default'
# 查询预算
curl -s 'localhost:8080/budget?tenant_id=default'
# 撤回授权（admin）
curl -s -X POST localhost:8080/revoke -H 'X-Role: admin' \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"default","user_id":"u1"}'
# 审计（admin，不含可还原个体数据）
curl -s localhost:8080/audit -H 'X-Role: admin'
```

## 测试

```bash
uv run pytest          # 覆盖：预算超额、授权撤回、并发收敛、重启恢复、权限审计
```

## 模块

| 文件 | 职责 |
|---|---|
| `privacy_telemetry/models.py` | 领域类型与异常 |
| `privacy_telemetry/config.py` | 租户配置（维度/窗口/预算/种子） |
| `privacy_telemetry/storage.py` | SQLite 事务化持久化与检查点 |
| `privacy_telemetry/budget.py` | 单调、幂等的每租户预算账本 |
| `privacy_telemetry/noise.py` | 固定种子派生的可复现 Laplace 噪声 |
| `privacy_telemetry/engine.py` | 摄入/聚合/撤回/查询编排 |
| `privacy_telemetry/audit.py` | 角色与脱敏审计 |
| `privacy_telemetry/api.py` | FastAPI HTTP 接口 |
| `main.py` | 服务入口与环境变量配置 |

隐私语义、配置项与边界详见 [docs/PRIVACY.md](docs/PRIVACY.md)。
