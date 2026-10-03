# 基因组数据访问治理

这是一个只使用Python标准库和SQLite的模块化项目，默认端口为`8304`。所有业务规则集中在`src/rules.py`，`app.py`只负责组装依赖和启动服务。

## 模块结构

- `app.py`：命令行参数、依赖组装、启动和信号处理。
- `src/domain.py`：角色、数据结构、领域异常和基础校验。
- `src/rules.py`：状态机、权限、领域计算、冲突和跨对象校验（含三对象生命周期联动规则）。
- `src/repository.py`：SQLite建表、查询、事务、乐观锁、操作号台账和启动时数据升级。
- `src/service.py`：用例编排、幂等处理、版本控制、生命周期级联、到期清扫、放行判定和审计对账。
- `src/lifecycle_migration.py`：已有凭证数据升级（旧状态映射与回收原因回填）。
- `src/http_api.py`：HTTP路由、请求解析和统一错误响应。
- `src/audit.py`：实体操作审计时间线。
- `static/index.html`：最小演示页面。
- `tests/`：完整流程、规则和失败场景测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8304
```

服务启动时会自动建表。`--host`可修改监听地址，`--db`可指定其他SQLite文件。

## 核心对象

- `dataset`：受控数据集（registered/restricted/published）。
- `application`：访问申请（draft/submitted/under_review/approved/rejected/withdrawn）。
- `grant`：限时数据使用凭证（issued/active/void/recycling/recycled/revoked）。

## 生命周期联动

- **数据集受限（restrict）**：该数据集下未激活凭证立即作废（void），已激活凭证进入回收中（recycling）并停止放行；级联与主动作在同一事务提交。
- **申请撤回（withdraw）**：关联未激活凭证作废，已激活凭证进入回收中并停止放行。
- **凭证到期（expire 或 `GET /api/grants/sweep-expirations` 清扫）**：未激活凭证作废，已激活凭证进入回收中；回收期间到期的凭证回收原因落为 expired，不再允许恢复。
- **数据集重新发布（publish）**：仅因数据集受限进入回收、关联申请仍批准且仍在有效期内、回收未完成的凭证自动重新启用（active）；已回收完成或已到期的不恢复。
- **放行判定**：`GET /api/grants/<id>/access` 返回 allow/deny 及原因。

凭证的 `lifecycle_reason`（dataset_restricted / application_withdrawn / expired / revoked）记录回收原因。

## 操作号（激活/撤销并发）

动作请求可携带 `op_no`（请求体字段或 `X-Op-No` 头）。委员会同时提交激活与撤销同一凭证时，以版本号乐观锁串行化，只有一边成功；失败重试沿用原操作号，不产生第二条操作记录或审计；已成功的操作号重放直接返回结果。操作台账见 `operations` 表。

## 已有数据升级

服务启动时按 `PRAGMA user_version` 幂等升级：旧 `expired`/`revoked` 凭证按申请、数据集和到期时间映射到新状态并回填 `lifecycle_reason`，每次升级写 `lifecycle_migration` 审计。

## 审计对账

`GET /api/reconcile` 列出状态不一致记录：凭证与关联申请/数据集/到期时间漂移、缺失关联对象、缺失回收原因、审计时间线与实体状态漂移、成功操作缺少审计等。

## 主要接口

- `GET /health`：健康检查。
- `GET /api/<kind>`：按对象类型查询，可用`?status=`过滤。
- `POST /api/<kind>`：创建对象；请求体为JSON。
- `GET /api/entities/<id>`：读取对象当前版本。
- `POST /api/entities/<id>/actions`：提交`{"action":"动作名","data":{...},"expected_version":数字,"op_no":"操作号"}`。
- `GET /api/grants/<id>/access`：凭证放行判定。
- `GET /api/grants/sweep-expirations`：清扫已到期凭证（admin/committee）。
- `GET /api/reconcile`：审计对账，列出状态不一致记录。
- `GET /api/audit`：读取审计记录。

请求身份通过`X-User-Id`和`X-Role`请求头传入。创建和动作的可执行角色由规则引擎控制。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 局限

数据目录和授权凭证是治理流程演示，不包含真实数据下载、加密或机构身份联邦。
