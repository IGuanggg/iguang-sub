# iguang-sub 订阅聚合服务

旭光自研的订阅聚合后台（Python 单文件应用）。部署于 HostDare `103.79.118.103`，公网入口 `https://sub.0909106.xyz`。

## 功能

- 多源订阅聚合：拉取节点源 → subs-check 筛选（延迟/地区/协议）→ 生成 Clash / v2rayNG 订阅
- Web 后台管理：模板、节点、更新
- 板夹 `scripts/xray_usage_collector.py`：Xray 节点流量计量采集
- 对接 sublinkpro / Xboard 分发

## 部署

```bash
cp .env.example .env   # 填写 ADMIN_USER / ADMIN_PASSWORD / UPDATE_TOKEN / SUB_TOKEN 等
docker compose up -d --build
```

- 端口：`HOST_PORT`（默认映射 `8001`，本机使用 `18002 -> 8001`，1Panel 反代）
- 数据目录 `data/`（nodes.txt + sub.db）为运行时数据，**不入库**

## 目录结构

```
app.py            # 主应用（Flask，单文件）
deploy/server/    # 服务部署脚本
scripts/          # 流量采集等工具
subs-check/config # subs-check 配置
static/ templates/ # Web 前端资源
```

## 说明

- `.env.example` 为模板，真实凭据只在服务器 `.env`
- 版本迭代：本仓库用于追踪部署配置与自研代码，便于重构