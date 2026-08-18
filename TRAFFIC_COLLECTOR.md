# 真实会员流量采集接入

后台接口：

```text
POST https://sub.0909106.xyz/api/traffic/report
Header: X-Update-Token: 你的 UPDATE_TOKEN
```

## Xray-core 推荐方式

前提：

- Xray 开启 Stats/API。
- 每个用户配置 `email`。
- 后台用户的 `traffic_key` 必须等于 Xray 用户 `email`。

推荐使用 `--reset`，每次读取后清空 Xray 计数，后台按增量累加：

```bash
python3 /opt/iguang-sub/scripts/xray_usage_collector.py \
  --backend xray \
  --xray-bin /usr/local/bin/xray \
  --xray-api 127.0.0.1:10085 \
  --reset \
  --report-url https://sub.0909106.xyz/api/traffic/report \
  --token 你的UPDATE_TOKEN
```

crontab：

```cron
*/5 * * * * /usr/bin/python3 /opt/iguang-sub/scripts/xray_usage_collector.py --backend xray --xray-bin /usr/local/bin/xray --xray-api 127.0.0.1:10085 --reset --report-url https://sub.0909106.xyz/api/traffic/report --token 你的UPDATE_TOKEN >> /var/log/iguang-traffic.log 2>&1
```

如果不能 reset，可以用 state 文件做增量。第一次运行默认只建立基线，第二次开始上报增量：

```bash
python3 /opt/iguang-sub/scripts/xray_usage_collector.py \
  --backend xray \
  --xray-bin /usr/local/bin/xray \
  --xray-api 127.0.0.1:10085 \
  --state-file /var/lib/iguang-sub/xray-traffic.json \
  --report-url https://sub.0909106.xyz/api/traffic/report \
  --token 你的UPDATE_TOKEN
```

## 手动 JSON 上报

增量上报必须带 `mode=delta` 或 `delta_bytes`：

```json
{
  "traffic_key": "user@example.com",
  "upload": 1048576,
  "download": 5242880,
  "mode": "delta",
  "source_ip": "203.0.113.10",
  "node": "HK-01",
  "protocol": "vless"
}
```

绝对值上报使用 `used_bytes`：

```json
{
  "traffic_key": "user@example.com",
  "used_bytes": 6291456
}
```

## sing-box 说明

`sing-box` 的 Clash API 主要是连接采样，不一定带会员用户标识。只有连接对象里存在 `user/email/inboundUser` 等字段时，脚本才能把流量归到对应会员。

```bash
python3 /opt/iguang-sub/scripts/xray_usage_collector.py \
  --backend sing-box \
  --sing-box-api http://127.0.0.1:9090 \
  --report-url https://sub.0909106.xyz/api/traffic/report \
  --token 你的UPDATE_TOKEN
```

如果 sing-box 连接没有用户标识，它只能作为审计事件参考，不能当作会员流量扣减依据。
