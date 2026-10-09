# syno-certsync

类似 acme.sh 的轻量工具：从云厂商按时间段拉取证书（或通过 ACME 签发），并更新到群晖 DSM。纯 Python 标准库，无需 pip 安装依赖，直接在群晖上运行。

## 能力矩阵

| 厂商 | 拉取已签发证书 (`fetch`/`sync`) | ACME 签发 (`issue`) |
|---|---|---|
| 阿里云 | 支持 | 支持 (dns_ali) |
| 腾讯云 | 支持 | 支持 (dns_tencent) |
| AWS ACM | 支持 (需 openssl，证书需允许导出) | 支持 (dns_aws) |
| Cloudflare | 不支持 (API 不返回私钥) | 支持 (dns_cf) |
| GoDaddy | 不支持 (私钥不由厂商保管) | 支持 (dns_gd) |
| 华为云 | 暂未实现 | 支持 (dns_huaweicloud) |

ACME 模式以 acme.sh 作为引擎，需先安装：`curl https://get.acme.sh | sh`。

## 使用

```sh
mkdir -p ~/.certsync && cp config.example.ini ~/.certsync/config.ini && chmod 600 ~/.certsync/config.ini

# 列出最近 7 天签发的证书
python3 -m syno_certsync list --provider aliyun --days 7

# 指定时间段并按域名过滤，下载
python3 -m syno_certsync fetch --provider tencent --since 2026-09-01 --until 2026-10-09 --domain example.com

# 按到期时间筛选 (例如未来30天内到期)
python3 -m syno_certsync list --provider aliyun --by expires --since 2026-10-09 --until 2026-11-08

# 拉取并直接更新群晖 (需 root)
python3 -m syno_certsync sync --provider aliyun --days 7 --domain example.com

# ACME 签发 (如 Cloudflare) 并部署
python3 -m syno_certsync issue --provider cloudflare -d example.com -d '*.example.com' --deploy
```

常用参数：`--since/--until`(日期或ISO时间)、`--days N`(最近N天)、`--by issued|expires`、`--include-expired`、`--dry-run`、`--syno-desc`、`--syno-default`。

## 群晖部署说明

1. 先在 DSM「控制面板 > 安全性 > 证书」手动导入一次证书并分配服务，创建证书槽位。
2. 工具按 `--syno-desc`(证书描述) 或域名匹配槽位，覆盖 `_archive` 下的 PEM 并同步到订阅该证书的各服务，然后重载 nginx。
3. 在「控制面板 > 任务计划」新建 root 用户的计划任务，例如每天执行：
   `python3 -m syno_certsync sync --provider aliyun --days 2 --domain example.com`

## Docker 部署 (群晖 Container Manager)

```sh
git clone <your-repo> && cd syno-certsync
mkdir -p config
cp config.example.ini config/config.ini && chmod 600 config/config.ini   # 填入密钥
cp config/jobs.example.txt config/jobs.txt                               # 每行一个任务
sudo docker compose up -d --build
sudo docker logs -f syno-certsync
```

- 容器需要 `privileged` 与 `pid: host`：前者用于写入 DSM 证书目录，后者让容器通过 `nsenter` 调用宿主机的 `synosystemctl restart nginx`。这是较高权限，请只用于你信任的镜像和密钥。
- 默认每 24 小时执行一遍 `jobs.txt` (`SYNC_INTERVAL_HOURS` 可调)；单次执行：`docker exec syno-certsync /entrypoint.sh once`；调试：`docker exec syno-certsync /entrypoint.sh list --provider aliyun --days 30`。
- 同样需要先在 DSM 里手动导入一次证书建立槽位。

## 发布镜像到 Docker Hub

仓库带有手动触发的 GitHub Action (`.github/workflows/docker-publish.yml`)，构建 linux/amd64 与 linux/arm64 镜像并推送到 `docker.io/<用户名>/syno-certsync`。

1. 在 Docker Hub 创建 Access Token (Account Settings > Security)。
2. 在 GitHub 仓库 Settings > Secrets and variables > Actions 添加 `DOCKERHUB_USERNAME` 和 `DOCKERHUB_TOKEN`。
3. 打开仓库 Actions 页，选择 "Publish Docker image" > Run workflow，填入 tag (可同时推 latest)。

## 状态与注意

- 阿里云、腾讯云、AWS 的接口参数与返回字段已对照官方文档核对；三家的签名算法用官方文档/测试集里的参考样例验证过 (见 `tests/test_signing.py`)；部署逻辑在模拟的 DSM 证书目录上测试过。但尚未用真实账号和真实群晖验证：DSM 的 `_archive/INFO` 结构 (参照社区脚本)、容器内 `nsenter` 重启 nginx。首次请先用 `list` 与 `--dry-run` 试跑，并反馈问题。
- `--days N` 只处理最近 N 天签发的证书；内容未变化时不会覆盖文件，也不会重启 nginx，所以 N 可以放心取大一些。
- 阿里云的开始/到期时间只精确到日期，腾讯云按北京时间 (GMT+8) 解析。
- 私钥会落盘到 `~/.certsync/certs`，权限 600，请勿提交到仓库 (已在 .gitignore 中排除)。
- 使用只读/最小权限的 AccessKey。

## 测试

```sh
python3 -m unittest discover tests
```

## License

MIT
