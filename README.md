# LanVault

局域网文件服务器，带一个单页 Web 面板：登录后可浏览目录、下载文件、上传文件、新建文件夹。
只依赖 Python 3.10+ 标准库，没有第三方包，也不需要 Node、数据库或前端构建步骤。

## 快速启动

```bash
cd ~/projects/lanvault
mkdir -p ~/share
python3 lanvault.py --root ~/share --user alice
```

启动时会提示输入密码。服务默认监听 `0.0.0.0:8080`，并打印可访问地址，例如：

```
LanVault 1.1.0
Root: /home/alice/share
User: alice
Open: http://192.0.2.1:8080
Open: http://127.0.0.1:8080
```

同一局域网内的任意设备打开该地址，用 `alice` 和密码登录后即可使用。不需要预先登记设备。
如果本机防火墙开启，需要放行对应的 TCP 端口。

`--root` 指向的目录必须已存在。服务不会自动创建它。

## 密码来源

优先级从高到低：

1. `--password-file FILE`：读取文件全部内容，只去掉末尾一个换行。适合 systemd。
2. 环境变量 `LANVAULT_PASSWORD`。
3. 交互式输入。

密码文件示例：

```bash
install -d -m 700 ~/.config/lanvault
install -m 600 /dev/null ~/.config/lanvault/password
printf '%s\n' 'replace-this' > ~/.config/lanvault/password
python3 lanvault.py --root ~/share --user alice \
  --password-file ~/.config/lanvault/password
```

如果密码文件对同组或其他用户可读，启动时会打印警告。服务只保留密码的 PBKDF2 摘要；代码在
启动完成后不再持有明文密码的引用，但 Python 不保证擦除已释放的字符串内存。进程内存中的摘要和
会话仍可能被同一系统用户读取，因此不要用高权限账号运行服务。

环境变量 `LANVAULT_PASSWORD` 可能被同一系统用户通过 `/proc` 读取，适合 systemd 的临时方案；
长期运行优先使用权限为 `0600` 的密码文件。重启服务会使所有会话失效。

## 免密登录（公钥）

首次用密码登录成功后，浏览器自动生成一把不可导出的 P-256 密钥对（私钥存在浏览器
IndexedDB，公钥上传服务端）。之后打开页面时，服务端下发一次性随机挑战，浏览器用私钥签名，
服务端验签通过即发放会话 Cookie，全程不再输入密码。模型与 SSH 相同：服务端只存公钥。

- 服务端公钥保存在 `--state-file` 同目录的 `public-keys.json`（权限 `0600`），每个用户最多
  16 把。顶栏钥匙按钮可查看已登记的浏览器、为当前浏览器启用、移除公钥。
- 密码登录始终保留作为兜底；浏览器清空站点数据后，用密码重新登录一次即可重新登记。
- 服务端验签依赖系统 `openssl` 命令（不是 Python 包）。缺少 openssl 时启动日志打印警告，
  公钥相关接口返回 `501`，密码登录不受影响。
- **需要安全上下文**：浏览器 WebCrypto 的 `crypto.subtle` 只在 HTTPS 或 `localhost` 下可用。
  纯 HTTP 跨设备访问时免密不可用，只有服务器本机浏览器能用；跨设备免密需要启用 TLS。
- 挑战 60 秒有效、只能使用一次并绑定客户端 IP；验签失败计入与密码登录相同的限流
  （5 分钟 8 次）。

## 启用 HTTPS

服务支持直接加载 PEM 证书和私钥：

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
  -keyout ~/.config/lanvault/key.pem \
  -out ~/.config/lanvault/cert.pem \
  -subj "/CN=lanvault.local" \
  -addext "subjectAltName=IP:192.0.2.1,DNS:lanvault.local"
chmod 600 ~/.config/lanvault/key.pem

python3 lanvault.py --root ~/share --user alice \
  --password-file ~/.config/lanvault/password \
  --tls-cert ~/.config/lanvault/cert.pem \
  --tls-key ~/.config/lanvault/key.pem
```

浏览器会提示自签证书不受信任。证书的 SAN 必须包含实际使用的 IP 或域名。TLS 最低版本为 1.2，
启用 TLS 后会话 Cookie 自动加上 `Secure`。

**HTTP 模式不加密。** 密码、Cookie、上传和下载内容都可能被同一网络中的嗅探者看到。只在可信
局域网使用 HTTP；否则启用 TLS。本项目面向局域网，不建议直接暴露到公网。

## 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--root PATH` | 必填 | 要共享的目录 |
| `--bind ADDR` | `0.0.0.0` | 监听地址；可设为 `127.0.0.1` 只允许本机 |
| `--port PORT` | `8080` | 监听端口 |
| `--user NAME` | 当前系统用户 | 登录用户名 |
| `--password-file FILE` | 无 | 从文件读取密码 |
| `--state-file FILE` | `$XDG_STATE_HOME/lanvault/quick-access.json` | 按用户保存快捷访问的 JSON 文件；同目录另存公钥登录的 `public-keys.json` |
| `--session-hours N` | `12` | 会话绝对有效期，单位小时 |
| `--max-upload-mb N` | `0` | 单文件上传上限，单位 MiB；0 表示不限 |
| `--tls-cert FILE` | 无 | TLS 证书链 |
| `--tls-key FILE` | 无 | TLS 私钥，必须和证书同时提供 |
| `--quiet` | 关闭 | 只输出警告和错误 |

## 功能

- 登录后浏览共享目录；面包屑导航，浏览器前进/后退可用。
- 密码登录一次后，浏览器登记公钥，之后挑战-应答免密登录（见「免密登录（公钥）」）。
- 点击可预览的文件名，在站内弹窗查看图片、视频、音频、PDF 和纯文本；其他文件点击后仍直接下载。
- 预览弹窗底部提供「Previous / Next」按钮和序号，也可用键盘左右方向键，按当前目录的排序和过滤顺序切换可预览文件。
- 点击 Name、Size、Modified 表头排序，再次点击反向；文件夹始终排在文件前面，排序在切换目录后保留。
- 左侧「Quick access」面板：用文件或文件夹行内的图钉按钮固定，点面板条目直接跳转或预览。配置保存在服务端，按登录用户区分，换浏览器或设备后仍然有效。
- 文件名过滤，只作用于当前目录。
- 下载大文件时流式传输，支持单段 `Range` 请求、`ETag` 和 `304 Not Modified`。
- 拖放或选择多个文件上传；逐个显示进度，失败项保留原因。
- 同名文件默认跳过；界面会先询问是否覆盖。
- 上传内容直接写入目标目录内的临时文件，完成后原子替换，不会把整个文件读进内存。
- 可新建文件夹。
- 亮色/暗色主题跟随系统，移动端布局可用。

### 预览类型

| 类型 | 扩展名 |
|---|---|
| 图片 | `avif` `bmp` `gif` `ico` `jpeg` `jpg` `png` `svg` `webp` |
| 视频 | `m4v` `mov` `mp4` `ogv` `webm` |
| 音频 | `aac` `flac` `m4a` `mp3` `oga` `ogg` `opus` `wav` `weba` |
| PDF | `pdf` |
| 文本 / 源码 | `adoc` `asm` `bash` `bat` `bib` `c` `cc` `cfg` `cmd` `conf` `cpp` `cs` `css` `csv` `cxx` `diff` `env` `fish` `go` `h` `hh` `hpp` `htm` `html` `ini` `java` `js` `json` `jsonl` `jsx` `kt` `kts` `less` `log` `lua` `m` `markdown` `md` `mjs` `patch` `php` `pl` `ps1` `py` `r` `rb` `rst` `rs` `sass` `scala` `scss` `sh` `sql` `srt` `swift` `tex` `toml` `ts` `tsv` `tsx` `txt` `vb` `vtt` `vue` `xml` `yaml` `yml` `zsh` |

扩展名按不区分大小写匹配。HTML 和 Markdown 只按源码显示。其他扩展名点击文件名后直接下载。

## 安全模型

- **单账号，无角色。** 所有已登录客户端拥有同一套权限，能看到整个 `--root`。
- 密码使用 PBKDF2-HMAC-SHA256，600,000 次迭代，加 16 字节随机盐；进程只保留摘要。
- 会话令牌由 `secrets.token_urlsafe(32)` 生成，服务端只保存令牌的 SHA-256；绝对过期，不续期。
- 登录失败限流：同一来源 IP 在 5 分钟内失败 8 次后，返回 `429`，直到窗口滑出。密码登录和
  公钥验签失败共用同一计数。
- 会话 Cookie 设置 `HttpOnly`、`SameSite=Strict`、`Path=/`，TLS 模式下再加 `Secure`。
- 所有写操作（登录、退出、新建目录、上传、公钥登记与移除）都要求请求头
  `X-LanVault-Request: 1`，结合 `SameSite=Strict` 防止跨站请求伪造。
- 公钥登录使用一次性挑战：32 字节随机数，60 秒过期，绑定客户端 IP，验证后立即作废；
  服务端通过系统 `openssl` 验签，公钥以 PEM 存于 `0600` 的 JSON 文件。浏览器侧私钥
  由 WebCrypto 生成且不可导出，泄露站点数据不会直接暴露可用于其他服务的密钥材料。
- 路径在解析后用真实路径检查必须位于共享目录内；指向目录外的符号链接不会出现在列表里，
  也无法下载或预览。
- 返回 `CSP`、`X-Content-Type-Options: nosniff` 等安全响应头。普通页面和 API 使用
  `X-Frame-Options: DENY`；同源预览响应改为 `SAMEORIGIN`，以便 PDF 在弹窗内显示。
- 预览端点只对白名单类型返回 `inline`；文本和代码统一使用 `text/plain`，避免把上传的 HTML
  当网页执行。SVG 预览使用沙箱 CSP，PDF 预览只允许同源页面嵌入。
- 新上传文件权限为 `0644`；覆盖已有文件时保留原文件权限。覆盖通过临时文件加
  `os.replace` 完成。
- 上传文件名不包含路径分隔符，控制字符和超过 255 字节的文件名会被拒绝。
- 快捷访问按登录用户保存在 `--state-file` 指向的 JSON 文件中，文件权限为 `0600`，写入通过
  临时文件加 `os.replace` 完成。文件损坏时忽略内容并重新开始，不影响服务启动。
- 不记录查询字符串，日志不含密码或会话令牌。

### 已知限制

- 没有删除、重命名、移动文件或文件夹的接口。
- 没有多用户、配额、按目录授权。
- 上传不支持断点续传；一次请求对应一个完整文件。
- 拖放只上传文件，不会递归上传整个目录。
- 下载只支持单个字节范围；多段 `Range` 返回 `416`。
- 预览只覆盖白名单扩展名：常见图片、视频、音频、PDF 和文本/代码文件。HTML、Markdown
  等文本文件按源码显示，不作为网页渲染。SVG 通过 `<img>` 显示，并附带禁用脚本的 CSP。
- 视频和音频能否播放取决于浏览器支持的容器与编码；不支持时界面会提示无法播放。
- 文本预览最多读取前 1 MiB，底部会提示被截断；图片、音视频和 PDF 不截断。
- PDF 预览依赖浏览器自带的 PDF 阅读器。
- 快捷访问每个用户最多 64 项。固定的条目被删除后仍显示在面板中，点击时提示不存在，
  需要手动移除。
- 服务不持久化会话；重启后所有客户端需要重新登录（已登记的公钥不丢，重启后免密登录仍然可用）。
- 免密公钥登录需要安全上下文（HTTPS 或 localhost）与系统 `openssl`；纯 HTTP 跨设备访问不可用。
- 以服务进程的系统用户身份读写文件，遵守该用户的操作系统权限。
- 界面使用 `<dialog>`、`color-mix()` 和原生 ES2020 语法，需要较新的 Firefox、Chrome、Edge 或 Safari。
  老旧浏览器仍可通过 HTTP API 使用，但不保证面板样式。

## HTTP API

除 `POST /api/login`、`POST /api/auth/challenge`、`POST /api/auth/verify` 外，所有 `/api/*`
端点都要求有效会话 Cookie。写请求额外要求 `X-LanVault-Request: 1`。路径参数都是相对共享
根目录的 POSIX 路径，根目录用空字符串表示。

| 方法和路径 | 说明 |
|---|---|
| `POST /api/login` | JSON `{"username": "...", "password": "..."}`；成功设置会话 Cookie |
| `GET /api/session` | 返回当前用户、共享根名称和 `publicKeyAuth`（openssl 是否可用） |
| `POST /api/logout` | 注销当前会话 |
| `POST /api/auth/challenge` | 无需会话；返回 `{"id", "nonce"}`，nonce 为 32 字节随机数的十六进制 |
| `POST /api/auth/verify` | 无需会话；JSON `{"id", "signature"}`，签名 Base64；成功设置会话 Cookie |
| `GET /api/auth/keys` | 返回当前用户已登记的公钥列表（id、指纹、标签、时间） |
| `POST /api/auth/keys` | JSON `{"publicKey": "-----BEGIN PUBLIC KEY-----..."}`；登记公钥，重复登记幂等 |
| `POST /api/auth/keys/remove` | JSON `{"id": "KEY_ID"}`；移除公钥，返回 `204` |
| `GET /api/list?path=DIR` | 列出目录 |
| `GET/HEAD /api/download?path=FILE` | 下载文件，支持单段 `Range` |
| `GET/HEAD /api/preview?path=FILE` | 内联预览白名单内的文件，支持单段 `Range` |
| `PUT /api/upload?path=DIR&name=FILE&overwrite=0` | 原始请求体即文件内容，必须带 `Content-Length` |
| `POST /api/mkdir` | JSON `{"path": "PARENT", "name": "NAME"}` |
| `GET /api/quick-access` | 返回当前用户的快捷访问条目 |
| `POST /api/quick-access` | JSON `{"path": "ITEM"}`；加入快捷访问，重复加入返回 `200` |
| `POST /api/quick-access/remove` | JSON `{"path": "ITEM"}`；移除，返回剩余条目 |

登录并上传示例：

```bash
curl -c cookies.txt \
  -H 'X-LanVault-Request: 1' \
  -H 'Content-Type: application/json' \
  --data '{"username":"alice","password":"replace-this"}' \
  http://192.0.2.1:8080/api/login

curl -b cookies.txt -H 'X-LanVault-Request: 1' \
  -X PUT --data-binary @file.bin \
  'http://192.0.2.1:8080/api/upload?path=&name=file.bin&overwrite=0'
```

示例中的密码会进入 shell 历史记录。日常使用请通过网页登录，不要把真实密码写进命令。

## 测试

```bash
cd ~/projects/lanvault
python3 -m unittest discover -s tests -v
```

测试只监听 `127.0.0.1` 的随机端口，覆盖认证、登录限流、CSRF 请求头、目录浏览、Range 下载、
内联预览与类型白名单、上传/覆盖、上传大小限制、路径穿越和符号链接逃逸、快捷访问的持久化与
用户隔离，以及公钥登记、挑战-应答登录、签名与挑战的重放拒绝、移除公钥和缺少 openssl 时的降级
（公钥相关用例需要系统安装 `openssl`，缺失时自动跳过）。

## 文件结构

```
lanvault.py          服务端、路由、认证、公钥验签、CLI
web/index.html       页面结构
web/style.css        亮色/暗色样式和响应式布局
web/app.js           登录、免密公钥、浏览、下载、预览、上传、新建目录逻辑
web/favicon.svg      图标
tests/test_lanvault.py
```

## systemd 示例（用户级）

不需要 sudo，服务以当前用户运行。把下面内容保存为
`~/.config/systemd/user/lanvault.service`：

```ini
[Unit]
Description=LanVault file server

[Service]
WorkingDirectory=%h/projects/lanvault
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 %h/projects/lanvault/lanvault.py \
  --root %h/share \
  --bind 0.0.0.0 \
  --port 8080 \
  --user alice \
  --password-file %h/.config/lanvault/password
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
```

- `%h` 展开为当前用户的家目录。
- 监听地址和端口通过 `--bind`、`--port` 配置；`--bind 0.0.0.0` 表示监听所有网卡，
  只允许本机访问时改为 `127.0.0.1`。
- 用户名和密码通过 `--user` 与 `--password-file` 配置，见「密码来源」一节。

启用和管理：

```bash
systemctl --user daemon-reload
systemctl --user enable --now lanvault
systemctl --user status lanvault
journalctl --user -u lanvault -f
```

默认情况下，用户级服务只在你登录后运行。若希望开机后未登录也能自启，执行：

```bash
loginctl enable-linger $USER
```

修改 `.service` 文件后需要重新执行 `systemctl --user daemon-reload`。修改密码后执行
`systemctl --user restart lanvault` 生效；重启会使所有已登录会话失效。
