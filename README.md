# Excel 数据脱敏技能（`excel-data-masking`）

> **核心承诺**：所有扫描、识别与脱敏计算**100% 在你自己的电脑本地进程完成**，原始表格明文**绝不进入大模型上下文**，也不会上传至任何外部服务器。

---

## 一句话极简用法（不用敲任何命令）

下载 `excel-data-masking.zip` 后，**不需要自己安装软件、不需要解压、更不需要敲任何终端命令**。

直接把压缩包拖进（或发送给）你的 AI 智能体对话框（**Antigravity / Claude Code / Codex / Cursor / Gemini CLI / OpenCode** 均可），复制发送下面这句话即可：

> **“请阅读这个压缩包里的 README.md，帮我自动安装这个脱敏技能并启动本地服务。”**

智能体会自动在后台帮你装好全部环境、部署技能、启动纯本地离线界面并打开浏览器——**全程零手工命令**。

> [!CAUTION]
> **安全铁律**：脱敏时请直接把表格拖进打开的本地浏览器界面，或在对话中**只发本地文件路径**（例如 `D:\data\员工表.xlsx`），**绝不要把表格内容复制粘贴进聊天框**！

---

## 🤖 给 AI 智能体的全自动安装与启动执行协议（Agent Auto-Setup Protocol）

> [!IMPORTANT]
> **对 AI 智能体的强制指令**：
> 当用户向你发送本压缩包或要求安装本技能时，**严禁要求用户自己打开终端、安装依赖或运行任何手工命令！** 你必须主动、静默地按顺序完成以下 4 个动作，直接把可用的本地浏览器链接交给用户。

### 第 1 步：解压压缩包到临时目录（如尚未解压）
- 若用户直接提供了 `.zip` 压缩包（例如 `excel-data-masking.zip`），请使用跨平台命令将其解压到系统临时目录（Windows 上可用 `python` 或 `py -3`）：
  ```text
  python3 -m zipfile -e "<zip_path>" "<temp_dir>"
  ```
- 若当前读取的已是解压后的 `excel-data-masking` 文件夹，则直接跳过此步。

### 第 2 步：运行内置跨平台全自动安装脚本
- 执行压缩包内置的 `auto_install.py`（Windows 上若无 `python3`，请改用 `python` 或 `py -3`）：
  ```text
  python3 "<解压目录>/excel-data-masking/scripts/auto_install.py"
  ```
- 脚本使用纯 Python 标准库编写，会自动完成以下工作并向标准输出打印 JSON：
  1. 自动探测本机已安装的智能体平台目录（Antigravity、Claude Code、Codex、Cursor、Gemini CLI、OpenCode，未探测到时自动安装到 `~/.agents/skills/excel-data-masking/`）并安全复制技能文件。
  2. 自动准备独立运行环境（优先预热 `uv` 缓存；无 `uv` 时自动创建本地 `.venv` 并安装高性能解析库；纯离线内网自动检测并回退本地 Python 环境）。
  3. 输出包含 `status`、`installed_paths`、`primary_skill_dir`、`runtime_mode`、`launch_args` 与 `launch_command` 的标准 JSON。

### 第 3 步：以守护进程在后台启动本地服务
- 读取上一步 JSON 输出中的 `launch_command`（即使用已就绪环境执行 `"<已安装目录>/scripts/mask_cli.py" ui`）。
- **必须以非阻塞的后台守护进程（Daemon / Background Process）方式启动**该命令（切勿在前台同步阻塞等待退出）。

### 第 4 步：获取本地 URL 并交付给用户
- 从后台进程的标准输出中捕获类似 `http://127.0.0.1:<端口>/` 的本地访问地址（`ui` 模式也会自动尝试打开系统默认浏览器）。
- 将该 `http://127.0.0.1:<端口>/` 链接清晰展示给用户，并向用户确认：
  1. 技能与纯本地离线 Web 脱敏服务**已在你的本机安全启动**（零外网请求、仅监听 `127.0.0.1`）。
  2. 可直接点击链接在浏览器中拖拽 Excel/CSV 文件完成脱敏；**提醒用户切勿把原表文本粘贴进聊天框**。
  3. 日后如需直接在对话中批量处理，只需发送本地文件路径（如 `用 excel-data-masking 脱敏 <文件路径>`）即可，无需再次安装。

---

## 附录：功能与配置速查（供需要了解详情的人查阅）

### 1. 核心特性与安全保障
- **零外部明文泄密**：对话模式仅传递路径与脱敏后预览；Web 向导模式完全离线运行于 `127.0.0.1`（无外网/CDN 请求，带随机令牌校验）。
- **20 万行级高并发**：内置流式读写与多进程并发引擎，支持 `.xlsx`、`.xlsm`、`.xls`、`.xlsb` 与 `.csv`。
- **绝不覆盖原文件**：默认输出为同目录 `<原文件名>_masked.xlsx`（或 `_masked.csv`），原始文件完好无损。

### 2. 支持的智能体平台与自动安装目录对照表

`auto_install.py` 会自动扫描并同步安装到本机以下已存在的平台目录（亦可传入 `--target all` 或逗号分隔平台名如 `--target antigravity,claude`）：

| 智能体平台 | 全局技能目录（macOS / Linux） | 全局技能目录（Windows） | 项目级目录（工作区根目录下） |
| :--- | :--- | :--- | :--- |
| **Antigravity** | `~/.gemini/config/skills/excel-data-masking/` | `%USERPROFILE%\.gemini\config\skills\excel-data-masking\` | `.agents/skills/excel-data-masking/` |
| **Claude Code** | `~/.claude/skills/excel-data-masking/` | `%USERPROFILE%\.claude\skills\excel-data-masking\` | `.claude/skills/excel-data-masking/` |
| **Codex** | `~/.codex/skills/excel-data-masking/` | `%USERPROFILE%\.codex\skills\excel-data-masking\` | `.agents/skills/excel-data-masking/` |
| **Cursor** | `~/.cursor/skills/excel-data-masking/` | `%USERPROFILE%\.cursor\skills\excel-data-masking\` | `.cursor/skills/excel-data-masking/` |
| **Gemini CLI** | `~/.gemini/skills/excel-data-masking/` | `%USERPROFILE%\.gemini\skills\excel-data-masking\` | `.gemini/skills/excel-data-masking/` |
| **OpenCode** | `~/.config/opencode/skills/excel-data-masking/` | `%USERPROFILE%\.config\opencode\skills\excel-data-masking\` | `.opencode/skills/excel-data-masking/` |
| **通用保底路径** | `~/.agents/skills/excel-data-masking/` | `%USERPROFILE%\.agents\skills\excel-data-masking\` | `.agents/skills/excel-data-masking/` |

### 3. 内置 8 种脱敏规则速查表

| 规则标识 | 业务中文名称 | 通俗说明与适用场景 | 脱敏前后示例 |
| :--- | :--- | :--- | :--- |
| `mask_keep` | **星号遮挡（保留首尾）** | 保留首尾关键字符、中间用 `*` 遮挡，最常用的展示型脱敏 | `13812345678` → `138****5678` |
| `hash_sha256` | **加密代号替换** | 加盐不可逆摘要；相同口令下同值结果一致，适合跨表 Join / 去重统计 | `13812345678` → `a3f9c01e8b2d4712` |
| `redact` | **整格替换为固定文字** | 整格替换为统一占位符，用于密码、API Key、Token 等高危凭据 | `sk-9f8e7d6c5b` → `[已脱敏]` |
| `generalize` | **模糊化处理** | 保留统计趋势但隐藏精确值（日期取年月、数值分桶/取整、文本截断） | `13500` → `10000-15000`；`2023-05-18` → `2023-05` |
| `regex_replace` | **按格式局部替换** | 按自定义正则精准替换指定片段 | `EMP-202301` → `EMP-****01` |
| `inline_text` | **长文本隐私清洗** | 专门处理“备注/沟通记录”列，保留正常描述文字，仅遮挡文中夹带的敏感信息 | `联系张某13812345678确认` → `联系张某138****5678确认` |
| `obfuscate` | **数据混淆（同长度同格式）** | 严格保留原长度、标点与字符类别（数字换数字、字母换字母、汉字换汉字）；默认每次随机打散关联，支持按口令同名同混淆及保留首尾位数 | `1000F100` → `7482K915`；`中国宝武-单体` → `华盛瑞泰-云达` |
| `none` | **不脱敏（原样保留）** | 显式标记该列无需处理，原样输出 | `研发部` → `研发部` |

### 4. 自动识别的 11 类敏感信息速查表

| 自动识别类型 | 涵盖字段举例 | 默认推荐规则 | 脱敏预览示例 |
| :--- | :--- | :--- | :--- |
| **中国大陆手机号**（`phone_cn`） | 手机、联系电话、Mobile（支持 `+86` 前缀） | `mask_keep` | `138****5678` |
| **身份证号**（`id_card_cn`） | 18 位（带校验码与日期校验）及 15 位身份证号 | `mask_keep` | `110101********1234` |
| **银行卡号**（`bank_card`） | 13~19 位银行卡号（经 Luhn 算法校验） | `mask_keep` | `6222************1234` |
| **电子邮箱**（`email`） | 个人与企业邮箱地址 | `mask_keep` | `z***@example.com` |
| **企业统一社会信用代码**（`uscc`） | 18 位社会信用代码 | `mask_keep` | `9111************1X` |
| **IP 地址**（`ip_address`） | IPv4 / IPv6 网络地址 | `mask_keep` | `192.168.*.*` |
| **车牌号**（`license_plate`） | 蓝牌、新能源绿牌等中国大陆车牌 | `mask_keep` | `京A***88` |
| **固定电话**（`landline`） | 带区号座机号（如 `010-88886666`） | `mask_keep` | `010-****6666` |
| **姓名 / 人名**（`person_name`） | 姓名、联系人、法人、持卡人等（自动排除“法人标识”等是/否标志列） | `mask_keep` | `张*` / `欧阳**` |
| **通信地址**（`address`） | 家庭住址、收货地址、办公地址 | `mask_keep` | `北京市海淀区****` |
| **密码 / 密钥 / Token**（`secret`） | 密码、Secret、API Key、Access Token 等 | `redact` | `[已脱敏]` |

### 5. 常见说明（无 Python / 内网离线 / 格式说明）

1. **如果公司电脑尚未安装 Python 怎么办？**
   - 智能体执行 `auto_install.py` 时若发现缺少 Python 3.11+ 或 `uv`，可由智能体直接帮你安装（或你在 Windows 微软商店搜索安装 Python 3.12 / 使用 `winget install Python.Python.3.12`；macOS 可使用 `brew install uv` 或安装 Python 3.12），装好后再让智能体继续即可。
2. **完全断网的内网环境能用吗？**
   - 可以。内网机器只要已有 Python 3.11+（预装 `python-calamine` / `xlsxwriter` 或基础 `openpyxl` / `xlrd`），`auto_install.py` 会自动跳过外网拉包并回退到本地 Python 模式，全部 `inspect`、`apply` 与 `ui` 功能 100% 离线可用（无任何外网或 CDN 请求）。
3. **老格式 `.xls` / `.xlsm` / `.xlsb` 输出与样式说明**：
   - 为支持 20 万行级高并发流式处理并彻底清除公式残留明文，`.xls` / `.xlsm` / `.xlsb` 脱敏结果统一输出为标准 `_masked.xlsx`；`.csv` 输出为带 BOM 的 UTF-8-SIG（Excel 打开不乱码）。输出保留全部 Sheet、表头与单元格值（公式写出计算缓存值），不保留字体颜色、边框样式与动态公式。
4. **日常对话脱敏方式（进阶）**：
   - 技能安装完成后，除使用本地 Web 界面外，你也可以直接对智能体说：`请用 excel-data-masking 脱敏 "D:\财务 报表\2026员工明细.xlsx"`（支持含中文和空格的路径），智能体会本地扫描全列并返回脱敏预览供你确认。
