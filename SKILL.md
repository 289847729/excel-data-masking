---
name: excel-data-masking
description: >-
  Use this skill when the user wants to inspect, mask, anonymize, or sanitize sensitive data in Excel
  (.xlsx, .xlsm, .xls, .xlsb) or CSV spreadsheets locally without leaking any raw sensitive data to
  external LLMs, supporting high-concurrency streaming, automatic column detection, and custom rules.
---

# Excel 数据脱敏技能（零外部泄漏本地高并发）

本技能通过本地 Python 流式高并发引擎完成敏感列识别与不可逆脱敏，确保**任何原始敏感明文绝不进入 LLM 上下文或发往外部模型**。

---

## 1. 安全铁律（违反即安全事故）

> [!CAUTION]
> **严禁用户在聊天框直接粘贴原始表格文本**：表格文本只要在对话中发送，原始明文即已进入外部模型上下文！若用户误贴了原表文本，Agent 必须先坦诚提示该泄密风险，并建议**新开对话仅传本地文件路径**，或改用**100% 离线纯本地 Web 向导**（`ui` 模式）。

1. **严禁用户在聊天框直接粘贴原始表格文本**：引导用户始终仅提供本地文件路径（或直接使用本地 Web 向导），绝不让原表文本经由聊天框进入外部模型上下文。
2. **严禁直接读取用户数据文件**：绝不对待脱敏的 `.xlsx` / `.xlsm` / `.xls` / `.xlsb` / `.csv` 文件调用 `read_file` / `Read` / `view_file` / `cat` / `head` / `tail` / `grep` / `rg` 或任何会在终端/上下文中打印文件内容的自写脚本。
3. **唯一数据入口**：仅将**文件路径**传给 [mask_cli.py](./scripts/mask_cli.py)（通过 `uv run --script` 执行）。
4. **绝不覆盖原文件**：输出文件默认写入 `<原文件名>_masked.xlsx`（或 `_masked.csv`）；CLI 禁止输入输出同路径。
5. **报错不回退查看原文件**：若脚本返回错误 JSON，仅依据已清洗的错误信息排查（如路径、编码、格式或参数问题），**严禁**以“排查错误”为由尝试直接查看原始文件内容。
6. **配置零样本原则**：写入 `config.json` 的内容只能包含 `global_salt`、Sheet 名、列名、规则名与规则参数，严禁附带原始样例。

---

## 2. 标准作业流程

### Step 1：获取文件路径与预期需求
确认用户提供的输入文件（或批量文件路径），以及是否有明确保留/关联需求（例如跨表一致哈希、指定输出路径）。若用户仅给出文件名，先在工作区确认其完整路径（仅限列目录或文件存在性检查，严禁读取文件内容）。

### Step 2：本地全量预检（`inspect`）
调用本地脚本对文件进行全列扫描（禁止只看前几行；请勿使用仅限 Unix 的 Shell 语法或反斜杠换行，保持单行双引号传参以兼容 Windows PowerShell / CMD 与 macOS / Linux）：

```text
uv run --script "<skill_dir>/scripts/mask_cli.py" inspect "<input_path>"
```

常用可选参数：
- `--sheet "<sheet_name>"`：仅扫描指定 Sheet。
- `--chunk-size 20000`：调整流式扫描分块大小。

**解析要点**：
- 脚本输出纯 JSON，敏感列仅包含 `masked_previews`（**已本地脱敏后的最多 3 条预览**）。
- 非敏感列的 `masked_previews` 强制为空列表 `[]`，仅包含 `value_kind`、`min_len`、`max_len` 等结构统计；若 `inline_hint` 为 `true`，说明该自由文本列中偶发夹带敏感片段。

### Step 3：向用户展示方案并确认规则
按 Sheet 将所有列以 Markdown 表格呈现给用户：

| 列名 | 识别类型 | 置信度 / 命中率 | 推荐规则 | 脱敏预览 | 默认勾选 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 手机号 | `phone_cn` | `0.99 / 99.8%` | `mask_keep` | `138****5678` | 是 |
| 备注 | 非敏感 (`text`, 长度 4-80) | 偶发内嵌敏感片段 | `none`（建议可选 `inline_text`） | `[非敏感列，未输出预览]` | 否 |

向用户确认以下决策（支持使用交互多选工具或直接对话确认，同时允许自然语言覆盖）：
1. **待脱敏列勾选**：增加或取消哪些列？
2. **规则覆盖**（内置 8 种脱敏规则）：
   - 是否需要将部分列（如手机号、身份证）由 `mask_keep` 改为 `hash_sha256` 以保持跨行/跨表统计与 Join 一致性？（若启用，确认使用用户指定盐值或自动生成本次任务随机 `global_salt`）
   - 对账套代码、企业名称、工号等需要保留原长度、标点分隔符与字符类别（数字/字母/汉字）但需打散关联的列，是否选用 `obfuscate`（同长度同格式文本混淆，默认每次随机，可选确定性混淆并支持保留首尾位数）？
   - 对 `inline_hint: true` 的备注/描述列，是否开启 `inline_text` 清洗内嵌敏感信息？
   - 如需调整保留位数、分桶泛化、`obfuscate` 参数或自定义正则，按需查阅 [rules-catalog.md](./references/rules-catalog.md)。

### Step 4：生成纯结构化配置并执行高并发脱敏（`apply`）
1. 使用文件写入工具（如 `write_file` / `Write` 等）或脚本安全生成临时 `config.json`（UTF-8 编码，参见 [rules-catalog.md](./references/rules-catalog.md) 的结构规范，可放于系统临时目录或任务临时目录，用后删除）。**禁止**使用 Unix heredoc 命令拼接配置文件，确保 Windows / macOS / Linux 全平台兼容。
2. 执行单行脱敏命令（带双引号以兼容含空格或中文的 Windows / POSIX 路径）：

```text
uv run --script "<skill_dir>/scripts/mask_cli.py" apply "<input_path>" --config "<config_path>"
```

常用可选参数：`--output "<output_path>"`、`--workers 8`、`--chunk-size 15000`。

**格式与保真提示**：
- 引擎采用高速流式纯数据模式：保留全部 Sheet 结构、表头与单元格值（公式输出其计算缓存值），**不保留**原表字体颜色/边框样式/合并单元格/动态公式。
- 老格式 `.xls`（及 `.xlsm` / `.xlsb`）输出统一升级为 `.xlsx`；`.csv` 输出为 UTF-8-SIG 编码。

### Step 5：验证与交付
1. 检查 `apply` 返回 JSON：确认 `status == "ok"`、输出文件已生成、总处理行数与输入行数一致、各列脱敏命中计数符合预期。
2. 删除临时 `config.json`。
3. 向用户交付输出文件可点击路径、处理行数、各列应用规则汇总、是否使用盐值（不泄露盐值本身或按用户要求提示）及耗时。

---

## 3. 纯本地离线 Web 界面模式（零模型接触）

适合最高安全等级或用户不希望任何统计元数据经过对话的场景。启动纯本地 Web 向导后，文件解析、列选择、规则配置与结果导出全程在用户本机浏览器与本地进程内完成，**零模型接触、零外网请求**：

```text
uv run --script "<skill_dir>/scripts/mask_cli.py" ui
```

- **安全与隔离**：仅绑定回环地址 `127.0.0.1`（拒绝非回环绑定），全离线运行、无任何外网或 CDN 请求，且每次会话带随机访问令牌校验。
- **核心能力**：支持拖拽上传 `.xlsx` / `.xlsm` / `.xls` / `.xlsb` / `.csv`（或直接输入本地文件路径），可视化展示全列识别结果与脱敏预览，支持勾选列、切换 8 种脱敏规则（含 `obfuscate` 同长度同格式混淆）、配置盐值与保留位数并一键导出或下载脱敏结果。
- **跨平台通用**：Windows（PowerShell / CMD）、macOS、Linux 均使用上述单行双引号命令；支持可选参数 `--port <端口号>`（默认随机可用端口）与 `--no-browser`（仅输出本地访问 URL）。

---

## 4. 跨平台部署与离线运行说明

- **一键全自动安装（推荐，零手工命令）**：
  - 执行 `python3 "<skill_dir>/scripts/auto_install.py"`（Windows 可用 `python` 或 `py -3`），自动探测并安装至本机已存在的智能体平台目录（Antigravity / Claude Code / Codex / Cursor / Gemini CLI / OpenCode，保底 `~/.agents/skills/excel-data-masking/`），自动准备 `uv` 或独立 `.venv` 依赖环境并输出含 `launch_command` 的 JSON。
- **手动部署路径参考**：
  - Windows 全局技能目录：`%USERPROFILE%\.gemini\config\skills\excel-data-masking\`
  - macOS / Linux 全局技能目录：`~/.gemini/config/skills/excel-data-masking/`
  - 工作区技能目录：`<workspace>/.agents/skills/excel-data-masking/`
- **离线 / 受限内网环境（Windows / Linux / macOS）**：
  - 若环境无法访问外网 `uv` 源，可直接使用本地 `python`（Python >= 3.11）调用脚本：`python "<skill_dir>/scripts/mask_cli.py" inspect "<input_path>"`、`apply` 与 `ui`。
  - 建议在离线环境中预先安装 `python-calamine` 与 `xlsxwriter` 以获得最高流式吞吐；若环境仅预装 `openpyxl` / `xlrd`，脚本会自动平滑降级运行（安全隔离与功能一致，仅超大数据耗时有所增加）。
