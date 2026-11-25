# 敏感数据识别与脱敏规则参考手册

本文档提供 `excel-data-masking` 内置的 11 类敏感数据类型、8 种脱敏规则参数定义及 `config.json` 完整配置示例。仅在需要自定义规则、调整参数或解释识别逻辑时按需查阅。

---

## 1. 内置敏感数据类型（11 类）

识别引擎采用**表头语义评分（权重 0.4）+ 全列非空内容正则/校验命中率（权重 0.6）**混合判定：
- 综合分 `score >= 0.65` 或内容命中率 `hit_rate >= 0.85` 判定为敏感列；
- 非敏感列若偶发在自由文本中夹带手机/身份证/银行卡/邮箱/固话/IP，会标记 `inline_hint: true`，提示可启用 `inline_text` 规则。

| 类型 ID | 中文名称 | 识别与校验特征 | 默认推荐规则 | 脱敏预览示例 |
| :--- | :--- | :--- | :--- | :--- |
| `phone_cn` | 中国大陆手机号 | 表头关键词 + 11 位手机号正则（含 `+86`/`86-` 可选前缀） | `mask_keep` | `138****5678` |
| `id_card_cn` | 身份证号 | 18 位（含 GB 11643-1999 校验码校验）或 15 位老身份证 | `mask_keep` | `110101********1234` |
| `bank_card` | 银行卡号 | 13~19 位数字 + Luhn 算法校验 | `mask_keep` | `6222************1234` |
| `email` | 电子邮箱 | 标准邮箱格式正则 + 表头关键词 | `mask_keep` | `z***@example.com` |
| `uscc` | 企业统一社会信用代码 | 18 位社会信用代码编码正则与字符集校验 | `mask_keep` | `9111************1X` |
| `ip_address` | IP 地址 | IPv4 / IPv6 格式正则 + 表头关键词 | `mask_keep` | `192.168.*.*` |
| `license_plate` | 车牌号 | 中国大陆蓝牌/绿牌（新能源）车牌正则 | `mask_keep` | `京A***88` |
| `landline` | 固定电话 | 区号 + 号码正则（如 `010-88886666`） | `mask_keep` | `010-****6666` |
| `person_name` | 姓名 / 人名 | 表头强语义（姓名/联系人/法人/持卡人）+ 2~4 字中文人名特征 | `mask_keep` | `张*` / `欧阳**` |
| `address` | 通信地址 | 表头强语义（地址/住址/收货地址）+ 省市区路号结构特征 | `mask_keep` | `北京市海淀区****` |
| `secret` | 密码 / 密钥 / Token | 表头语义（password/pwd/secret/token/key）+ 常见密钥前缀（`sk-`, `AKIA`, `ghp_`, `Bearer `）与高熵特征 | `redact` | `[已脱敏]` |

---

## 2. 内置脱敏规则（8 种）

所有规则均保证**无状态、不可逆、支持多进程并行**。空值（`None` 或纯空白）统一原样保留。

### 2.1 `mask_keep`（保留前后缀掩码）
按敏感类型默认规则保留首尾关键位，中间以 `*` 掩码；也可通过 `params` 显式覆盖保留长度。
- **可选 `params`**：
  - `keep_head` (`int`)：强制保留前 N 个字符。
  - `keep_tail` (`int`)：强制保留后 M 个字符。
  - `mask_char` (`str`, 默认 `"*"`)：掩码替换字符。
- **示例**：
  ```json
  { "rule": "mask_keep", "sensitive_type": "phone_cn", "params": { "keep_head": 3, "keep_tail": 4 } }
  ```

### 2.2 `hash_sha256`（带盐确定性哈希）
对明文执行加盐 SHA-256 哈希，适用于**跨行/跨表需要保持关联一致性（Join / 去重统计）**但不可逆还原的列（如手机号、身份证号、工号）。
- **可选 `params`**：
  - `salt` (`str`)：列级独立盐值；未传时自动回退使用配置顶层的 `global_salt`。
  - `length` (`int`, 默认 `16`)：截取十六进制摘要长度（建议 `12`~`64`）。
  - `prefix` (`str`, 默认 `""`)：输出前缀，例如 `"H_"`。
- **示例**：
  ```json
  { "rule": "hash_sha256", "sensitive_type": "id_card_cn", "params": { "length": 16 } }
  ```

### 2.3 `redact`（全屏蔽占位）
将整列非空值替换为统一占位符，默认用于密码、API Key、Token 等高危凭据列。
- **可选 `params`**：
  - `replacement` (`str`, 默认 `"[已脱敏]"`)：替换后的占位文本。
- **示例**：
  ```json
  { "rule": "redact", "sensitive_type": "secret", "params": { "replacement": "[REDACTED]" } }
  ```

### 2.4 `generalize`（泛化 / 区间化 / 截断）
降低数值、日期或文本精度，保留统计分布特征而隐藏精确个体值。
- **可选 `params`**：
  - `mode` (`str`)：支持 `"date_year"`（仅保留年份）、`"date_ym"`（保留年月 `YYYY-MM`）、`"number_round"`（数值四舍五入或取整）、`"number_bucket"`（按 `bucket` 步长归入区间如 `"10000-20000"`）、`"truncate"`（文本截断前 N 字）。
  - `bucket` (`int | float`)：`number_bucket` 模式下的分桶步长。
  - `precision` (`int`)：`number_round` 保留小数位（可为负数如 `-3` 表示精确到千位；亦兼容 `round_to` 步长）。
  - `max_len` / `max_chars` (`int`)：`truncate` 模式保留字符数。
- **示例**：
  ```json
  { "rule": "generalize", "params": { "mode": "number_bucket", "bucket": 5000 } }
  ```

### 2.5 `regex_replace`（自定义正则替换）
使用用户指定正则表达式匹配并替换单元格内容。
- **必填 `params`**：
  - `pattern` (`str`)：Python 正则表达式。
  - `repl` (`str`, 默认 `"***"`)：替换字符串（支持正则分组反向引用如 `r"\1****\2"`）。
- **示例**：
  ```json
  { "rule": "regex_replace", "params": { "pattern": "(EMP-)(\\d{4})(\\d+)", "repl": "\\1****\\3" } }
  ```

### 2.6 `inline_text`（自由文本内嵌敏感信息清洗）
专门用于“备注 / 工单描述 / 沟通记录”等非结构化文本列，自动扫描文本内部夹带的**手机号、身份证号、银行卡号、邮箱、固话、IPv4**并做局部掩码替换，保留其余正常描述语义。
- **可选 `params`**：
  - `types` (`list[str]`)：限定要清洗的内嵌类型子集；省略时扫描全部默认内嵌类型。
- **示例**：
  ```json
  { "rule": "inline_text", "params": {} }
  ```

### 2.7 `obfuscate`（数据混淆：同长度同格式文本混淆）
对单元格文本执行同长度、同格式混淆：严格保留原始字符串长度、空白及标点/分隔符位置，并按字符类别逐位替换（ASCII/全角数字→数字、大写字母→大写字母、小写字母→小写字母、汉字→常用简体汉字），适用于账套代码、企业名称、工号等需要保留格式结构同时打散真实关联的场景。
- **可选 `params`**：
  - `mode` (`str`, 默认 `"random"`)：混淆模式。默认 `"random"` 每次随机打散关联；可选 `"consistent"` 确定性混淆（按口令/盐值保持同名同混淆）。
  - `salt` (`str`)：列级盐值，仅在 `mode: "consistent"` 时生效；未传时自动回退使用配置顶层的 `global_salt`。
  - `keep_head` (`int`, 默认 `0`)：保留前 N 个字符不混淆。
  - `keep_tail` (`int`, 默认 `0`)：保留后 M 个字符不混淆（当保留总长度达到或超过原串长度时自动夹紧，保证至少 1 个字符被混淆）。
- **示例**：
  ```json
  { "rule": "obfuscate", "params": { "mode": "random", "keep_head": 0, "keep_tail": 0 } }
  ```

### 2.8 `none`（不脱敏，原样保留）
显式标记该列不执行脱敏（原样透传写出）。

---

## 3. `config.json` 配置结构规范

`apply` 命令接受纯结构化 JSON 配置文件（**禁止写入任何原始数据样本**）：

```json
{
  "global_salt": "请替换为本次任务的随机盐值或用户指定盐值",
  "allow_unsalted": false,
  "columns": {
    "手机号": { "rule": "hash_sha256", "sensitive_type": "phone_cn", "params": { "length": 16 } },
    "客户备注": { "rule": "inline_text", "params": {} }
  },
  "sheets": {
    "员工明细": {
      "columns": {
        "身份证号": { "rule": "mask_keep", "sensitive_type": "id_card_cn", "params": {} },
        "银行卡": { "rule": "mask_keep", "sensitive_type": "bank_card", "params": { "keep_head": 4, "keep_tail": 4 } },
        "登录密码": { "rule": "redact", "sensitive_type": "secret", "params": {} },
        "入职日期": { "rule": "generalize", "params": { "mode": "date_ym" } }
      }
    },
    "汇总统计": {
      "columns": {
        "联系电话": { "rule": "none" }
      }
    }
  }
}
```

**优先级说明**：若某 Sheet 内定义了 `sheets.<sheet_name>.columns.<col_name>`，则优先于顶层通用映射 `columns.<col_name>`；未命中任何配置的列默认原样透传（等同于 `none`）。
