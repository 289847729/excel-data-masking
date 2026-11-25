"""Sensitive data detection and stateless masking rules for Excel/CSV data.

All functions and rule handlers in this module are stateless and pickle-safe
for multiprocessing workers. Zero raw plaintext values are exposed in metadata
recommendations or sanitized error messages.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import math
import random
import re
import secrets
from functools import lru_cache
from typing import Any

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

RULE_TYPES: set[str] = {
    "mask_keep",
    "hash_sha256",
    "redact",
    "generalize",
    "regex_replace",
    "inline_text",
    "obfuscate",
    "none",
}

SENSITIVE_TYPES: dict[str, dict[str, str]] = {
    "phone_cn": {
        "label": "手机号",
        "default_rule": "mask_keep",
        "category": "format",
        "description": "中国大陆11位手机号码",
    },
    "id_card_cn": {
        "label": "身份证号",
        "default_rule": "mask_keep",
        "category": "format",
        "description": "中国大陆15位或18位居民身份证号（含校验码验证）",
    },
    "bank_card": {
        "label": "银行卡号",
        "default_rule": "mask_keep",
        "category": "format",
        "description": "13-19位银行卡号（含Luhn校验）",
    },
    "email": {
        "label": "电子邮箱",
        "default_rule": "mask_keep",
        "category": "format",
        "description": "标准电子邮件地址",
    },
    "uscc": {
        "label": "统一社会信用代码",
        "default_rule": "mask_keep",
        "category": "format",
        "description": "18位企业统一社会信用代码",
    },
    "ip_address": {
        "label": "IP地址",
        "default_rule": "mask_keep",
        "category": "format",
        "description": "IPv4或IPv6网络地址",
    },
    "license_plate": {
        "label": "车牌号",
        "default_rule": "mask_keep",
        "category": "format",
        "description": "中国大陆传统及新能源机动车号牌",
    },
    "landline": {
        "label": "固定电话",
        "default_rule": "mask_keep",
        "category": "format",
        "description": "中国大陆区号固话及400/800热线",
    },
    "person_name": {
        "label": "姓名",
        "default_rule": "mask_keep",
        "category": "semantic",
        "description": "个人真实姓名或联系人姓名",
    },
    "address": {
        "label": "通信地址",
        "default_rule": "mask_keep",
        "category": "hybrid",
        "description": "省市区街道门牌等详细居住或收货地址",
    },
    "secret": {
        "label": "密钥/口令",
        "default_rule": "redact",
        "category": "hybrid",
        "description": "密码、API Key、访问令牌及高熵密钥串",
    },
}

_SEMANTIC_TYPES = {"person_name", "address", "secret"}
_INLINE_HINT_TYPES = {
    "phone_cn",
    "id_card_cn",
    "bank_card",
    "email",
    "landline",
    "ip_address",
}

# ---------------------------------------------------------------------------
# Precompiled regex patterns
# ---------------------------------------------------------------------------

_RE_PHONE_CN = re.compile(r"^(?:\+?86[- ]?)?(1[3-9]\d{9})$")
_RE_ID_CARD_18 = re.compile(
    r"^([1-9]\d{5})((?:19|20)\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}([0-9Xx])$"
)
_RE_ID_CARD_15 = re.compile(
    r"^([1-9]\d{5})(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}$"
)
_RE_BANK_DIGITS = re.compile(r"^[1-9]\d{12,18}$")
_RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_RE_USCC = re.compile(r"^[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}$")
_RE_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
_RE_PLATE = re.compile(
    r"^[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领]"
    r"[A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳]$"
)
_RE_LANDLINE = re.compile(
    r"^(?:0\d{2,3}[- ]\d{7,8}(?:-\d{1,6})?|\(0\d{2,3}\)\d{7,8}|[48]00[- ]?\d{3}[- ]?\d{4})$"
)
_RE_ADDRESS = re.compile(
    r"^(?=.*(?:省|自治区|市|区|县|旗|镇|乡))"
    r"(?=.*(?:路|街|道|巷|弄|村|区|苑|大厦|广场|号|栋|单元|室)).{6,}$"
)
_RE_SECRET_PREFIX = re.compile(
    r"^(?:"
    r"sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{10,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9_]{16,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{12,}|"
    r"AIza[0-9A-Za-z_-]{28,}|"
    r"glpat-[A-Za-z0-9_-]{16,}|"
    r"(?:npm|pypi)-[A-Za-z0-9_-]{16,}|"
    r"Bearer\s+[A-Za-z0-9._-]{12,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")$"
)
_RE_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_RE_NON_ASCII_OR_SPACE = re.compile(r"[\s\u4e00-\u9fff]")

# Inline scanning patterns (strict boundaries)
_RE_INLINE_ID_18 = re.compile(
    r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?![0-9A-Za-z])"
)
_RE_INLINE_BANK = re.compile(r"(?<!\d)[1-9]\d{12,18}(?!\d)")
_RE_INLINE_ID_15 = re.compile(
    r"(?<!\d)[1-9]\d{5}\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}(?!\d)"
)
_RE_INLINE_PHONE = re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")
_RE_INLINE_LANDLINE = re.compile(
    r"(?<!\d)(?:0\d{2,3}-\d{7,8}(?:-\d{1,6})?|[48]00-\d{3}-\d{4})(?!\d)"
)
_RE_INLINE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_RE_INLINE_IPV4 = re.compile(
    r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)"
)

# Generalize & address helpers
_RE_DATE_YMD = re.compile(
    r"^\s*(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[T\s]\d{1,2}:\d{2}(?::\d{2})?)?\s*$"
)
_RE_ADDR_PREFIX = re.compile(
    r"^((?:[^省市区县]{1,8}(?:省|自治区|特别行政区))?"
    r"(?:[^市区县]{1,10}市)?"
    r"(?:[^市区县]{1,10}(?:区|县|旗))?)"
)

# Error sanitization patterns
_RE_ERR_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_RE_ERR_SECRET = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{6,}|(?:AKIA|ASIA)[0-9A-Z]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|"
    r"Bearer\s+[A-Za-z0-9._-]{6,})"
)
_RE_ERR_IPV4 = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_RE_ERR_LONG_NUM = re.compile(r"\d{5,}")
_RE_ERR_SINGLE_QUOTED = re.compile(r"'[^'\n]{5,}'")
_RE_ERR_DOUBLE_QUOTED = re.compile(r'"[^"\n]{5,}"')

# ---------------------------------------------------------------------------
# Header keyword scoring tables
# ---------------------------------------------------------------------------

# (exact_cn_or_en_keywords, partial_cn_or_token_keywords, negative_substrings)
_HEADER_RULES: dict[str, tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "phone_cn": (
        ("手机号", "手机号码", "移动电话", "联系电话", "手机", "mobile", "mobile_phone", "cellphone", "phone_number", "telphone"),
        ("电话", "phone", "tel", "cell", "contact_no"),
        ("固定", "座机", "landline", "传真", "fax"),
    ),
    "id_card_cn": (
        ("身份证", "身份证号", "身份证号码", "证件号码", "居民身份证", "id_card", "idcard", "citizen_id", "identity_no", "identity_card"),
        ("证件号", "证件", "identity"),
        ("银行", "bank", "企业", "公司", "税号", "信用代码"),
    ),
    "bank_card": (
        ("银行卡", "银行卡号", "银行账号", "借记卡", "信用卡", "储蓄卡", "bank_card", "bank_account", "card_no", "card_number", "account_no"),
        ("卡号", "账号", "iban", "pan"),
        ("身份证", "id_card", "idcard", "会员", "vip", "工号"),
    ),
    "email": (
        ("邮箱", "电子邮箱", "电子邮件", "邮件地址", "email", "e-mail", "mail", "email_address"),
        ("邮件", "mail"),
        ("邮编", "邮政", "postcode", "zip"),
    ),
    "uscc": (
        ("统一社会信用代码", "社会信用代码", "企业信用代码", "纳税人识别号", "企业税号", "税号", "uscc", "credit_code", "tax_id", "tin"),
        ("信用代码", "纳税人", "统一信用", "tax_no"),
        (),
    ),
    "ip_address": (
        ("ip", "ip地址", "ip_address", "ip_addr", "client_ip", "remote_ip", "login_ip", "server_ip", "ipv4", "ipv6"),
        ("ip_v4", "ip_v6", "host_ip", "src_ip", "dst_ip"),
        ("zip", "ship", "vip", "tip", "equip", "script"),
    ),
    "license_plate": (
        ("车牌", "车牌号", "车牌号码", "号牌", "号牌号码", "license_plate", "plate_no", "plate_number", "car_no", "vehicle_no"),
        ("车辆号牌", "车号", "plate"),
        ("模板", "template"),
    ),
    "landline": (
        ("固话", "固定电话", "座机", "座机号", "办公电话", "客服电话", "传真", "landline", "fixed_phone", "office_phone", "fax"),
        ("座机", "固话", "landline", "fax"),
        ("手机", "mobile"),
    ),
    "person_name": (
        ("姓名", "真实姓名", "全名", "联系人", "收件人", "收货人", "寄件人", "员工姓名", "客户姓名", "户名", "开户名", "法人", "持卡人", "person_name", "full_name", "real_name", "customer_name", "employee_name", "contact_name", "name"),
        ("姓", "联系人", "recipient", "sender", "owner"),
        ("公司", "企业", "单位", "部门", "机构", "商品", "产品", "项目", "文件", "表名", "列名", "品牌", "型号", "城市", "学校", "医院", "渠道", "用户名", "标识", "标记", "状态", "类型", "company", "product", "file", "sheet", "dept", "project", "brand", "city", "username", "flag", "indicator"),
    ),
    "address": (
        ("地址", "住址", "家庭住址", "家庭地址", "联系地址", "通讯地址", "通信地址", "收货地址", "收件地址", "居住地址", "户籍地址", "address", "addr", "home_address", "shipping_address", "mailing_address"),
        ("住址", "地址", "address", "addr", "location"),
        ("ip", "mac", "邮箱", "邮件", "email", "url", "网址", "链接", "web", "server"),
    ),
    "secret": (
        ("密码", "口令", "密钥", "私钥", "公钥", "令牌", "password", "passwd", "pwd", "secret", "api_key", "apikey", "access_key", "secret_key", "private_key", "token", "access_token", "auth_token", "credential"),
        ("秘钥", "密钥", "口令", "密码", "secret", "token", "passwd", "pwd", "credential"),
        ("密码本", "提示", "hint", "规则"),
    ),
}

_FREE_TEXT_HEADER_HINTS = (
    "备注",
    "说明",
    "描述",
    "详情",
    "详细",
    "内容",
    "留言",
    "反馈",
    "意见",
    "日志",
    "工单",
    "摘要",
    "remark",
    "note",
    "notes",
    "comment",
    "comments",
    "desc",
    "description",
    "detail",
    "details",
    "content",
    "message",
    "msg",
    "log",
    "memo",
)

# ---------------------------------------------------------------------------
# Validation helpers (all pure, stateless)
# ---------------------------------------------------------------------------

_ID18_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID18_CHECK_CHARS = "10X98765432"
_DAYS_IN_MONTH = (0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _is_valid_calendar_date(year: int, month: int, day: int) -> bool:
    if not (1 <= month <= 12 and 1 <= day <= _DAYS_IN_MONTH[month]):
        return False
    if month == 2 and day == 29:
        return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
    return True


def _is_valid_id_card_cn(val: str) -> bool:
    m18 = _RE_ID_CARD_18.match(val)
    if m18:
        year = int(m18.group(2))
        month = int(m18.group(3))
        day = int(m18.group(4))
        if not _is_valid_calendar_date(year, month, day):
            return False
        total = sum(int(val[i]) * _ID18_WEIGHTS[i] for i in range(17))
        return val[17].upper() == _ID18_CHECK_CHARS[total % 11]

    m15 = _RE_ID_CARD_15.match(val)
    if m15:
        year = 1900 + int(m15.group(2))
        month = int(m15.group(3))
        day = int(m15.group(4))
        return _is_valid_calendar_date(year, month, day)

    return False


def _luhn_valid(digits: str) -> bool:
    total = 0
    alt = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _is_valid_bank_card(val: str) -> bool:
    compact = val.replace(" ", "").replace("-", "")
    if not _RE_BANK_DIGITS.match(compact):
        return False
    return _luhn_valid(compact)


def _is_valid_uscc(val: str) -> bool:
    if len(val) != 18:
        return False
    upper = val.upper()
    if not _RE_USCC.match(upper):
        return False
    # Exclude pure 18-digit numbers unless valid registry prefix (91/92/93/51/52/53/11-19)
    # and not a valid ID card, preventing 18-digit IDs from colliding with USCC.
    if upper.isdigit():
        if upper[:2] not in {"11", "12", "13", "19", "51", "52", "53", "59", "91", "92", "93"}:
            return False
        if _is_valid_id_card_cn(upper):
            return False
    return True


def _is_valid_ip(val: str) -> bool:
    if _RE_IPV4.match(val):
        return True
    if ":" in val:
        try:
            ipaddress.IPv6Address(val)
            return True
        except ValueError:
            return False
    return False


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_secret(val: str) -> bool:
    if _RE_SECRET_PREFIX.match(val):
        return True
    if len(val) < 20 or _RE_NON_ASCII_OR_SPACE.search(val) or _RE_UUID.match(val):
        return False
    # Exclude normal URLs or paths or pure digits
    if val.startswith(("http://", "https://", "/")) or val.isdigit():
        return False
    has_upper = any("A" <= c <= "Z" for c in val)
    has_lower = any("a" <= c <= "z" for c in val)
    has_digit = any("0" <= c <= "9" for c in val)
    classes = int(has_upper) + int(has_lower) + int(has_digit)
    if classes < 2:
        return False
    return _shannon_entropy(val) >= 3.8


# ---------------------------------------------------------------------------
# Public detection & recommendation APIs
# ---------------------------------------------------------------------------


def score_header(col_name: str) -> dict[str, float]:
    """Score a column header against all 11 sensitive types in [0.0, 1.0]."""
    raw = (col_name or "").strip().lower()
    scores = {stype: 0.0 for stype in SENSITIVE_TYPES}
    if not raw:
        return scores

    compact = re.sub(r"[\s_\-./()（）]+", "", raw)
    tokens = set(re.findall(r"[a-z0-9]+|[\u4e00-\u9fff]+", raw))
    # Also split camelCase tokens if any
    for word in re.findall(r"[A-Za-z]+", col_name or ""):
        for part in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", word):
            tokens.add(part.lower())

    for stype, (exact_kws, partial_kws, neg_kws) in _HEADER_RULES.items():
        if any(neg in raw or neg in tokens for neg in neg_kws):
            continue

        best = 0.0
        for kw in exact_kws:
            kw_compact = kw.replace("_", "").replace("-", "")
            if raw == kw or compact == kw_compact or kw in tokens:
                best = 1.0
                break
            # Only allow substring match for >= 3-char keywords or Chinese >= 2-char keywords
            if (len(kw_compact) >= 3 or any("\u4e00" <= c <= "\u9fff" for c in kw_compact)) and kw_compact in compact:
                best = max(best, 0.88)

        if best < 1.0:
            for kw in partial_kws:
                kw_compact = kw.replace("_", "").replace("-", "")
                if kw in tokens or raw == kw:
                    best = max(best, 0.78)
                elif len(kw_compact) >= 2 and kw_compact in compact:
                    # Avoid short English substring false positives like "ip" in "zip"
                    if kw_compact.isascii() and len(kw_compact) <= 3:
                        continue
                    best = max(best, 0.72)

        scores[stype] = round(best, 4)

    return scores


def detect_value_types(value: Any) -> list[str]:
    """Detect matching sensitive types for a single non-empty cell value."""
    if value is None:
        return []
    val = _to_clean_str(value).strip()
    if not val:
        return []

    hits: list[str] = []

    if _is_valid_id_card_cn(val):
        hits.append("id_card_cn")
    if _RE_PHONE_CN.match(val):
        hits.append("phone_cn")
    if _is_valid_bank_card(val):
        hits.append("bank_card")
    if _RE_EMAIL.match(val):
        hits.append("email")
    if _is_valid_uscc(val):
        hits.append("uscc")
    if _is_valid_ip(val):
        hits.append("ip_address")

    plate_norm = val.replace("·", "").replace("-", "").replace(" ", "")
    if _RE_PLATE.match(plate_norm):
        hits.append("license_plate")

    if _RE_LANDLINE.match(val):
        hits.append("landline")
    if _is_secret(val):
        hits.append("secret")
    if _RE_ADDRESS.match(val):
        hits.append("address")

    return hits


def has_inline_sensitive(value: str) -> bool:
    """Return True if free text embeds phone, ID card, bank card, email, landline, or IPv4."""
    if not value:
        return False
    text = str(value)
    if _RE_INLINE_PHONE.search(text) or _RE_INLINE_EMAIL.search(text) or _RE_INLINE_LANDLINE.search(text):
        return True
    if _RE_INLINE_IPV4.search(text):
        return True
    for m in _RE_INLINE_ID_18.finditer(text):
        if _is_valid_id_card_cn(m.group(0)):
            return True
    for m in _RE_INLINE_ID_15.finditer(text):
        if _is_valid_id_card_cn(m.group(0)):
            return True
    for m in _RE_INLINE_BANK.finditer(text):
        if _is_valid_bank_card(m.group(0)):
            return True
    return False


def recommend_column(
    col_name: str,
    non_null_count: int,
    type_hits: dict[str, int],
    sample_masked: dict[str, list[str]],
    value_kind: str,
    min_len: int,
    max_len: int,
) -> dict[str, Any]:
    """Combine header semantics and full-column scan hits to recommend a masking rule.

    Zero-plaintext invariant: if the column is classified as non-sensitive,
    `masked_previews` is strictly forced to `[]`.
    """
    header_scores = score_header(col_name)

    if non_null_count <= 0:
        return {
            "col_name": col_name,
            "non_null_count": 0,
            "value_kind": value_kind,
            "min_len": min_len,
            "max_len": max_len,
            "is_sensitive": False,
            "sensitive_type": None,
            "sensitive_label": None,
            "confidence": 0.0,
            "header_score": 0.0,
            "hit_rate": 0.0,
            "hits": 0,
            "recommended_rule": "none",
            "masked_previews": [],
            "inline_hint": False,
        }

    best_type: str | None = None
    best_score = -1.0
    best_header = 0.0
    best_rate = 0.0
    best_hits = 0

    for stype in SENSITIVE_TYPES:
        # Single-character values (e.g. "是"/"否") cannot be person names.
        if stype == "person_name" and max_len < 2:
            continue

        h_score = header_scores.get(stype, 0.0)
        hits = type_hits.get(stype, 0)
        hit_rate = min(1.0, hits / non_null_count)
        score = 0.4 * h_score + 0.6 * hit_rate

        # Semantic columns (person_name, address, secret) often have unstructured values
        # that regex alone cannot match; trust strong semantic headers on text columns.
        if stype in _SEMANTIC_TYPES and h_score >= 0.75 and value_kind in ("text", "mixed"):
            if stype == "person_name" and max_len > 40:
                score = min(score, 0.45)
            else:
                score = max(score, round(0.85 * h_score, 4))

        # Tie-break: higher score, then higher hit_rate, then format types over semantic
        is_format = 1 if stype not in _SEMANTIC_TYPES else 0
        best_is_format = 1 if (best_type and best_type not in _SEMANTIC_TYPES) else 0
        if (score, hit_rate, is_format) > (best_score, best_rate, best_is_format):
            best_type = stype
            best_score = score
            best_header = h_score
            best_rate = hit_rate
            best_hits = hits

    is_sensitive = best_type is not None and (best_score >= 0.65 or best_rate >= 0.85)

    if is_sensitive and best_type is not None:
        default_rule = SENSITIVE_TYPES[best_type]["default_rule"]
        previews = list(sample_masked.get(best_type, []))[:3]
        return {
            "col_name": col_name,
            "non_null_count": non_null_count,
            "value_kind": value_kind,
            "min_len": min_len,
            "max_len": max_len,
            "is_sensitive": True,
            "sensitive_type": best_type,
            "sensitive_label": SENSITIVE_TYPES[best_type]["label"],
            "confidence": round(min(1.0, best_score), 4),
            "header_score": round(best_header, 4),
            "hit_rate": round(best_rate, 4),
            "hits": best_hits,
            "recommended_rule": default_rule,
            "masked_previews": previews,
            "inline_hint": False,
        }

    # Non-sensitive column: enforce zero-plaintext invariant (masked_previews = [])
    raw_header = (col_name or "").strip().lower()
    inline_hits_present = any(type_hits.get(t, 0) > 0 for t in _INLINE_HINT_TYPES)
    free_text_header = any(kw in raw_header for kw in _FREE_TEXT_HEADER_HINTS)
    inline_hint = bool(
        value_kind in ("text", "mixed")
        and (inline_hits_present or (free_text_header and max_len >= 12))
    )

    return {
        "col_name": col_name,
        "non_null_count": non_null_count,
        "value_kind": value_kind,
        "min_len": min_len,
        "max_len": max_len,
        "is_sensitive": False,
        "sensitive_type": None,
        "sensitive_label": None,
        "confidence": round(max(0.0, best_score), 4),
        "header_score": round(best_header, 4),
        "hit_rate": round(best_rate, 4),
        "hits": best_hits,
        "recommended_rule": "none",
        "masked_previews": [],
        "inline_hint": inline_hint,
    }


# ---------------------------------------------------------------------------
# Masking rule implementations (stateless, pickle-safe)
# ---------------------------------------------------------------------------


def _to_clean_str(value: Any) -> str:
    """Convert scalar values cleanly; strip trailing .0 on integer floats from Excel."""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    return str(value)


def _mask_span(text: str, keep_head: int, keep_tail: int, mask_char: str = "*") -> str:
    n = len(text)
    if n == 0:
        return text
    if n == 1:
        return mask_char
    head = max(0, keep_head)
    tail = max(0, keep_tail)
    if head + tail >= n:
        # Always guarantee at least 1 masked character so plaintext is never returned as-is.
        if n == 2:
            return text[0] + mask_char
        head = min(head, max(1, n // 3))
        tail = min(tail, max(0, n - head - 1))
    masked_len = max(1, n - head - tail)
    tail_part = text[n - tail :] if tail > 0 else ""
    return text[:head] + (mask_char * masked_len) + tail_part


def _mask_by_type(text: str, sensitive_type: str | None, mask_char: str = "*") -> str:
    if sensitive_type == "phone_cn":
        if text.startswith("+86"):
            prefix = text[:4] if len(text) > 4 and text[3] in (" ", "-") else "+86"
            body = text[len(prefix) :]
            return prefix + _mask_span(body, 3, 4, mask_char)
        return _mask_span(text, 3, 4, mask_char)

    if sensitive_type == "id_card_cn":
        return _mask_span(text, 6, 4 if len(text) >= 18 else 3, mask_char)

    if sensitive_type == "bank_card":
        return _mask_span(text, 4, 4, mask_char)

    if sensitive_type == "email":
        if "@" in text:
            local, domain = text.split("@", 1)
            if len(local) <= 1:
                masked_local = mask_char * 3
            else:
                masked_local = local[0] + (mask_char * max(3, len(local) - 1))
            return f"{masked_local}@{domain}"
        return _mask_span(text, 1, 4, mask_char)

    if sensitive_type == "uscc":
        return _mask_span(text, 4, 4, mask_char)

    if sensitive_type == "ip_address":
        if "." in text and text.count(".") == 3:
            parts = text.split(".")
            return f"{parts[0]}.{parts[1]}.{mask_char * 3}.{mask_char * 3}"
        if ":" in text:
            parts = text.split(":")
            if len(parts) >= 3:
                return f"{parts[0]}:{parts[1]}:{mask_char * 4}:{parts[-1]}"
        return _mask_span(text, 3, 2, mask_char)

    if sensitive_type == "license_plate":
        return _mask_span(text, 2, 1, mask_char)

    if sensitive_type == "landline":
        if "-" in text:
            head, rest = text.split("-", 1)
            return f"{head}-{_mask_span(rest, 0, 2, mask_char)}"
        return _mask_span(text, 3, 2, mask_char)

    if sensitive_type == "person_name":
        if len(text) <= 1:
            return mask_char
        if text.isascii() and " " in text:
            return _mask_span(text, 2, 1, mask_char)
        return text[0] + (mask_char * (len(text) - 1))

    if sensitive_type == "address":
        m = _RE_ADDR_PREFIX.match(text)
        prefix = m.group(1) if m else ""
        if prefix and len(prefix) < len(text):
            return prefix + (mask_char * max(4, min(8, len(text) - len(prefix))))
        keep = min(6, max(2, len(text) // 3))
        return _mask_span(text, keep, 0, mask_char)

    # secret or unknown type
    return _mask_span(text, 2, 2, mask_char)


def _apply_mask_keep(value: Any, sensitive_type: str | None, params: dict[str, Any]) -> str:
    text = _to_clean_str(value).strip()
    mask_char = str(params.get("mask_char", "*")) or "*"
    if "keep_head" in params or "keep_tail" in params:
        keep_head = int(params.get("keep_head", 0))
        keep_tail = int(params.get("keep_tail", 0))
        return _mask_span(text, keep_head, keep_tail, mask_char)
    return _mask_by_type(text, sensitive_type, mask_char)


def _apply_hash_sha256(value: Any, params: dict[str, Any]) -> str:
    text = _to_clean_str(value).strip()
    salt = params.get("salt")
    if salt is None or salt == "":
        salt = params.get("global_salt", "")
    salt_str = "" if salt is None else str(salt)
    length = int(params.get("length", 16))
    length = max(4, min(64, length))
    prefix = str(params.get("prefix", ""))
    payload = f"{salt_str}:{text}" if salt_str else text
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]
    return f"{prefix}{digest}" if prefix else digest


def _apply_generalize(value: Any, params: dict[str, Any]) -> Any:
    mode = str(params.get("mode", "auto"))

    # 1. Date / datetime generalization
    is_date_mode = mode in ("date", "date_year", "date_ym")
    if isinstance(value, (_dt.datetime, _dt.date)) or is_date_mode:
        precision = "year" if mode == "date_year" else str(params.get("precision", "month"))
        if mode == "date_ym":
            precision = "month"
        if isinstance(value, (_dt.datetime, _dt.date)):
            return f"{value.year:04d}" if precision == "year" else f"{value.year:04d}-{value.month:02d}"
        m = _RE_DATE_YMD.match(str(value))
        if m:
            y, mo = int(m.group(1)), int(m.group(2))
            return f"{y:04d}" if precision == "year" else f"{y:04d}-{mo:02d}"

    if mode == "auto" and isinstance(value, str):
        m = _RE_DATE_YMD.match(value)
        if m:
            precision = str(params.get("precision", "month"))
            y, mo = int(m.group(1)), int(m.group(2))
            return f"{y:04d}" if precision == "year" else f"{y:04d}-{mo:02d}"

    # 2. Numeric generalization (bucket or rounding)
    is_num_mode = mode in ("number", "number_round", "number_bucket")
    num_val: float | None = None
    if mode != "truncate":
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            num_val = float(value)
        elif is_num_mode or "bucket" in params or "round_to" in params:
            try:
                num_val = float(str(value).strip())
            except ValueError:
                num_val = None

    if num_val is not None:
        if "bucket" in params and params["bucket"]:
            bucket = float(params["bucket"])
            if bucket > 0:
                low = math.floor(num_val / bucket) * bucket
                high = low + bucket
                if bucket.is_integer():
                    return f"[{int(low)}, {int(high)})"
                return f"[{low:g}, {high:g})"
        round_to = float(params.get("round_to", 0))
        if round_to > 0:
            rounded = math.floor(num_val / round_to) * round_to
            return int(rounded) if round_to.is_integer() else rounded
        if mode == "number_round" or isinstance(params.get("precision"), int):
            ndigits = int(params.get("precision", 0))
            rounded = round(num_val, ndigits)
            return int(rounded) if ndigits <= 0 else rounded
        # Default auto numeric generalization: order-of-magnitude floor
        if abs(num_val) >= 100:
            step = 100.0
        elif abs(num_val) >= 10:
            step = 10.0
        else:
            return f"[{math.floor(num_val)}, {math.floor(num_val) + 1})"
        low = math.floor(num_val / step) * step
        return f"[{int(low)}, {int(low + step)})"

    # 3. Text truncation generalization
    text = _to_clean_str(value).strip()
    max_chars = int(params.get("max_chars", params.get("max_len", 4)))
    max_chars = max(1, max_chars)
    if len(text) <= max_chars:
        keep = max(1, len(text) // 2)
        return text[:keep] + "..."
    return text[:max_chars] + "..."


@lru_cache(maxsize=256)
def _compile_user_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _apply_regex_replace(value: Any, params: dict[str, Any]) -> Any:
    pattern = params.get("pattern")
    if not pattern:
        return value
    repl = str(params.get("repl", "***"))
    compiled = _compile_user_regex(str(pattern))
    return compiled.sub(repl, _to_clean_str(value))


def _apply_inline_text(value: Any, params: dict[str, Any] | None = None) -> Any:
    text = _to_clean_str(value)
    allowed = set((params or {}).get("types") or _INLINE_HINT_TYPES)

    def _sub_id18(m: re.Match[str]) -> str:
        s = m.group(0)
        return _mask_by_type(s, "id_card_cn") if _is_valid_id_card_cn(s) else s

    def _sub_bank(m: re.Match[str]) -> str:
        s = m.group(0)
        return _mask_by_type(s, "bank_card") if _is_valid_bank_card(s) else s

    def _sub_id15(m: re.Match[str]) -> str:
        s = m.group(0)
        return _mask_by_type(s, "id_card_cn") if _is_valid_id_card_cn(s) else s

    if "id_card_cn" in allowed:
        text = _RE_INLINE_ID_18.sub(_sub_id18, text)
    if "bank_card" in allowed:
        text = _RE_INLINE_BANK.sub(_sub_bank, text)
    if "id_card_cn" in allowed:
        text = _RE_INLINE_ID_15.sub(_sub_id15, text)
    if "phone_cn" in allowed:
        text = _RE_INLINE_PHONE.sub(lambda m: _mask_by_type(m.group(0), "phone_cn"), text)
    if "landline" in allowed:
        text = _RE_INLINE_LANDLINE.sub(lambda m: _mask_by_type(m.group(0), "landline"), text)
    if "email" in allowed:
        text = _RE_INLINE_EMAIL.sub(lambda m: _mask_by_type(m.group(0), "email"), text)
    if "ip_address" in allowed:
        text = _RE_INLINE_IPV4.sub(lambda m: _mask_by_type(m.group(0), "ip_address"), text)
    return text


_SYS_RNG = secrets.SystemRandom()
_OBFUSCATE_DIGITS = "0123456789"
_OBFUSCATE_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_OBFUSCATE_LOWER = "abcdefghijklmnopqrstuvwxyz"
_OBFUSCATE_FULLWIDTH_DIGITS = "０１２３４５６７８９"
_OBFUSCATE_CN_POOL = (
    "一二三四五六七八九十"
    "人大小中天地上水火风"
    "云山海川林木花草光明"
    "日月星宇金银铜铁石玉"
    "华盛瑞泰恒达信德利丰"
    "永安康昌兴隆嘉誉博远"
    "宏图伟业骏腾飞启新创"
    "智联科微东升西宁南平"
    "北辰春源秋航夏至冬雪"
    "文武英豪俊杰贤良忠厚"
    "诚松守义勤劳敏慧正清"
    "和睦友爱祥福寿庆荣富"
    "赵钱孙李周吴郑王陈杨"
)


def _pick_other(rng: random.Random, pool: str, ch: str) -> str:
    n = len(pool)
    if n <= 1:
        return pool
    idx = pool.find(ch)
    if idx == -1:
        return pool[rng.randrange(n)]
    pick = rng.randrange(n - 1)
    if pick >= idx:
        pick += 1
    return pool[pick]


def _obfuscate_char(ch: str, rng: random.Random) -> str:
    if "0" <= ch <= "9":
        return _pick_other(rng, _OBFUSCATE_DIGITS, ch)
    if "A" <= ch <= "Z":
        return _pick_other(rng, _OBFUSCATE_UPPER, ch)
    if "a" <= ch <= "z":
        return _pick_other(rng, _OBFUSCATE_LOWER, ch)
    if "\uff10" <= ch <= "\uff19":
        return _pick_other(rng, _OBFUSCATE_FULLWIDTH_DIGITS, ch)
    if "\u4e00" <= ch <= "\u9fff":
        return _pick_other(rng, _OBFUSCATE_CN_POOL, ch)
    if ch.isdigit():
        return _pick_other(rng, _OBFUSCATE_DIGITS, ch)
    if ch.isalpha():
        pool = _OBFUSCATE_UPPER if ch.isupper() else _OBFUSCATE_LOWER
        return _pick_other(rng, pool, ch)
    return ch


def _apply_obfuscate(value: Any, params: dict[str, Any] | None = None) -> Any:
    """Obfuscate text while preserving length, punctuation, and per-character class."""
    if value is None:
        return value
    if isinstance(value, str) and value.strip() == "":
        return value

    text = _to_clean_str(value)
    n = len(text)
    if n == 0:
        return value

    p = params or {}
    raw_head = p.get("keep_head", 0)
    raw_tail = p.get("keep_tail", 0)
    head = max(0, int(raw_head if raw_head not in (None, "") else 0))
    tail = max(0, int(raw_tail if raw_tail not in (None, "") else 0))

    if n == 1:
        head, tail = 0, 0
    elif head + tail >= n:
        if n == 2:
            head, tail = (0, 1) if head == 0 and tail > 0 else (1, 0)
        else:
            head = min(head, max(1, n // 3))
            tail = min(tail, max(0, n - head - 1))

    mode = str(p.get("mode") or "random").strip().lower()
    if mode == "consistent":
        salt = p.get("salt") or p.get("global_salt") or ""
        payload = f"{salt}:{text}" if salt else text
        seed = int.from_bytes(hashlib.sha256(payload.encode("utf-8")).digest(), "big")
        rng: random.Random = random.Random(seed)
    else:
        rng = _SYS_RNG

    end = n - tail
    if head == 0 and end == n:
        return "".join(_obfuscate_char(ch, rng) for ch in text)
    return (
        text[:head]
        + "".join(_obfuscate_char(ch, rng) for ch in text[head:end])
        + text[end:]
    )


def apply_rule(value: Any, rule_spec: dict[str, Any]) -> Any:
    """Apply a single stateless masking rule to a cell value.

    Null or whitespace-only values are returned unchanged.
    """
    if value is None:
        return value
    if isinstance(value, str) and value.strip() == "":
        return value

    rule = (rule_spec or {}).get("rule", "none")
    sensitive_type = (rule_spec or {}).get("sensitive_type")
    params = (rule_spec or {}).get("params") or {}

    if rule == "none":
        return value
    if rule == "mask_keep":
        return _apply_mask_keep(value, sensitive_type, params)
    if rule == "hash_sha256":
        return _apply_hash_sha256(value, params)
    if rule == "redact":
        return str(params.get("replacement", "[已脱敏]"))
    if rule == "generalize":
        return _apply_generalize(value, params)
    if rule == "regex_replace":
        return _apply_regex_replace(value, params)
    if rule == "inline_text":
        return _apply_inline_text(value, params)
    if rule == "obfuscate":
        return _apply_obfuscate(value, params)

    raise ValueError(f"Unsupported masking rule: {rule}")


# ---------------------------------------------------------------------------
# Error sanitization (zero-plaintext boundary)
# ---------------------------------------------------------------------------


def sanitize_error(exc: Exception) -> str:
    """Strip sensitive values (long digits, emails, secrets, quoted strings) from errors."""
    msg = str(exc) if exc is not None else ""
    msg = _RE_ERR_EMAIL.sub("<email_redacted>", msg)
    msg = _RE_ERR_SECRET.sub("<secret_redacted>", msg)
    msg = _RE_ERR_IPV4.sub("<ip_redacted>", msg)
    msg = _RE_ERR_SINGLE_QUOTED.sub("'<redacted>'", msg)
    msg = _RE_ERR_DOUBLE_QUOTED.sub('"<redacted>"', msg)
    msg = _RE_ERR_LONG_NUM.sub("<num_redacted>", msg)
    if len(msg) > 300:
        msg = msg[:300] + "..."
    return f"{type(exc).__name__}: {msg}" if msg else type(exc).__name__
