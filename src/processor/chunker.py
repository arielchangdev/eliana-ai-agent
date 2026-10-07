"""文本切分器。

切分規則（design.md）：
1. 以 ``\n\n`` 為主要邊界
2. 超過 max_tokens 以句末標點再切
3. 低於 min_tokens 合併鄰段

Property 3 不變量：對於總 token 數 >= min_tokens 的輸入，
產出的每個片段皆滿足 ``min_tokens <= token_count <= max_tokens``。

實作策略（兩階段）：
1. 決定片段數量 ``k`` 並計算「平均目標邊界」，使每段 token 數落在
   [min_tokens, max_tokens]（數學上保證，見 ``_target_boundaries``）。
2. 將每個目標邊界「吸附」至鄰近的句末/段落邊界，但吸附幅度受限，
   確保調整後仍不違反 [min_tokens, max_tokens] 不變量。
"""
from __future__ import annotations

import math

from ..models import TextChunk
from .tokenizer import _TOKEN_RE

# 句末邊界（含中英文標點）
_SENTENCE_END = set(".!?。！？;；")


def _token_spans(text: str) -> list[tuple[int, int]]:
    """回傳每個 token 的 (start, end) 字元 offset。"""
    return [(m.start(), m.end()) for m in _TOKEN_RE.finditer(text)]


def _is_boundary_token(text: str, span: tuple[int, int]) -> bool:
    """判斷 token 是否為句末標點，或其後緊接換行/段落。"""
    tok = text[span[0]:span[1]]
    if tok and tok[-1] in _SENTENCE_END:
        return True
    tail = text[span[1]:span[1] + 2]
    return "\n" in tail


def _target_boundaries(total: int, min_tokens: int, max_tokens: int) -> list[int]:
    """回傳理想的切分邊界（token 索引），保證每段長度落在 [min, max]。

    邊界為「下一段起點」的 token 索引列表，不含 0 與 total 兩端點以外的
    重複。回傳的相鄰邊界差（含 0 與 total）皆介於 [min_tokens, max_tokens]。
    """
    # 片段數量：至少要 ceil(total/max) 段才不會有段超過 max
    k = max(1, math.ceil(total / max_tokens))
    # 若段數過多導致每段低於 min，減少段數
    while k > 1 and total / k < min_tokens:
        k -= 1

    # 平均分配，餘數平均散佈到前面幾段
    base = total // k
    rem = total % k
    boundaries: list[int] = []
    acc = 0
    for idx in range(k):
        size = base + (1 if idx < rem else 0)
        acc += size
        if idx < k - 1:  # 最後一段的結尾即 total，不列入
            boundaries.append(acc)
    return boundaries


def chunk_text(
    text: str, min_tokens: int = 256, max_tokens: int = 1024
) -> list[TextChunk]:
    """將文本切分為 token 數介於 [min_tokens, max_tokens] 的片段。

    對於總 token 數 < min_tokens 的短文本，回傳單一片段（可能小於
    min_tokens）；此為無法滿足下限的合理退化情形。
    """
    if not text or not text.strip():
        return []
    if min_tokens <= 0 or max_tokens < min_tokens:
        raise ValueError("需滿足 0 < min_tokens <= max_tokens")

    spans = _token_spans(text)
    total = len(spans)
    if total == 0:
        return []

    # 短文本：無法達到 min_tokens，回傳單一片段
    if total <= min_tokens:
        return [_make_chunk(text, spans, 0, total)]

    targets = _target_boundaries(total, min_tokens, max_tokens)
    cut_points = _snap_boundaries(text, spans, targets, total, min_tokens, max_tokens)

    # 依 cut_points 產生片段
    chunks: list[TextChunk] = []
    start = 0
    for cut in cut_points + [total]:
        chunks.append(_make_chunk(text, spans, start, cut))
        start = cut
    return chunks


def _snap_boundaries(
    text: str,
    spans: list[tuple[int, int]],
    targets: list[int],
    total: int,
    min_tokens: int,
    max_tokens: int,
) -> list[int]:
    """將每個理想邊界吸附至鄰近句末邊界，且不違反長度不變量。

    對第 i 個邊界，其允許區間為 [prev + min_tokens, target 之後仍滿足
    後續段落約束]。為簡化並保證正確，將吸附範圍限制在
    [max(prev+min, next_target - max), min(prev+max, next_target - min)]，
    使調整不會使任一相鄰段落越界。
    """
    cut_points: list[int] = []
    prev = 0
    for i, target in enumerate(targets):
        next_bound = targets[i + 1] if i + 1 < len(targets) else total
        # 本段下限：prev + min_tokens；本段上限：prev + max_tokens
        low = max(prev + min_tokens, next_bound - max_tokens)
        high = min(prev + max_tokens, next_bound - min_tokens)
        if low > high:
            # 理論上不會發生（targets 已保證可行），保守取 target
            chosen = max(prev + min_tokens, min(target, prev + max_tokens))
        else:
            chosen = _nearest_boundary(text, spans, target, low, high)
        cut_points.append(chosen)
        prev = chosen
    return cut_points


def _nearest_boundary(
    text: str,
    spans: list[tuple[int, int]],
    target: int,
    low: int,
    high: int,
) -> int:
    """在 [low, high] 內尋找最接近 target 的句末邊界；找不到則回傳 target 的夾擠值。"""
    target = max(low, min(target, high))
    best = target
    best_dist = None
    # 掃描允許區間內的句末邊界（cut = 下一段起點，檢查 cut-1 是否為邊界）
    for cut in range(low, high + 1):
        if cut <= 0 or cut > len(spans):
            continue
        if _is_boundary_token(text, spans[cut - 1]):
            dist = abs(cut - target)
            if best_dist is None or dist < best_dist:
                best_dist = dist
                best = cut
    return best


def _make_chunk(
    text: str, spans: list[tuple[int, int]], start_idx: int, end_idx: int
) -> TextChunk:
    """由 token 索引範圍 [start_idx, end_idx) 建立片段。"""
    start_off = spans[start_idx][0]
    end_off = spans[end_idx - 1][1]
    return TextChunk(
        text=text[start_off:end_off],
        token_count=end_idx - start_idx,
        start_offset=start_off,
        end_offset=end_off,
    )
