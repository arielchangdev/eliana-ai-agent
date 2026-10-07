"""本地 LLM 推論服務，基於 Ollama REST API."""

from typing import Optional

import httpx
import psutil

from eliana_core.models.llm import LLMResponse, ModelInfo
from eliana_core.models.constants import QUANTIZATION_LEVELS, QUANTIZATION_RATIOS


# Ollama 僅允許的本地主機位址前綴
_ALLOWED_HOSTS = ("http://localhost", "http://127.0.0.1", "http://[::1]")


class LocalLLM:
    """本地 LLM 推論服務，基於 Ollama。

    所有推論皆透過本地 Ollama REST API 完成，禁止任何外部 API 呼叫。
    """

    def __init__(self, base_url: str = "http://localhost:11434") -> None:
        """初始化 LocalLLM 服務。

        Args:
            base_url: Ollama REST API 的基底 URL，預設為 http://localhost:11434。
                      僅允許本地位址以確保推論不外洩。
        """
        self._validate_local_url(base_url)
        self.base_url = base_url.rstrip("/")
        self.current_model: str = "llama3"
        self.current_quantization: str = "Q4_K_M"
        self._client: Optional[httpx.AsyncClient] = None

    @staticmethod
    def _validate_local_url(url: str) -> None:
        """驗證 URL 為本地位址，確保推論不會呼叫外部 API。"""
        if not any(url.startswith(prefix) for prefix in _ALLOWED_HOSTS):
            raise ValueError(
                f"僅允許本地 Ollama 位址，禁止外部 API 呼叫。收到: {url}"
            )

    @property
    def client(self) -> httpx.AsyncClient:
        """取得或建立 httpx AsyncClient。"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(300.0, connect=10.0),
            )
        return self._client

    async def close(self) -> None:
        """關閉 HTTP 客戶端連線。"""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def generate(self, prompt: str, model: Optional[str] = None) -> LLMResponse:
        """執行本地推論請求。

        透過 Ollama REST API (POST /api/generate) 執行推論，
        確保所有處理皆在本地完成。

        Args:
            prompt: 推論提示文字。
            model: 指定模型名稱，若為 None 則使用 current_model。

        Returns:
            LLMResponse 包含生成文字、模型名稱、token 數與耗時。

        Raises:
            httpx.HTTPStatusError: 當 Ollama API 回傳錯誤狀態碼。
            httpx.ConnectError: 當無法連線至本地 Ollama 服務。
        """
        target_model = model or self.current_model

        payload = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
        }

        response = await self.client.post("/api/generate", json=payload)
        response.raise_for_status()

        data = response.json()

        return LLMResponse(
            text=data.get("response", ""),
            model=data.get("model", target_model),
            tokens_generated=data.get("eval_count", 0),
            generation_time_ms=data.get("total_duration", 0) / 1_000_000,  # ns -> ms
        )

    async def switch_model(self, model_name: str) -> bool:
        """熱切換模型，不重啟服務。

        透過向 Ollama 發送空推論請求來預載入模型，
        成功後更新 current_model。

        Args:
            model_name: 要切換的目標模型名稱。

        Returns:
            True 表示切換成功，False 表示切換失敗。
        """
        try:
            payload = {
                "model": model_name,
                "prompt": "",
                "stream": False,
            }
            response = await self.client.post("/api/generate", json=payload)
            response.raise_for_status()

            self.current_model = model_name
            return True
        except (httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException):
            return False

    async def get_loaded_models(self) -> list[ModelInfo]:
        """查詢已載入模型列表。

        透過 Ollama REST API (GET /api/tags) 取得可用模型資訊。

        Returns:
            已載入模型的 ModelInfo 列表。

        Raises:
            httpx.HTTPStatusError: 當 Ollama API 回傳錯誤狀態碼。
            httpx.ConnectError: 當無法連線至本地 Ollama 服務。
        """
        response = await self.client.get("/api/tags")
        response.raise_for_status()

        data = response.json()
        models: list[ModelInfo] = []

        for model_data in data.get("models", []):
            name = model_data.get("name", "")
            size_bytes = model_data.get("size", 0)
            size_gb = size_bytes / (1024**3)

            quantization = self._extract_quantization(name, model_data)

            models.append(ModelInfo(
                name=name,
                size_gb=round(size_gb, 2),
                quantization=quantization,
                loaded=True,
            ))

        return models

    @staticmethod
    def _extract_quantization(name: str, model_data: dict) -> str:
        """從模型名稱或詳情中推斷量化等級。"""
        details = model_data.get("details", {})
        quant = details.get("quantization_level", "")
        if quant:
            return quant

        name_upper = name.upper()
        known_levels = ["Q8_0", "Q6_K", "Q5_K_M", "Q4_K_M", "Q4_0", "Q3_K_S", "Q2_K"]
        for level in known_levels:
            if level in name_upper:
                return level

        return "Q4_K_M"

    @staticmethod
    def select_quantization_level(available_memory_gb: float, model_size_gb: float) -> str:
        """根據可用記憶體選擇適當的量化等級（純函式）。

        依 QUANTIZATION_LEVELS 順序（從最高品質到最低品質）選擇
        第一個記憶體需求不超過可用記憶體的量化等級。
        若沒有任何等級能符合，回傳最低品質等級。

        Args:
            available_memory_gb: 可用記憶體大小（GB）。
            model_size_gb: 模型完整大小（GB）。

        Returns:
            選定的量化等級名稱（如 "Q8_0"、"Q4_K_M" 等）。
        """
        for level in QUANTIZATION_LEVELS:
            ratio = QUANTIZATION_RATIOS[level]
            estimated_memory = model_size_gb * ratio
            if estimated_memory <= available_memory_gb:
                return level

        # 若無等級可用，回傳最低品質等級
        return QUANTIZATION_LEVELS[-1]

    async def auto_downgrade_quantization(self) -> Optional[str]:
        """記憶體不足時自動降低量化等級。

        偵測系統可用記憶體，若當前量化等級的記憶體需求超過可用記憶體，
        則自動降級至下一個較低品質的量化等級。

        Returns:
            新的量化等級名稱，若無需降級或已是最低等級則回傳 None。
        """
        mem = psutil.virtual_memory()
        available_memory_gb = mem.available / (1024**3)

        try:
            models = await self.get_loaded_models()
            current_model_info = next(
                (m for m in models if m.name == self.current_model), None
            )
            if current_model_info is None:
                return None
            model_size_gb = current_model_info.size_gb
        except (httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException):
            return None

        # 找到當前量化等級在列表中的位置
        try:
            current_index = QUANTIZATION_LEVELS.index(self.current_quantization)
        except ValueError:
            current_index = 0

        # 若已是最低品質等級，無法再降級
        if current_index >= len(QUANTIZATION_LEVELS) - 1:
            return None

        # 從當前等級的下一級開始尋找可用等級
        remaining_levels = QUANTIZATION_LEVELS[current_index + 1:]
        for level in remaining_levels:
            ratio = QUANTIZATION_RATIOS[level]
            estimated_memory = model_size_gb * ratio
            if estimated_memory <= available_memory_gb:
                self.current_quantization = level
                return level

        # 若仍無法容納，降至最低品質等級
        self.current_quantization = QUANTIZATION_LEVELS[-1]
        return QUANTIZATION_LEVELS[-1]