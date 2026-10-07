"""LLM 推論 API 端點.

實作 POST /llm/generate、POST /llm/switch-model 端點，
提供本地 LLM 推論與模型切換功能。
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from eliana_core.services.local_llm import LocalLLM


router = APIRouter()


# --- Pydantic Schemas ---


class LLMRequest(BaseModel):
    """LLM 推論請求 schema."""

    prompt: str = Field(..., min_length=1, description="推論提示文字")
    model: Optional[str] = Field(
        default=None, description="指定模型名稱，若為 None 則使用當前模型"
    )


class LLMResponseSchema(BaseModel):
    """LLM 推論回應 schema."""

    text: str = Field(..., description="生成文字")
    model: str = Field(..., description="使用的模型名稱")
    tokens_generated: int = Field(..., description="生成的 token 數")
    generation_time_ms: float = Field(..., description="生成耗時 (毫秒)")


class ModelSwitchRequest(BaseModel):
    """模型切換請求 schema."""

    model_name: str = Field(..., min_length=1, description="目標模型名稱")


class ModelSwitchResponse(BaseModel):
    """模型切換回應 schema."""

    success: bool = Field(..., description="切換是否成功")
    model: str = Field(..., description="當前使用的模型名稱")


# --- Dependencies ---


def get_llm(request: Request) -> LocalLLM:
    """取得 LocalLLM 實例（FastAPI 依賴注入）.

    優先從 app.state 取得（lifespan 初始化的實例），
    若不存在則建立新實例（向後相容測試場景）。
    """
    if hasattr(request.app.state, "local_llm"):
        return request.app.state.local_llm
    return LocalLLM()


# --- Endpoints ---


@router.post("/generate", response_model=LLMResponseSchema)
async def llm_generate(
    request: LLMRequest,
    llm: LocalLLM = Depends(get_llm),
) -> LLMResponseSchema:
    """執行本地 LLM 推論.

    透過 LocalLLM.generate() 在本地完成推論，禁止外部 API 呼叫。
    """
    try:
        response = await llm.generate(prompt=request.prompt, model=request.model)
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"LLM 推論失敗: {e}",
        )

    return LLMResponseSchema(
        text=response.text,
        model=response.model,
        tokens_generated=response.tokens_generated,
        generation_time_ms=response.generation_time_ms,
    )


@router.post("/switch-model", response_model=ModelSwitchResponse)
async def switch_model(
    request: ModelSwitchRequest,
    llm: LocalLLM = Depends(get_llm),
) -> ModelSwitchResponse:
    """切換 LLM 模型.

    透過 LocalLLM.switch_model() 熱切換模型，不重啟服務。
    """
    success = await llm.switch_model(request.model_name)

    return ModelSwitchResponse(
        success=success,
        model=llm.current_model,
    )
