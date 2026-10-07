"""任務管理 API 端點.

實作 POST /tasks、GET /tasks/{task_id}、GET /tasks 端點，
提供任務建立、狀態查詢與列表功能。
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from eliana_core.db.database import DatabasePool, get_db
from eliana_core.db import task_repo
from eliana_core.models.task import (
    Task,
    TaskCategory,
    TaskPriority,
    TaskStatus,
)
from eliana_core.services.task_scheduler import TaskSchedulerService


router = APIRouter()


# --- Pydantic Schemas ---


class CreateTaskRequest(BaseModel):
    """建立任務請求 schema."""

    name: str = Field(..., min_length=1, description="任務名稱")
    description: str = Field(default="", description="任務描述")
    priority: TaskPriority = Field(
        default=TaskPriority.NORMAL, description="任務優先順序"
    )
    category: TaskCategory = Field(
        default=TaskCategory.COMPUTATION, description="任務類別"
    )
    dependencies: list[str] = Field(
        default_factory=list, description="依賴的任務 ID 列表"
    )
    payload: dict = Field(default_factory=dict, description="任務負載資料")
    max_retries: int = Field(default=3, ge=0, description="最大重試次數")


class TaskResponse(BaseModel):
    """建立任務回應 schema."""

    id: str = Field(..., description="任務 ID")
    name: str = Field(..., description="任務名稱")
    description: str = Field(default="", description="任務描述")
    priority: TaskPriority = Field(..., description="任務優先順序")
    category: TaskCategory = Field(..., description="任務類別")
    status: TaskStatus = Field(..., description="任務狀態")
    dependencies: list[str] = Field(default_factory=list, description="依賴任務 ID 列表")
    payload: dict = Field(default_factory=dict, description="任務負載資料")
    retry_count: int = Field(default=0, description="已重試次數")
    max_retries: int = Field(default=3, description="最大重試次數")
    created_at: datetime = Field(..., description="建立時間")
    started_at: Optional[datetime] = Field(None, description="開始執行時間")
    completed_at: Optional[datetime] = Field(None, description="完成時間")
    error_message: Optional[str] = Field(None, description="錯誤訊息")


class TaskStatusResponse(BaseModel):
    """任務狀態查詢回應 schema."""

    id: str = Field(..., description="任務 ID")
    name: str = Field(..., description="任務名稱")
    status: TaskStatus = Field(..., description="任務狀態")
    priority: TaskPriority = Field(..., description="任務優先順序")
    category: TaskCategory = Field(..., description="任務類別")
    retry_count: int = Field(default=0, description="已重試次數")
    max_retries: int = Field(default=3, description="最大重試次數")
    created_at: datetime = Field(..., description="建立時間")
    started_at: Optional[datetime] = Field(None, description="開始執行時間")
    completed_at: Optional[datetime] = Field(None, description="完成時間")
    error_message: Optional[str] = Field(None, description="錯誤訊息")


# --- Dependencies ---


async def get_scheduler(request: Request) -> TaskSchedulerService:
    """取得 TaskSchedulerService 實例（FastAPI 依賴注入）.

    優先從 app.state 取得（lifespan 初始化的實例），
    若不存在則建立新實例（向後相容測試場景）。
    """
    if hasattr(request.app.state, "task_scheduler"):
        return request.app.state.task_scheduler
    db_pool = await get_db()
    return TaskSchedulerService(db_pool=db_pool)


# --- Helper ---


def _task_to_response(task: Task) -> TaskResponse:
    """將 Task dataclass 轉換為 TaskResponse."""
    return TaskResponse(
        id=task.id,
        name=task.name,
        description=task.description,
        priority=task.priority,
        category=task.category,
        status=task.status,
        dependencies=task.dependencies,
        payload=task.payload,
        retry_count=task.retry_count,
        max_retries=task.max_retries,
        created_at=task.created_at,
        started_at=task.started_at,
        completed_at=task.completed_at,
        error_message=task.error_message,
    )


def _task_to_status_response(task: Task) -> TaskStatusResponse:
    """將 Task dataclass 轉換為 TaskStatusResponse."""
    return TaskStatusResponse(
        id=task.id,
        name=task.name,
        status=task.status,
        priority=task.priority,
        category=task.category,
        retry_count=task.retry_count,
        max_retries=task.max_retries,
        created_at=task.created_at,
        started_at=task.started_at,
        completed_at=task.completed_at,
        error_message=task.error_message,
    )


# --- Endpoints ---


@router.post("", response_model=TaskResponse, status_code=201)
async def create_task(
    request: CreateTaskRequest,
    scheduler: TaskSchedulerService = Depends(get_scheduler),
) -> TaskResponse:
    """建立新任務並加入排程佇列.

    依據優先順序與依賴關係排入任務佇列，回傳已建立的任務資訊。
    """
    task = Task(
        name=request.name,
        description=request.description,
        priority=request.priority,
        category=request.category,
        dependencies=request.dependencies,
        payload=request.payload,
        max_retries=request.max_retries,
    )

    try:
        task_id = await scheduler.enqueue_task(task)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # 回傳已建立的任務（使用實際寫入的 ID）
    from dataclasses import replace

    created_task = replace(task, id=task_id) if task_id != task.id else task
    return _task_to_response(created_task)


@router.get("/{task_id}", response_model=TaskStatusResponse)
async def get_task_status(
    task_id: str,
    scheduler: TaskSchedulerService = Depends(get_scheduler),
) -> TaskStatusResponse:
    """查詢指定任務的狀態."""
    db_pool = await get_db()
    task = await task_repo.get_task(db_pool, task_id)

    if task is None:
        raise HTTPException(status_code=404, detail=f"Task not found: {task_id}")

    return _task_to_status_response(task)


@router.get("", response_model=list[TaskStatusResponse])
async def list_tasks(
    status: Optional[TaskStatus] = Query(None, description="依狀態篩選任務"),
    scheduler: TaskSchedulerService = Depends(get_scheduler),
) -> list[TaskStatusResponse]:
    """列出任務，可依狀態篩選.

    若未指定 status 參數，回傳所有狀態的任務。
    """
    db_pool = await get_db()

    if status is not None:
        tasks = await task_repo.list_tasks_by_status(db_pool, status)
    else:
        # 取得所有狀態的任務
        all_tasks: list[Task] = []
        for s in TaskStatus:
            tasks_for_status = await task_repo.list_tasks_by_status(db_pool, s)
            all_tasks.extend(tasks_for_status)
        tasks = all_tasks

    return [_task_to_status_response(t) for t in tasks]
