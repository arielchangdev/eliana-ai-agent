"""任務排程器核心邏輯。"""

from dataclasses import replace
from typing import Optional

from eliana_core.models.task import Task, HostTarget, TaskCategory, TaskStatus
from eliana_core.models.constants import CATEGORY_TO_HOST
from eliana_core.db.database import DatabasePool
from eliana_core.db import task_repo
from eliana_core.models.remote import RemoteResult
from eliana_core.errors.exceptions import TaskExecutionError


# 有效的狀態轉換路徑
VALID_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.PENDING: {TaskStatus.RUNNING},
    TaskStatus.RUNNING: {TaskStatus.COMPLETED, TaskStatus.FAILED},
    TaskStatus.FAILED: {TaskStatus.PENDING},
    TaskStatus.COMPLETED: set(),
}


def classify_task_target(task: Task) -> HostTarget:
    """依 CATEGORY_TO_HOST 映射決定任務應在哪台主機執行。

    Args:
        task: 任務實例。

    Returns:
        目標主機（HostTarget.WEAPON 或 HostTarget.CORE）。

    Raises:
        ValueError: 若任務類別不在映射表中。
    """
    if task.category not in CATEGORY_TO_HOST:
        raise ValueError(f"Unknown task category: {task.category}")
    return CATEGORY_TO_HOST[task.category]


def update_status(
    task: Task,
    new_status: TaskStatus,
    error: Optional[str] = None,
) -> Task:
    """驗證狀態轉換並回傳更新後的任務。

    有效轉換路徑：
    - pending -> running
    - running -> completed
    - running -> failed
    - failed -> pending (透過 retry)

    Args:
        task: 當前任務實例。
        new_status: 欲轉換的目標狀態。
        error: 錯誤訊息（僅在轉換至 failed 時使用）。

    Returns:
        狀態已更新的新 Task 實例。

    Raises:
        ValueError: 若狀態轉換無效。
    """
    current_status = task.status
    valid_targets = VALID_TRANSITIONS.get(current_status, set())

    if new_status not in valid_targets:
        raise ValueError(
            f"Invalid status transition: {current_status.value} -> {new_status.value}"
        )

    return replace(task, status=new_status, error_message=error)


def retry_task(task: Task) -> tuple[bool, Task]:
    """根據重試策略決定是否重新排程失敗任務。

    若 retry_count < max_retries，遞增 retry_count 並將狀態重設為 PENDING。

    Args:
        task: 當前失敗的任務實例。

    Returns:
        (eligible, updated_task) 元組。
        eligible 為 True 表示可重試，updated_task 包含更新後的狀態與計數。
        eligible 為 False 時 updated_task 與輸入相同。
    """
    if task.retry_count < task.max_retries:
        updated = replace(
            task,
            retry_count=task.retry_count + 1,
            status=TaskStatus.PENDING,
            error_message=None,
        )
        return True, updated

    return False, task


def get_execution_order(tasks: list[Task]) -> list[Task]:
    """根據依賴關係與優先順序計算執行順序（拓撲排序）。

    使用 Kahn's algorithm 進行拓撲排序。同層級中（所有依賴皆已滿足的任務）
    依優先順序排列（priority 值越小優先權越高）。

    Args:
        tasks: 待排序的任務列表。

    Returns:
        依執行順序排列的任務列表。

    Raises:
        ValueError: 若任務間存在循環依賴。
    """
    if not tasks:
        return []

    # 建立 task id -> task 的查找表
    task_map: dict[str, Task] = {t.id: t for t in tasks}
    # 僅考慮列表中存在的任務 ID 集合
    task_ids = set(task_map.keys())

    # 計算每個任務的入度（僅計算列表內的依賴）
    in_degree: dict[str, int] = {t.id: 0 for t in tasks}
    # 建立反向鄰接表：被依賴者 -> 依賴者列表
    dependents: dict[str, list[str]] = {t.id: [] for t in tasks}

    for task in tasks:
        for dep_id in task.dependencies:
            if dep_id in task_ids:
                in_degree[task.id] += 1
                dependents[dep_id].append(task.id)

    # 初始化：找出所有入度為 0 的任務，依優先順序排序
    ready: list[Task] = sorted(
        [task_map[tid] for tid, deg in in_degree.items() if deg == 0],
        key=lambda t: t.priority.value,
    )

    result: list[Task] = []

    while ready:
        # 取出當前層級中優先權最高的任務
        current = ready.pop(0)
        result.append(current)

        # 更新依賴此任務的其他任務的入度
        new_ready: list[Task] = []
        for dep_tid in dependents[current.id]:
            in_degree[dep_tid] -= 1
            if in_degree[dep_tid] == 0:
                new_ready.append(task_map[dep_tid])

        # 將新就緒的任務加入 ready 列表並重新排序
        if new_ready:
            ready.extend(new_ready)
            ready.sort(key=lambda t: t.priority.value)

    # 檢查是否所有任務都已排入結果（偵測循環依賴）
    if len(result) != len(tasks):
        raise ValueError("Circular dependency detected among tasks")

    return result


# --- 整合服務層 ---


class TaskSchedulerService:
    """任務排程器服務，整合 DB 與 SSH 通訊層。"""

    def __init__(self, db_pool: DatabasePool, ssh_channel=None):
        self._db_pool = db_pool
        self._ssh_channel = ssh_channel  # Optional, will be implemented in task 5

    async def enqueue_task(self, task: Task) -> str:
        """驗證任務並寫入 DB，回傳 task_id。

        Validation:
        - task must have a name
        - task.status should be PENDING
        - task.category must be a valid TaskCategory

        Args:
            task: 要入列的任務。

        Returns:
            寫入後的任務 ID。

        Raises:
            ValueError: 若任務驗證失敗。
        """
        # 驗證任務名稱
        if not task.name or not task.name.strip():
            raise ValueError("Task must have a non-empty name")

        # 驗證狀態應為 PENDING
        if task.status != TaskStatus.PENDING:
            raise ValueError(
                f"Task status must be PENDING for enqueue, got: {task.status.value}"
            )

        # 驗證類別為有效的 TaskCategory
        if not isinstance(task.category, TaskCategory):
            raise ValueError(f"Invalid task category: {task.category}")

        # 寫入 DB
        task_id = await task_repo.insert_task(self._db_pool, task)
        return task_id

    async def dequeue_next(self) -> Optional[Task]:
        """從 DB 取出最高優先的可執行任務。

        Logic:
        - Get all pending tasks ordered by priority
        - Check dependency satisfaction (all deps must be completed)
        - Return the first task whose deps are all satisfied, or None
        - Update the returned task's status to RUNNING

        Returns:
            下一個可執行的任務，若無可執行任務則回傳 None。
        """
        pending_tasks = await task_repo.get_pending_tasks_ordered(self._db_pool)

        for task in pending_tasks:
            # 檢查所有依賴是否已完成
            deps_satisfied = True
            for dep_id in task.dependencies:
                dep_task = await task_repo.get_task(self._db_pool, dep_id)
                if dep_task is None or dep_task.status != TaskStatus.COMPLETED:
                    deps_satisfied = False
                    break

            if deps_satisfied:
                # 更新狀態為 RUNNING
                await task_repo.update_task_status(
                    self._db_pool, task.id, TaskStatus.RUNNING
                )
                return replace(task, status=TaskStatus.RUNNING)

        return None

    async def dispatch_task(self, task: Task) -> RemoteResult:
        """依 classify_task_target 結果派送任務至對應主機。

        - Use classify_task_target to determine the target host
        - If target is CORE: execute locally (placeholder for now)
        - If target is WEAPON: use SSH channel to execute remotely
        - If SSH channel is not available and target is WEAPON, raise an error

        Args:
            task: 要派送的任務。

        Returns:
            執行結果 RemoteResult。

        Raises:
            TaskExecutionError: 若 SSH channel 未設定且目標為 WEAPON。
        """
        target = classify_task_target(task)

        if target == HostTarget.CORE:
            # 本地執行（placeholder）
            return RemoteResult(
                stdout=f"Task '{task.name}' executed locally on CORE host",
                stderr="",
                exit_code=0,
                execution_time_ms=0.0,
            )

        # target == HostTarget.WEAPON
        if self._ssh_channel is None:
            raise TaskExecutionError(
                message=f"SSH channel not available, cannot dispatch task '{task.name}' to WEAPON host",
                task_id=task.id,
            )

        # 透過 SSH channel 遠端執行（placeholder for task 5）
        return RemoteResult(
            stdout=f"Task '{task.name}' dispatched to WEAPON host via SSH",
            stderr="",
            exit_code=0,
            execution_time_ms=0.0,
        )
