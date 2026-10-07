"""任務持久化存取層（Task Repository）.

提供任務的 CRUD 操作與查詢功能，
使用 DatabasePool 進行非同步 SQLite 存取。
"""

import json
import logging
from datetime import datetime
from typing import Optional

from eliana_core.db.database import DatabasePool
from eliana_core.models.task import Task, TaskCategory, TaskPriority, TaskStatus

logger = logging.getLogger(__name__)


def _task_to_row(task: Task) -> tuple:
    """將 Task dataclass 轉換為 SQLite 行資料."""
    return (
        task.id,
        task.name,
        task.description,
        task.priority.value,
        task.category.value,
        task.status.value,
        json.dumps(task.dependencies),
        json.dumps(task.payload),
        task.retry_count,
        task.max_retries,
        task.created_at.isoformat(),
        task.started_at.isoformat() if task.started_at else None,
        task.completed_at.isoformat() if task.completed_at else None,
        task.error_message,
    )


def _row_to_task(row) -> Task:
    """將 SQLite 行資料轉換為 Task dataclass."""
    return Task(
        id=row[0],
        name=row[1],
        description=row[2],
        priority=TaskPriority(row[3]),
        category=TaskCategory(row[4]),
        status=TaskStatus(row[5]),
        dependencies=json.loads(row[6]) if row[6] else [],
        payload=json.loads(row[7]) if row[7] else {},
        retry_count=row[8],
        max_retries=row[9],
        created_at=datetime.fromisoformat(row[10]),
        started_at=datetime.fromisoformat(row[11]) if row[11] else None,
        completed_at=datetime.fromisoformat(row[12]) if row[12] else None,
        error_message=row[13],
    )


async def insert_task(pool: DatabasePool, task: Task) -> str:
    """插入任務至資料庫.

    Args:
        pool: 資料庫連線池.
        task: 要插入的任務物件.

    Returns:
        插入的任務 ID.
    """
    sql = """
        INSERT INTO tasks (
            id, name, description, priority, category, status,
            dependencies, payload, retry_count, max_retries,
            created_at, started_at, completed_at, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    await pool.execute_write(sql, _task_to_row(task))
    logger.debug("任務已插入: %s (%s)", task.id, task.name)
    return task.id


async def get_task(pool: DatabasePool, task_id: str) -> Optional[Task]:
    """依 ID 取得任務.

    Args:
        pool: 資料庫連線池.
        task_id: 任務 ID.

    Returns:
        找到的 Task 物件，若不存在回傳 None.
    """
    conn = await pool.get_connection()
    try:
        cursor = await conn.execute(
            "SELECT id, name, description, priority, category, status, "
            "dependencies, payload, retry_count, max_retries, "
            "created_at, started_at, completed_at, error_message "
            "FROM tasks WHERE id = ?",
            (task_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_task(row)
    finally:
        await pool.release_connection(conn)


async def update_task_status(
    pool: DatabasePool,
    task_id: str,
    status: TaskStatus,
    error_message: Optional[str] = None,
) -> bool:
    """更新任務狀態.

    Args:
        pool: 資料庫連線池.
        task_id: 任務 ID.
        status: 新狀態.
        error_message: 錯誤訊息（選填）.

    Returns:
        True 若更新成功，False 若任務不存在.
    """
    conn = await pool.get_connection()
    try:
        # 根據狀態更新時間戳
        now = datetime.utcnow().isoformat()
        if status == TaskStatus.RUNNING:
            sql = (
                "UPDATE tasks SET status = ?, started_at = ?, error_message = ? "
                "WHERE id = ?"
            )
            params = (status.value, now, error_message, task_id)
        elif status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
            sql = (
                "UPDATE tasks SET status = ?, completed_at = ?, error_message = ? "
                "WHERE id = ?"
            )
            params = (status.value, now, error_message, task_id)
        else:
            sql = "UPDATE tasks SET status = ?, error_message = ? WHERE id = ?"
            params = (status.value, error_message, task_id)

        cursor = await conn.execute(sql, params)
        await conn.commit()
        updated = cursor.rowcount > 0
        if updated:
            logger.debug("任務狀態已更新: %s -> %s", task_id, status.value)
        return updated
    finally:
        await pool.release_connection(conn)


async def list_tasks_by_status(pool: DatabasePool, status: TaskStatus) -> list[Task]:
    """列出指定狀態的所有任務.

    Args:
        pool: 資料庫連線池.
        status: 要篩選的狀態.

    Returns:
        符合條件的任務列表.
    """
    conn = await pool.get_connection()
    try:
        cursor = await conn.execute(
            "SELECT id, name, description, priority, category, status, "
            "dependencies, payload, retry_count, max_retries, "
            "created_at, started_at, completed_at, error_message "
            "FROM tasks WHERE status = ?",
            (status.value,),
        )
        rows = await cursor.fetchall()
        return [_row_to_task(row) for row in rows]
    finally:
        await pool.release_connection(conn)


async def get_pending_tasks_ordered(pool: DatabasePool) -> list[Task]:
    """取得待執行任務，依優先順序排列.

    優先順序值越小表示越優先（CRITICAL=0 > HIGH=1 > NORMAL=2 > LOW=3）。

    Args:
        pool: 資料庫連線池.

    Returns:
        按優先順序排列的待執行任務列表.
    """
    conn = await pool.get_connection()
    try:
        cursor = await conn.execute(
            "SELECT id, name, description, priority, category, status, "
            "dependencies, payload, retry_count, max_retries, "
            "created_at, started_at, completed_at, error_message "
            "FROM tasks WHERE status = ? ORDER BY priority ASC, created_at ASC",
            (TaskStatus.PENDING.value,),
        )
        rows = await cursor.fetchall()
        return [_row_to_task(row) for row in rows]
    finally:
        await pool.release_connection(conn)
