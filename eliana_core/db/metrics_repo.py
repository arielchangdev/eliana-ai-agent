"""監控資料存取層（Metrics Repository）.

提供系統監控指標的儲存、查詢與過期清理功能。
"""

from datetime import datetime, timedelta

from eliana_core.db.database import DatabasePool
from eliana_core.models.metrics import SystemMetrics
from eliana_core.models.task import HostTarget


async def store_metrics(pool: DatabasePool, metrics: SystemMetrics) -> None:
    """儲存一筆系統監控指標至 metrics 表.

    Args:
        pool: 資料庫連線池.
        metrics: 系統指標資料.
    """
    await pool.execute_write(
        """
        INSERT INTO metrics (host, cpu_percent, memory_percent, memory_used_gb,
                             memory_total_gb, disk_percent, disk_used_gb,
                             disk_total_gb, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            metrics.host.value,
            metrics.cpu_percent,
            metrics.memory_percent,
            metrics.memory_used_gb,
            metrics.memory_total_gb,
            metrics.disk_percent,
            metrics.disk_used_gb,
            metrics.disk_total_gb,
            metrics.timestamp.isoformat(),
        ),
    )


async def query_history(
    pool: DatabasePool,
    host: HostTarget,
    start: datetime,
    end: datetime,
) -> list[SystemMetrics]:
    """查詢指定主機在時間範圍內的監控歷史.

    Args:
        pool: 資料庫連線池.
        host: 目標主機.
        start: 查詢起始時間.
        end: 查詢結束時間.

    Returns:
        SystemMetrics 列表，依時間排序.
    """
    conn = await pool.get_connection()
    try:
        cursor = await conn.execute(
            """
            SELECT host, cpu_percent, memory_percent, memory_used_gb,
                   memory_total_gb, disk_percent, disk_used_gb,
                   disk_total_gb, timestamp
            FROM metrics
            WHERE host = ? AND timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            """,
            (host.value, start.isoformat(), end.isoformat()),
        )
        rows = await cursor.fetchall()
        results: list[SystemMetrics] = []
        for row in rows:
            results.append(
                SystemMetrics(
                    host=HostTarget(row[0]),
                    cpu_percent=row[1],
                    memory_percent=row[2],
                    memory_used_gb=row[3],
                    memory_total_gb=row[4],
                    disk_percent=row[5],
                    disk_used_gb=row[6],
                    disk_total_gb=row[7],
                    timestamp=datetime.fromisoformat(row[8]),
                )
            )
        return results
    finally:
        await pool.release_connection(conn)


async def cleanup_old_data(pool: DatabasePool, retention_days: int = 7) -> int:
    """清理超過保留天數的監控資料.

    Args:
        pool: 資料庫連線池.
        retention_days: 資料保留天數，預設 7 天.

    Returns:
        刪除的記錄筆數.
    """
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    cutoff_iso = cutoff.isoformat()

    conn = await pool.get_connection()
    try:
        # 先取得要刪除的筆數
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM metrics WHERE timestamp < ?",
            (cutoff_iso,),
        )
        row = await cursor.fetchone()
        count = row[0]

        # 執行刪除
        await conn.execute(
            "DELETE FROM metrics WHERE timestamp < ?",
            (cutoff_iso,),
        )
        await conn.commit()
        return count
    finally:
        await pool.release_connection(conn)
