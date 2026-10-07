"""Pytest 全域設定：確保套件路徑可被匯入，並註冊 Hypothesis dev profile。"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from hypothesis import settings, HealthCheck

settings.register_profile(
    "dev",
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
settings.load_profile("dev")
