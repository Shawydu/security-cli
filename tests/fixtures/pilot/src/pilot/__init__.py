"""Minimal existing app for dependency-upgrade verification."""
from urllib3 import PoolManager


def new_client() -> PoolManager:
    return PoolManager()
