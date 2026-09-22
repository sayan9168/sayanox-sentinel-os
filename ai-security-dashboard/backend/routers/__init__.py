"""
Routers package initialization
"""

from backend.routers import metrics, threats, skills, auth, system, browser, notifications, fim, remediation, backup

__all__ = ["metrics", "threats", "skills", "auth", "system", "browser", "notifications", "fim", "remediation", "backup"]
