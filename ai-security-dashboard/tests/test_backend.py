"""
Test suite for AI Security Intelligence Dashboard Backend
Tests API endpoints, database operations, and MCP tools
"""

import pytest
import asyncio
from datetime import datetime
from httpx import AsyncClient, ASGITransport

# Import the FastAPI app
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, init_database, DB_PATH


@pytest.fixture
def test_db():
    """Initialize test database."""
    init_database()
    yield
    # Cleanup if needed


@pytest.fixture
async def client():
    """Create async test client."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


class TestRootEndpoint:
    """Test root endpoint."""
    
    @pytest.mark.asyncio
    async def test_root(self, client):
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data


class TestMetricsEndpoints:
    """Test metrics API endpoints."""
    
    @pytest.mark.asyncio
    async def test_get_latest_metrics(self, client):
        response = await client.get("/api/v1/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "cpu_percent" in data
        assert "memory_percent" in data
        assert "timestamp" in data
    
    @pytest.mark.asyncio
    async def test_get_metrics_history(self, client):
        response = await client.get("/api/v1/metrics/history")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestThreatsEndpoints:
    """Test threats API endpoints."""
    
    @pytest.mark.asyncio
    async def test_get_threats(self, client):
        response = await client.get("/api/v1/threats")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    @pytest.mark.asyncio
    async def test_add_threat(self, client):
        threat_data = {
            "title": "Test Security Alert",
            "source": "Test Source",
            "severity": "medium",
            "description": "Test description for security alert",
            "url": "https://example.com/alert",
            "published_date": datetime.utcnow().isoformat()
        }
        response = await client.post("/api/v1/threats", json=threat_data)
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == threat_data["title"]
        assert "detected_at" in data


class TestSkillsEndpoint:
    """Test skills API endpoint."""
    
    @pytest.mark.asyncio
    async def test_get_skills(self, client):
        response = await client.get("/api/v1/skills")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestDatabaseInitialization:
    """Test database initialization."""
    
    def test_init_database(self, test_db):
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        assert "system_metrics" in tables
        assert "threat_alerts" in tables
        assert "skills_log" in tables
        
        conn.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
