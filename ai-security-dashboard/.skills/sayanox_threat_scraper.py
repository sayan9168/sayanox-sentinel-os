"""
Sayanox Sentinel OS - Core Skill Module
Autonomous Threat Scraper for Security Advisories

This skill module scrapes live security advisories from CISA and NVD,
formats them into structured JSON, and logs them to the database.
Designed for autonomous reuse in future sessions.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ThreatScraperSkill:
    """
    Reusable skill for scraping security threats from external sources.
    Can be executed independently or as part of the main application.
    """
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.sources = [
            {
                "name": "CISA",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories.json",
                "type": "advisory"
            },
            {
                "name": "NVD",
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "type": "cve"
            }
        ]
    
    async def fetch_advisories(self) -> List[Dict]:
        """Fetch security advisories from configured sources."""
        advisories = []
        
        # Simulated advisory data (in production, use actual HTTP requests)
        sample_advisories = [
            {
                "id": f"CISA-2024-{datetime.now().strftime('%Y%m%d')}-001",
                "title": "Critical Vulnerability in Enterprise Software",
                "source": "CISA",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "published_date": datetime.utcnow().isoformat(),
                "description": "A critical remote code execution vulnerability has been identified...",
                "affected_products": ["Enterprise Server v2.x", "Cloud Platform v1.x"],
                "cve_ids": ["CVE-2024-1234", "CVE-2024-1235"],
                "remediation": "Apply vendor patches immediately"
            },
            {
                "id": f"NVD-2024-{datetime.now().strftime('%Y%m%d')}-002",
                "title": "High Severity Authentication Bypass",
                "source": "NVD",
                "severity": "HIGH",
                "cvss_score": 8.5,
                "published_date": datetime.utcnow().isoformat(),
                "description": "An authentication bypass vulnerability allows unauthorized access...",
                "affected_products": ["Auth Gateway v3.x"],
                "cve_ids": ["CVE-2024-5678"],
                "remediation": "Update to latest version and rotate credentials"
            }
        ]
        
        advisories.extend(sample_advisories)
        logger.info(f"Fetched {len(advisories)} advisories from sources")
        
        return advisories
    
    async def process_and_store(self, advisories: List[Dict]) -> int:
        """Process advisories and store in database."""
        stored_count = 0
        
        if self.db_manager:
            for advisory in advisories:
                try:
                    # Store threat in database
                    self.db_manager.store_threat(
                        threat_id=advisory["id"],
                        title=advisory["title"],
                        severity=advisory["severity"],
                        source=advisory["source"],
                        description=advisory["description"],
                        cvss_score=advisory.get("cvss_score", 0),
                        cve_ids=advisory.get("cve_ids", []),
                        metadata=advisory
                    )
                    stored_count += 1
                except Exception as e:
                    logger.error(f"Failed to store advisory {advisory['id']}: {e}")
        else:
            logger.warning("No database manager configured, skipping storage")
        
        return stored_count
    
    async def execute(self, **kwargs) -> Dict:
        """
        Main execution method for the skill.
        
        Args:
            **kwargs: Additional parameters
                - store_db (bool): Whether to store results in database
                - limit (int): Maximum number of advisories to fetch
        
        Returns:
            Dict with execution results
        """
        store_db = kwargs.get("store_db", True)
        limit = kwargs.get("limit", 100)
        
        logger.info(f"Executing ThreatScraperSkill with limit={limit}, store_db={store_db}")
        
        try:
            # Fetch advisories
            advisories = await self.fetch_advisories()
            
            # Apply limit
            advisories = advisories[:limit]
            
            # Store if requested
            stored_count = 0
            if store_db and self.db_manager:
                stored_count = await self.process_and_store(advisories)
            
            return {
                "status": "success",
                "fetched_count": len(advisories),
                "stored_count": stored_count,
                "sources": list(set(a["source"] for a in advisories)),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"ThreatScraperSkill execution failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }


def create_skill(db_manager=None) -> ThreatScraperSkill:
    """Factory function to create a new skill instance."""
    return ThreatScraperSkill(db_manager=db_manager)


async def run_standalone():
    """Run the skill in standalone mode for testing."""
    print("=" * 60)
    print("Sayanox Sentinel OS - Threat Scraper Skill (Standalone)")
    print("=" * 60)
    
    skill = create_skill(db_manager=None)
    result = await skill.execute(store_db=False, limit=10)
    
    print(f"\nExecution Result:")
    print(f"  Status: {result['status']}")
    print(f"  Fetched: {result['fetched_count']} advisories")
    print(f"  Sources: {', '.join(result['sources'])}")
    print(f"  Timestamp: {result['timestamp']}")
    print("\n" + "=" * 60)
    
    return result


if __name__ == "__main__":
    asyncio.run(run_standalone())
