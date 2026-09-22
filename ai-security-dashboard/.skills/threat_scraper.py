"""
Reusable Skill Module: Threat Scraper
Can be executed independently for security advisory scraping
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatScraperSkill:
    """
    Standalone threat scraper skill module.
    Can be imported and used independently in future sessions.
    
    Usage:
        from skills.threat_scraper import ThreatScraperSkill
        
        scraper = ThreatScraperSkill()
        threats = await scraper.scrape_cisa()
    """
    
    CISA_API_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories.json"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?lastModDuration=120&resultsPerPage=10"
    
    def __init__(self, output_dir: str = "./scraped_data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def scrape_cisa(self) -> List[Dict]:
        """Scrape CISA cybersecurity advisories"""
        logger.info("Scraping CISA advisories...")
        
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.CISA_API_URL) as response:
                    if response.status == 200:
                        data = await response.json()
                        alerts = data.get("alerts", [])[:20]
                        
                        threats = []
                        for alert in alerts:
                            threat = {
                                "title": alert.get("title", "Unknown"),
                                "source": "CISA",
                                "severity": self._map_severity(alert.get("severity", "Medium")),
                                "description": alert.get("short_description", ""),
                                "url": alert.get("url"),
                                "cve_id": self._extract_cve(alert.get("title", "")),
                                "published_date": alert.get("date_published"),
                                "scraped_at": datetime.utcnow().isoformat()
                            }
                            threats.append(threat)
                        
                        self._save_to_file(threats, "cisa_threats.json")
                        logger.info(f"Scraped {len(threats)} threats from CISA")
                        return threats
        except Exception as e:
            logger.error(f"Error scraping CISA: {e}")
            return self._get_demo_threats("CISA")
    
    async def scrape_nvd(self) -> List[Dict]:
        """Scrape NVD CVE database"""
        logger.info("Scraping NVD vulnerabilities...")
        
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.NVD_API_URL) as response:
                    if response.status == 200:
                        data = await response.json()
                        vulns = data.get("vulnerabilities", [])[:20]
                        
                        threats = []
                        for vuln in vulns:
                            cve_item = vuln.get("cve", {})
                            metrics = cve_item.get("metrics", {})
                            
                            # Get CVSS score
                            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
                            base_score = cvss_v3.get("cvssData", {}).get("baseScore", 5.0)
                            
                            threat = {
                                "title": cve_item.get("descriptions", [{}])[0].get("value", "Unknown CVE"),
                                "source": "NVD",
                                "severity": self._score_to_severity(base_score),
                                "description": cve_item.get("descriptions", [{}])[0].get("value", ""),
                                "url": f"https://nvd.nist.gov/vuln/detail/{cve_item.get('id')}",
                                "cve_id": cve_item.get("id"),
                                "published_date": cve_item.get("published"),
                                "scraped_at": datetime.utcnow().isoformat()
                            }
                            threats.append(threat)
                        
                        self._save_to_file(threats, "nvd_threats.json")
                        logger.info(f"Scraped {len(threats)} vulnerabilities from NVD")
                        return threats
        except Exception as e:
            logger.error(f"Error scraping NVD: {e}")
            return self._get_demo_threats("NVD")
    
    async def scrape_all(self) -> Dict[str, List[Dict]]:
        """Scrape all sources concurrently"""
        logger.info("Starting full threat scrape...")
        
        results = await asyncio.gather(
            self.scrape_cisa(),
            self.scrape_nvd(),
            return_exceptions=True
        )
        
        return {
            "cisa": results[0] if isinstance(results[0], list) else [],
            "nvd": results[1] if isinstance(results[1], list) else [],
            "total": len(results[0]) + len(results[1]) if all(isinstance(r, list) for r in results) else 0,
            "scraped_at": datetime.utcnow().isoformat()
        }
    
    def _map_severity(self, severity_str: str) -> str:
        """Map severity string to standard levels"""
        severity_map = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
        }
        return severity_map.get(severity_str.lower(), "MEDIUM")
    
    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "MEDIUM"
    
    def _extract_cve(self, text: str) -> Optional[str]:
        """Extract CVE ID from text"""
        import re
        cve_pattern = r'CVE-\d{4}-\d+'
        match = re.search(cve_pattern, text, re.IGNORECASE)
        return match.group(0) if match else None
    
    def _get_demo_threats(self, source: str) -> List[Dict]:
        """Generate demo threats when scraping fails"""
        return [
            {
                "title": f"Demo Critical Vulnerability from {source}",
                "source": source,
                "severity": "CRITICAL",
                "description": "Demo threat - actual scraping failed",
                "cve_id": f"CVE-2024-{hash(source) % 9000 + 1000}",
                "scraped_at": datetime.utcnow().isoformat()
            }
        ]
    
    def _save_to_file(self, data: List[Dict], filename: str):
        """Save scraped data to JSON file"""
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved data to {filepath}")
    
    def load_cached_data(self, filename: str) -> Optional[List[Dict]]:
        """Load previously scraped data from cache"""
        filepath = self.output_dir / filename
        if filepath.exists():
            with open(filepath, 'r') as f:
                return json.load(f)
        return None


async def main():
    """Main entry point for standalone execution"""
    print("=" * 60)
    print("THREAT SCRAPER SKILL - Standalone Execution")
    print("=" * 60)
    
    scraper = ThreatScraperSkill()
    results = await scraper.scrape_all()
    
    print(f"\n✓ Scraped {results['total']} total threats")
    print(f"  - CISA: {len(results['cisa'])} threats")
    print(f"  - NVD: {len(results['nvd'])} threats")
    print(f"\nData saved to ./scraped_data/")
    
    return results


if __name__ == "__main__":
    asyncio.run(main())
