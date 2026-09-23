"""
Browser Control Engine - Playwright Automation
Provides headless browser control, screenshot capture, and web interaction
"""

import os
import base64
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from playwright.async_api import async_playwright, Browser, Page, BrowserContext

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BrowserEngine:
    """Playwright-based browser automation engine."""
    
    def __init__(self):
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.screenshot_dir = Path(os.path.dirname(__file__)) / ".." / ".." / "screenshots"
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
    
    async def initialize(self, headless: bool = True):
        """Initialize browser instance."""
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(headless=headless)
        self.context = await self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        self.page = await self.context.new_page()
        logger.info("Browser engine initialized")
    
    async def close(self):
        """Close browser instance."""
        if self.browser:
            await self.browser.close()
            self.browser = None
            self.page = None
            self.context = None
            logger.info("Browser engine closed")
    
    async def navigate(self, url: str, wait_until: str = "domcontentloaded", timeout: int = 30000) -> Dict[str, Any]:
        """Navigate to a URL."""
        if not self.page:
            await self.initialize()
        
        try:
            response = await self.page.goto(url, wait_until=wait_until, timeout=timeout)
            return {
                "success": True,
                "url": url,
                "status": response.status if response else None,
                "title": await self.page.title(),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Navigation error: {e}")
            return {
                "success": False,
                "url": url,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def screenshot(self, name: Optional[str] = None, full_page: bool = True) -> Dict[str, Any]:
        """Take a screenshot of the current page."""
        if not self.page:
            return {"success": False, "error": "Browser not initialized"}
        
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = name or f"screenshot_{timestamp}.png"
            filepath = self.screenshot_dir / filename
            
            screenshot_bytes = await self.page.screenshot(full_page=full_page)
            
            # Save to file
            with open(filepath, "wb") as f:
                f.write(screenshot_bytes)
            
            # Return base64 encoded image for UI display
            base64_image = base64.b64encode(screenshot_bytes).decode('utf-8')
            
            return {
                "success": True,
                "filename": filename,
                "filepath": str(filepath),
                "base64": base64_image,
                "size_bytes": len(screenshot_bytes),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Screenshot error: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def desktop_screenshot(self) -> Dict[str, Any]:
        """Take a desktop screenshot using system tools."""
        import subprocess
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"desktop_{timestamp}.png"
        filepath = self.screenshot_dir / filename
        
        try:
            # Try different screenshot methods based on OS
            if os.uname().sysname == "Linux":
                # Try scrot, then gnome-screenshot, then ImageMagick
                for cmd in [
                    ["scrot", str(filepath)],
                    ["gnome-screenshot", "-f", str(filepath)],
                    ["import", "-window", "root", str(filepath)]
                ]:
                    try:
                        result = subprocess.run(cmd, capture_output=True, timeout=10)
                        if result.returncode == 0 and filepath.exists():
                            break
                    except Exception:
                        continue
            else:
                return {
                    "success": False,
                    "error": "Desktop screenshots only supported on Linux",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            if filepath.exists():
                with open(filepath, "rb") as f:
                    screenshot_bytes = f.read()
                
                base64_image = base64.b64encode(screenshot_bytes).decode('utf-8')
                
                return {
                    "success": True,
                    "filename": filename,
                    "filepath": str(filepath),
                    "base64": base64_image,
                    "size_bytes": len(screenshot_bytes),
                    "type": "desktop",
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to capture desktop screenshot - no suitable tool found",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Desktop screenshot error: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def click(self, selector: str) -> Dict[str, Any]:
        """Click an element on the page."""
        if not self.page:
            return {"success": False, "error": "Browser not initialized"}
        
        try:
            await self.page.click(selector, timeout=10000)
            return {
                "success": True,
                "selector": selector,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Click error: {e}")
            return {
                "success": False,
                "selector": selector,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def fill(self, selector: str, value: str) -> Dict[str, Any]:
        """Fill an input field."""
        if not self.page:
            return {"success": False, "error": "Browser not initialized"}
        
        try:
            await self.page.fill(selector, value, timeout=10000)
            return {
                "success": True,
                "selector": selector,
                "value": "*" * len(value),  # Hide sensitive data
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Fill error: {e}")
            return {
                "success": False,
                "selector": selector,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def evaluate(self, javascript: str) -> Dict[str, Any]:
        """Execute JavaScript on the page."""
        if not self.page:
            return {"success": False, "error": "Browser not initialized"}
        
        try:
            result = await self.page.evaluate(javascript)
            return {
                "success": True,
                "result": result,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Evaluate error: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def get_content(self) -> Dict[str, Any]:
        """Get the HTML content of the current page."""
        if not self.page:
            return {"success": False, "error": "Browser not initialized"}
        
        try:
            content = await self.page.content()
            title = await self.page.title()
            url = self.page.url
            
            return {
                "success": True,
                "url": url,
                "title": title,
                "content_length": len(content),
                "content": content[:10000],  # Limit content size
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Get content error: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def solve_captcha(self) -> Dict[str, Any]:
        """
        Attempt to detect and provide guidance for captcha solving.
        Note: Actual captcha solving requires external services.
        """
        if not self.page:
            return {"success": False, "error": "Browser not initialized"}
        
        try:
            # Detect common captcha elements
            captcha_selectors = [
                'iframe[src*="recaptcha"]',
                'iframe[src*="hcaptcha"]',
                '[data-sitekey]',
                '.g-recaptcha',
                '.h-captcha'
            ]
            
            detected_captchas = []
            for selector in captcha_selectors:
                elements = await self.page.query_selector_all(selector)
                if elements:
                    detected_captchas.append({
                        "selector": selector,
                        "count": len(elements)
                    })
            
            if detected_captchas:
                return {
                    "success": True,
                    "captcha_detected": True,
                    "captchas": detected_captchas,
                    "message": "Captcha detected. Manual intervention or external service required.",
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                return {
                    "success": True,
                    "captcha_detected": False,
                    "message": "No captcha detected on current page",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Captcha detection error: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def wait_for_selector(self, selector: str, timeout: int = 30000) -> Dict[str, Any]:
        """Wait for an element to appear on the page."""
        if not self.page:
            return {"success": False, "error": "Browser not initialized"}
        
        try:
            await self.page.wait_for_selector(selector, timeout=timeout)
            return {
                "success": True,
                "selector": selector,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Wait for selector error: {e}")
            return {
                "success": False,
                "selector": selector,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }


# Singleton instance
browser_engine = BrowserEngine()
