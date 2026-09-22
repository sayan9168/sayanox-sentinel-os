"""
Browser Automation Service
Playwright-based browser control for screenshots, web interaction, and visual logging
"""

import asyncio
import base64
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path
from playwright.async_api import async_playwright, Browser, BrowserContext, Page

logger = logging.getLogger(__name__)


class BrowserAutomation:
    """
    Automated browser controller for web scraping, screenshots,
    and interactive web sessions
    """
    
    def __init__(self, headless: bool = True):
        self.headless = headless
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._screenshots_dir = Path("screenshots")
        self._screenshots_dir.mkdir(exist_ok=True)
    
    async def start(self):
        """Start the browser"""
        if self._browser is None:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=self.headless,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--disable-gpu'
                ]
            )
            
            self._context = await self._browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            
            # Enable request interception for security
            await self._context.route("**/*", self._route_handler)
            
            self._page = await self._context.new_page()
            logger.info("Browser started successfully")
    
    async def _route_handler(self, route, request):
        """Intercept and log network requests"""
        logger.debug(f"Browser request: {request.method} {request.url}")
        await route.continue_()
    
    async def stop(self):
        """Stop the browser"""
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None
        logger.info("Browser stopped")
    
    async def navigate(self, url: str, wait_until: str = "networkidle", 
                       timeout: int = 30000) -> bool:
        """Navigate to a URL"""
        if not self._page:
            await self.start()
        
        try:
            await self._page.goto(url, wait_until=wait_until, timeout=timeout)
            logger.info(f"Navigated to: {url}")
            return True
        except Exception as e:
            logger.error(f"Navigation failed: {e}")
            return False
    
    async def take_screenshot(self, name: Optional[str] = None, 
                              full_page: bool = False) -> Dict[str, Any]:
        """
        Take a screenshot and return base64 encoded image
        """
        if not self._page:
            return {"success": False, "error": "Browser not initialized"}
        
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = name or f"screenshot_{timestamp}.png"
            filepath = self._screenshots_dir / filename
            
            screenshot_bytes = await self._page.screenshot(
                full_page=full_page,
                type="png"
            )
            
            # Save to file
            with open(filepath, "wb") as f:
                f.write(screenshot_bytes)
            
            # Return base64 for UI display
            base64_image = base64.b64encode(screenshot_bytes).decode('utf-8')
            
            logger.info(f"Screenshot saved: {filepath}")
            
            return {
                "success": True,
                "filename": filename,
                "filepath": str(filepath),
                "base64": base64_image,
                "size": len(screenshot_bytes)
            }
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def click(self, selector: str, timeout: int = 5000) -> Dict[str, Any]:
        """Click an element"""
        if not self._page:
            return {"success": False, "error": "Browser not initialized"}
        
        try:
            await self._page.click(selector, timeout=timeout)
            logger.info(f"Clicked: {selector}")
            return {"success": True, "selector": selector}
        except Exception as e:
            logger.error(f"Click failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def fill(self, selector: str, value: str, timeout: int = 5000) -> Dict[str, Any]:
        """Fill an input field"""
        if not self._page:
            return {"success": False, "error": "Browser not initialized"}
        
        try:
            await self._page.fill(selector, value, timeout=timeout)
            logger.info(f"Filled {selector} with value")
            return {"success": True, "selector": selector}
        except Exception as e:
            logger.error(f"Fill failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def evaluate(self, javascript: str) -> Any:
        """Execute JavaScript and return result"""
        if not self._page:
            return None
        
        try:
            result = await self._page.evaluate(javascript)
            return result
        except Exception as e:
            logger.error(f"Evaluate failed: {e}")
            return None
    
    async def get_content(self) -> str:
        """Get page HTML content"""
        if not self._page:
            return ""
        
        return await self._page.content()
    
    async def get_text(self, selector: str) -> str:
        """Get text content of an element"""
        if not self._page:
            return ""
        
        try:
            element = await self._page.query_selector(selector)
            if element:
                return await element.text_content()
            return ""
        except Exception as e:
            logger.error(f"Get text failed: {e}")
            return ""
    
    async def wait_for_selector(self, selector: str, timeout: int = 10000,
                                state: str = "visible") -> bool:
        """Wait for an element to appear"""
        if not self._page:
            return False
        
        try:
            await self._page.wait_for_selector(selector, timeout=timeout, state=state)
            return True
        except Exception as e:
            logger.error(f"Wait for selector failed: {e}")
            return False
    
    async def scrape_security_advisories(self) -> List[Dict[str, Any]]:
        """
        Scrape security advisories from multiple sources
        """
        advisories = []
        
        sources = [
            {
                "name": "CISA",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
                "selector": ".usa-card__body"
            },
            {
                "name": "NVD",
                "url": "https://nvd.nist.gov/vuln/general",
                "selector": ".data-table"
            }
        ]
        
        for source in sources:
            try:
                await self.navigate(source["url"])
                await asyncio.sleep(2)  # Wait for dynamic content
                
                content = await self.get_content()
                
                # Extract relevant data using JavaScript
                items = await self.evaluate(f"""
                    () => {{
                        const items = document.querySelectorAll('{source["selector"]}');
                        return Array.from(items).slice(0, 5).map(item => ({{
                            title: item.querySelector('h3, h4, .title')?.textContent?.trim() || 'Unknown',
                            link: item.querySelector('a')?.href || '',
                            date: item.querySelector('time, .date')?.textContent?.trim() || ''
                        }}));
                    }}
                """)
                
                if items:
                    for item in items:
                        advisories.append({
                            "source": source["name"],
                            **item
                        })
                
            except Exception as e:
                logger.error(f"Failed to scrape {source['name']}: {e}")
        
        return advisories
    
    async def solve_captcha(self, selector: str = "#captcha") -> Dict[str, Any]:
        """
        Attempt to handle simple captchas (for demo purposes)
        Note: Real captcha solving requires ML models or external services
        """
        if not self._page:
            return {"success": False, "error": "Browser not initialized"}
        
        # Check if captcha element exists
        exists = await self.wait_for_selector(selector, timeout=3000, state="attached")
        
        if not exists:
            return {"success": True, "message": "No captcha detected"}
        
        # For demo: try to find and click any visible challenge
        try:
            # This is a placeholder - real implementation would use ML
            await self.take_screenshot("captcha_challenge")
            
            return {
                "success": False,
                "message": "Captcha detected - manual intervention required",
                "screenshot": "captcha_challenge.png"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def interact_with_element(self, action: str, selector: str,
                                    value: Optional[str] = None) -> Dict[str, Any]:
        """
        Generic element interaction
        """
        actions = {
            "click": lambda: self.click(selector),
            "fill": lambda: self.fill(selector, value or ""),
            "hover": lambda: self._page.hover(selector) if self._page else None,
            "focus": lambda: self._page.focus(selector) if self._page else None
        }
        
        if action not in actions:
            return {"success": False, "error": f"Unknown action: {action}"}
        
        result = await actions[action]()
        return result if result else {"success": True}


# Global browser automation instance
browser_automation = BrowserAutomation(headless=True)
