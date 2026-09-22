"""
Browser Automation API Router
Screenshots, web interaction, and visual logging
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import Optional, Dict, Any
import base64

from backend.routers.auth import get_current_user, require_role
from backend.middleware.security import limiter
from backend.services.browser_automation import browser_automation

router = APIRouter()


@router.post("/browser/start")
@limiter.limit("5/minute")
async def start_browser(request, current_user: dict = Depends(require_role("admin"))):
    """Start the browser automation engine (admin only)"""
    try:
        await browser_automation.start()
        return {"success": True, "message": "Browser started"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start browser: {str(e)}"
        )


@router.post("/browser/stop")
async def stop_browser(current_user: dict = Depends(require_role("admin"))):
    """Stop the browser automation engine (admin only)"""
    await browser_automation.stop()
    return {"success": True, "message": "Browser stopped"}


@router.post("/browser/navigate")
async def browser_navigate(
    request,
    navigate_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Navigate to a URL"""
    url = navigate_data.get("url")
    wait_until = navigate_data.get("wait_until", "networkidle")
    timeout = navigate_data.get("timeout", 30000)
    
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is required"
        )
    
    success = await browser_automation.navigate(url, wait_until, timeout)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to navigate to URL"
        )
    
    return {"success": True, "url": url}


@router.post("/browser/screenshot")
async def take_screenshot(
    request,
    screenshot_data: Optional[dict] = None,
    current_user: dict = Depends(get_current_user)
):
    """Take a screenshot of the current page"""
    name = screenshot_data.get("name") if screenshot_data else None
    full_page = screenshot_data.get("full_page", False) if screenshot_data else False
    
    result = await browser_automation.take_screenshot(name, full_page)
    
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result.get("error", "Screenshot failed")
        )
    
    # Return without base64 by default (too large)
    return {
        "success": True,
        "filename": result["filename"],
        "filepath": result["filepath"],
        "size": result["size"]
    }


@router.get("/browser/screenshot/{filename}")
async def get_screenshot(
    request,
    filename: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a screenshot as base64 image"""
    from pathlib import Path
    
    filepath = browser_automation._screenshots_dir / filename
    
    if not filepath.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Screenshot not found"
        )
    
    with open(filepath, "rb") as f:
        image_bytes = f.read()
    
    base64_image = base64.b64encode(image_bytes).decode('utf-8')
    
    return {
        "success": True,
        "filename": filename,
        "content_type": "image/png",
        "base64": base64_image
    }


@router.post("/browser/click")
async def browser_click(
    request,
    click_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Click an element on the page"""
    selector = click_data.get("selector")
    timeout = click_data.get("timeout", 5000)
    
    if not selector:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Selector is required"
        )
    
    result = await browser_automation.click(selector, timeout)
    
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result.get("error", "Click failed")
        )
    
    return result


@router.post("/browser/fill")
async def browser_fill(
    request,
    fill_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Fill an input field"""
    selector = fill_data.get("selector")
    value = fill_data.get("value")
    timeout = fill_data.get("timeout", 5000)
    
    if not selector or value is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Selector and value are required"
        )
    
    result = await browser_automation.fill(selector, value, timeout)
    
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result.get("error", "Fill failed")
        )
    
    return result


@router.post("/browser/evaluate")
async def browser_evaluate(
    request,
    eval_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Execute JavaScript and return result"""
    javascript = eval_data.get("javascript")
    
    if not javascript:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="JavaScript code is required"
        )
    
    result = await browser_automation.evaluate(javascript)
    
    return {
        "success": True,
        "result": result
    }


@router.get("/browser/content")
async def get_page_content(
    request,
    current_user: dict = Depends(get_current_user)
):
    """Get the HTML content of the current page"""
    content = await browser_automation.get_content()
    return {
        "success": True,
        "content": content[:10000]  # Limit size
    }


@router.get("/browser/text/{selector}")
async def get_element_text(
    request,
    selector: str,
    current_user: dict = Depends(get_current_user)
):
    """Get text content of a specific element"""
    text = await browser_automation.get_text(selector)
    return {
        "success": True,
        "selector": selector,
        "text": text
    }


@router.post("/browser/scrape")
async def scrape_advisories(
    request,
    current_user: dict = Depends(get_current_user)
):
    """Scrape security advisories from configured sources"""
    advisories = await browser_automation.scrape_security_advisories()
    return {
        "success": True,
        "count": len(advisories),
        "advisories": advisories
    }


@router.post("/browser/captcha")
async def handle_captcha(
    request,
    captcha_data: Optional[dict] = None,
    current_user: dict = Depends(get_current_user)
):
    """Attempt to handle captcha (demo purposes)"""
    selector = captcha_data.get("selector", "#captcha") if captcha_data else "#captcha"
    result = await browser_automation.solve_captcha(selector)
    return result
