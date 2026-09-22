"""
Skills API Router
Endpoints for skill logging and retrieval
"""

from fastapi import APIRouter, HTTPException, Query, Body
from typing import List, Optional

from backend.models.schemas import SkillLog, SkillsResponse

router = APIRouter()


@router.get("/", response_model=SkillsResponse)
async def get_skills(category: Optional[str] = Query(default=None)):
    """Get all logged skills, optionally filtered by category"""
    from backend.main import connection_manager
    
    db_manager = connection_manager.get("db_manager")
    
    if not db_manager:
        return SkillsResponse(
            skills=[],
            count=0,
            categories=[]
        )
    
    skills_data = db_manager.get_skills(category=category)
    categories = db_manager.get_skill_categories()
    
    return SkillsResponse(
        skills=[SkillLog(**s) for s in skills_data],
        count=len(skills_data),
        categories=categories
    )


@router.post("/", response_model=SkillLog)
async def create_skill(skill: SkillLog = Body(...)):
    """Create a new skill log entry"""
    from backend.main import connection_manager
    
    db_manager = connection_manager.get("db_manager")
    
    if not db_manager:
        raise HTTPException(status_code=503, detail="Database not available")
    
    skill_data = skill.model_dump()
    skill_id = db_manager.insert_skill(skill_data)
    
    # Fetch the created skill
    skills = db_manager.get_skills()
    for s in skills:
        if s.get("id") == skill_id:
            return SkillLog(**s)
    
    return skill


@router.get("/categories", response_model=List[str])
async def get_skill_categories():
    """Get all unique skill categories"""
    from backend.main import connection_manager
    
    db_manager = connection_manager.get("db_manager")
    
    if not db_manager:
        return []
    
    return db_manager.get_skill_categories()


@router.get("/stats")
async def get_skills_stats():
    """Get skills statistics"""
    from backend.main import connection_manager
    
    db_manager = connection_manager.get("db_manager")
    
    if not db_manager:
        return {
            "total": 0,
            "by_category": {}
        }
    
    skills_data = db_manager.get_skills()
    categories = db_manager.get_skill_categories()
    
    # Count by category
    category_counts = {}
    for skill in skills_data:
        cat = skill.get("category", "Unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1
    
    return {
        "total": len(skills_data),
        "by_category": category_counts,
        "categories": categories
    }
