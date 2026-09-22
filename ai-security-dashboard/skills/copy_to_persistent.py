"""
Copy skill module to .skills directory for persistent storage
"""

import shutil
from pathlib import Path

def copy_skill_to_persistent_storage():
    """Copy threat_scraper.py to .skills directory"""
    source = Path(__file__).parent / "threat_scraper.py"
    dest = Path(__file__).parent.parent / ".skills" / "threat_scraper.py"
    
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(source, dest)
    
    print(f"Skill copied to: {dest}")


if __name__ == "__main__":
    copy_skill_to_persistent_storage()
