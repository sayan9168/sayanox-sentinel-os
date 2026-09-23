"""
Remote GUI Streaming & Automation Module
Lightweight headless VNC / HTML5 canvas stream for desktop interaction
"""

import os
import asyncio
import logging
import subprocess
import platform
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class RemoteGUIManager:
    """
    Remote GUI Streaming Manager
    Provides lightweight desktop streaming capabilities
    """
    
    def __init__(self):
        self.system = platform.system()
        self.is_streaming = False
        self.stream_port = 6080
        self.vnc_port = 5900
    
    def _run_command(self, command: list, timeout: int = 30) -> Dict[str, Any]:
        """Run a system command and return result."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def check_x11_available(self) -> bool:
        """Check if X11 display server is available (Linux)."""
        if self.system != "Linux":
            return False
        
        display = os.environ.get("DISPLAY", "")
        if not display:
            return False
        
        # Try to run xdotool or xdpyinfo
        result = self._run_command(["xdotool", "--version"])
        return result["success"]
    
    def check_quartz_available(self) -> bool:
        """Check if Quartz/CGSession is available (macOS)."""
        if self.system != "Darwin":
            return False
        
        # macOS screen sharing check
        result = self._run_command(["defaults", "read", "com.apple.RemoteManagement", "ARDAgent"])
        return result["success"]
    
    def start_vnc_server(self, password: Optional[str] = None) -> Dict[str, Any]:
        """
        Start a VNC server for remote desktop access.
        Note: Requires x11vnc or similar to be installed on Linux.
        """
        if self.system == "Linux":
            return self._start_x11vnc(password)
        elif self.system == "Darwin":
            return self._start_macos_screen_sharing()
        elif self.system == "Windows":
            return self._start_windows_remote_desktop()
        
        return {"success": False, "error": f"Unsupported OS: {self.system}"}
    
    def _start_x11vnc(self, password: Optional[str] = None) -> Dict[str, Any]:
        """Start x11vnc on Linux."""
        # Check if x11vnc is installed
        check_result = self._run_command(["which", "x11vnc"])
        if not check_result["success"]:
            return {
                "success": False, 
                "error": "x11vnc not installed. Install with: sudo apt-get install x11vnc",
                "install_command": "sudo apt-get install x11vnc"
            }
        
        cmd = ["x11vnc", "-display", os.environ.get("DISPLAY", ":0"), "-forever", "-shared"]
        
        if password:
            # Create VNC password file
            passwd_file = os.path.join(os.path.dirname(__file__), ".vnc_pass")
            self._run_command(["x11vnc", "-storepasswd", password, passwd_file])
            cmd.extend(["-rfbauth", passwd_file])
        else:
            cmd.append("-nopw")
        
        cmd.extend(["-listen", "0.0.0.0", "-httpport", str(self.stream_port)])
        
        # Start in background
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            self.is_streaming = True
            logger.info(f"Started x11vnc server on port {self.vnc_port}, HTTP on {self.stream_port}")
            
            return {
                "success": True,
                "message": "VNC server started",
                "vnc_port": self.vnc_port,
                "http_port": self.stream_port,
                "url": f"http://localhost:{self.stream_port}"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _start_macos_screen_sharing(self) -> Dict[str, Any]:
        """Enable macOS Screen Sharing."""
        # Enable Remote Management
        enable_cmd = [
            "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
            "-activate",
            "-configure", "-allowAccessFor", "allUsers",
            "-configure", "-access", "-on",
            "-restart", "-agent"
        ]
        
        result = self._run_command(enable_cmd)
        
        if result["success"]:
            self.is_streaming = True
            return {
                "success": True,
                "message": "macOS Screen Sharing enabled",
                "connection_url": "vnc://localhost:5900"
            }
        
        return result
    
    def _start_windows_remote_desktop(self) -> Dict[str, Any]:
        """Configure Windows Remote Desktop."""
        # Enable RDP through registry
        enable_cmd = [
            "reg", "add",
            "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server",
            "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "0", "/f"
        ]
        
        result = self._run_command(enable_cmd)
        
        if result["success"]:
            # Allow through firewall
            fw_cmd = [
                "netsh", "advfirewall", "firewall", "set", "rule",
                "group=\"Remote Desktop\"", "new", "enable=Yes"
            ]
            self._run_command(fw_cmd)
            
            self.is_streaming = True
            return {
                "success": True,
                "message": "Windows Remote Desktop enabled",
                "connection_url": "rdp://localhost:3389"
            }
        
        return result
    
    def stop_vnc_server(self) -> Dict[str, Any]:
        """Stop the VNC server."""
        if self.system == "Linux":
            result = self._run_command(["pkill", "-f", "x11vnc"])
            self.is_streaming = False
            return {"success": True, "message": "VNC server stopped"}
        
        elif self.system == "Darwin":
            disable_cmd = [
                "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
                "-deactivate", "-stop"
            ]
            result = self._run_command(disable_cmd)
            self.is_streaming = False
            return result
        
        elif self.system == "Windows":
            # Disable RDP
            disable_cmd = [
                "reg", "add",
                "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server",
                "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f"
            ]
            result = self._run_command(disable_cmd)
            self.is_streaming = False
            return result
        
        return {"success": False, "error": f"Unsupported OS: {self.system}"}
    
    def take_screenshot(self) -> Dict[str, Any]:
        """Take a screenshot of the current desktop."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        screenshot_dir = os.path.join(os.path.dirname(__file__), "..", "..", "screenshots")
        os.makedirs(screenshot_dir, exist_ok=True)
        screenshot_path = os.path.join(screenshot_dir, f"screenshot_{timestamp}.png")
        
        if self.system == "Linux":
            cmd = ["gnome-screenshot", "-f", screenshot_path]
            # Alternative: ["scrot", screenshot_path]
        elif self.system == "Darwin":
            cmd = ["screencapture", screenshot_path]
        elif self.system == "Windows":
            # Use PowerShell for screenshot
            ps_script = f"""
            Add-Type -AssemblyName System.Windows.Forms
            $screen = [System.Windows.Forms.Screen]::PrimaryScreen
            $bitmap = New-Object System.Drawing.Bitmap $screen.Bounds.Width, $screen.Bounds.Height
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            $graphics.CopyFromScreen($screen.Bounds.Location, [System.Drawing.Point]::Empty, $screen.Bounds.Size)
            $bitmap.Save('{screenshot_path}')
            $graphics.Dispose()
            $bitmap.Dispose()
            """
            cmd = ["powershell", "-Command", ps_script]
        else:
            return {"success": False, "error": f"Unsupported OS: {self.system}"}
        
        result = self._run_command(cmd)
        
        if result["success"] and os.path.exists(screenshot_path):
            return {
                "success": True,
                "path": screenshot_path,
                "size": os.path.getsize(screenshot_path)
            }
        
        return result
    
    def get_gui_status(self) -> Dict[str, Any]:
        """Get current GUI streaming status."""
        return {
            "is_streaming": self.is_streaming,
            "system": self.system,
            "vnc_port": self.vnc_port,
            "http_port": self.stream_port,
            "x11_available": self.check_x11_available() if self.system == "Linux" else False
        }
    
    def simulate_keypress(self, keys: str) -> Dict[str, Any]:
        """Simulate keyboard input (requires xdotool on Linux)."""
        if self.system == "Linux":
            result = self._run_command(["xdotool", "key", keys])
            return result
        elif self.system == "Darwin":
            result = self._run_command(["osascript", "-e", f'tell application "System Events" to keystroke "{keys}"'])
            return result
        return {"success": False, "error": "Keypress simulation not supported on this platform"}
    
    def simulate_click(self, button: str = "left") -> Dict[str, Any]:
        """Simulate mouse click."""
        if self.system == "Linux":
            result = self._run_command(["xdotool", "click", button])
            return result
        return {"success": False, "error": "Click simulation not supported on this platform"}
    
    def move_mouse(self, x: int, y: int) -> Dict[str, Any]:
        """Move mouse to specific coordinates."""
        if self.system == "Linux":
            result = self._run_command(["xdotool", "mousemove", str(x), str(y)])
            return result
        return {"success": False, "error": "Mouse movement not supported on this platform"}


# Global instance
gui_manager = RemoteGUIManager()
