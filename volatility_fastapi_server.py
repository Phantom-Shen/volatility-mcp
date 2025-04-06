"""
Volatility Memory Analysis FastAPI Server
This module implements a FastAPI server that provides RESTful endpoints for memory analysis
using Volatility3 framework. It includes a plugin system for different types of memory analysis
and supports Windows memory dumps.
The server provides the following endpoints:
- /plugins: Lists all available Volatility plugins
- /analyze/{plugin_name}: Analyzes memory dump with a specific plugin
- /analyze: Analyzes memory dump with all available plugins
Features:
- Plugin-based architecture for extensible memory analysis
- RESTful API interface
- Error handling and async operations
- Integration with FastMCP for microservice architecture
@author: @Gaffx
@version: 1.0.0
"""

import subprocess
import os
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from mcp.server.fastmcp import FastMCP


class VolatilityPlugin(ABC):
    """Base class for Volatility plugins"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    @abstractmethod
    def run(self, image_path: str) -> str:
        """Run the plugin on the specified memory image"""
        pass
    
    def get_info(self) -> Dict[str, str]:
        """Get plugin information"""
        return {
            "name": self.name,
            "description": self.description
        }


class WindowsPlugin(VolatilityPlugin):
    """Windows-specific Volatility plugin"""
    
    def __init__(self, name: str, plugin_name: str, description: str):
        super().__init__(name, description)
        self.plugin_name = plugin_name
    
    def run(self, image_path: str) -> str:
        """Run the Windows plugin on the specified memory image"""
        vol_bin = os.getenv('VOLATILITY_BIN')
        if not vol_bin:
            raise RuntimeError("VOLATILITY_BIN') environment variable is not set")
            
        if not os.path.exists(vol_bin):
            raise RuntimeError(f"Volatility executable not found at {vol_bin}")
            
        result = subprocess.run(
            [vol_bin, '-f', image_path, self.plugin_name],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise RuntimeError(f"Plugin {self.name} failed: {result.stderr}")
        return result.stdout


class VolatilityAnalyzer:
    """Class to manage Volatility analysis"""
    
    def __init__(self):
        # Initialize the analyzer with an empty plugin registry and its type is Dict[str, VolatilityPlugin]
        # This is a dictionary that maps plugin names to their corresponding VolatilityPlugin instances.
        self.plugins: Dict[str, VolatilityPlugin] = {}
    
    def register_plugin(self, plugin: VolatilityPlugin) -> None:
        """Register a plugin with the analyzer"""
        self.plugins[plugin.name] = plugin
    
    def get_plugin(self, name: str) -> Optional[VolatilityPlugin]:
        """Get a registered plugin by name"""
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[Dict[str, str]]:
        """List all registered plugins"""
        return [plugin.get_info() for plugin in self.plugins.values()]
    
    def analyze(self, image_path: str, plugin_name: str) -> str:
        """Run analysis using the specified plugin"""
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            raise ValueError(f"Plugin {plugin_name} not found")
        return plugin.run(image_path)
    
    def analyze_all(self, image_path: str) -> Dict[str, str]:
        """Run analysis using all registered plugins"""
        results = {}
        for name, plugin in self.plugins.items():
            try:
                results[name] = plugin.run(image_path)
            except Exception as e:
                results[name] = f"Error: {str(e)}"
        return results
    
    def validate_plugins(self) -> List[str]:
        """Validate all registered plugins and return any errors"""
        errors = []
        
        # Check VOLATILITY_BIN environment variable once
        vol_bin = os.getenv('VOLATILITY_BIN')
        if not vol_bin:
            errors.append("VOLATILITY_BIN environment variable is not set")
            return errors  # Return early since we can't proceed without the binary
        
        if not os.path.exists(vol_bin):
            errors.append(f"Volatility executable not found at {vol_bin}")
            return errors  # Return early since we can't proceed without valid binary
            
        # Validate individual plugins
        for name, plugin in self.plugins.items():
            try:
                if isinstance(plugin, WindowsPlugin):
                    # No need to check vol_bin again, we already validated it
                    pass
            except Exception as e:
                errors.append(f"Plugin {name} validation failed: {str(e)}")
        
        return errors


# Initialize the analyzer and register plugins
analyzer = VolatilityAnalyzer()
analyzer.register_plugin(WindowsPlugin("process", "windows.pslist.PsList", "Get process information from memory image"))
analyzer.register_plugin(WindowsPlugin("connections", "windows.netscan.NetScan", "Get network connection information from memory image"))
analyzer.register_plugin(WindowsPlugin("cmdline", "windows.cmdline.CmdLine", "Get command line information from memory image"))

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Validate plugins on startup
    errors = analyzer.validate_plugins()
    if errors:
        error_message = """
╔════════════════════════════════════════════════════════════════════════════════╗
║                              Configuration Error                               ║
╚════════════════════════════════════════════════════════════════════════════════╝

The following errors were detected during startup:
{}
To resolve this issue:

1. Set the VOLATILITY_BIN environment variable to point to your Volatility executable:
2. Ensure the path points to a valid Volatility installation
3. Restart the server

For more information, visit: https://volatility3.readthedocs.io/
""".format("\n".join(f"  • {error}" for error in errors))
        
        raise RuntimeError(error_message)
    yield

# Initialize FastAPI with lifespan
app = FastAPI(lifespan=lifespan)

# Initialize FastAPI and MCP
vol_url = "http://localhost:8000/analyze"
mcp = FastMCP("vol-mcp")


@app.get("/plugins")
async def list_plugins():
    """Endpoint to list available plugins"""
    return {"plugins": analyzer.list_plugins()}


@app.get("/analyze/{plugin_name}")
async def analyze_with_plugin(plugin_name: str, image_path: str):
    """Endpoint to analyze memory using a specific plugin"""
    try:
        plugin = analyzer.get_plugin(plugin_name)
        if not plugin:
            raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
        result = plugin.run(image_path)
        return {plugin_name: result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/analyze")
async def analyze_memory(image_path: str):
    """Endpoint to analyze memory using all plugins"""
    try:
        results = analyzer.analyze_all(image_path)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



