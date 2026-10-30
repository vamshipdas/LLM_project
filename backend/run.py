import uvicorn
import os
import sys

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("Starting Smart Threat Response Assistant Backend...")
    print("API Documentation available at: http://127.0.0.1:8123/docs")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8123, reload=True)
