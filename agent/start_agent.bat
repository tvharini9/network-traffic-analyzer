@echo off
cd /d "C:\Users\Harini.T.V\OneDrive\Desktop\proj\net traffic\network-analyzer\agent"
"C:\Users\Harini.T.V\OneDrive\Desktop\proj\net traffic\network-analyzer\agent\venv\Scripts\python.exe" capture_agent.py --backend "wss://network-production-9277.up.railway.app/ws/ingest" --token "networktrafficanalyzer-proj1"

