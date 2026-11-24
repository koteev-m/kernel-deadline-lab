"""Run just the selected offline transport experiment."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import host

if __name__=='__main__':
    record=host.run_guest(Path(sys.argv[1]),'xray-repro')
    sys.exit(0 if record.get('trial') and record.get('transport',{}).get('reality') else 1)
