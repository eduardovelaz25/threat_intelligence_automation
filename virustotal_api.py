from fastapi import FastAPI, HTTPException, Query
import os
import io
import contextlib

# Import the existing script as a module and reuse its functions without editing it
import virustotal_ingest

app = FastAPI()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/reputation")
def reputation(ioc: str = Query(..., description="Indicator of compromise (IP, URL, domain, hash)")):
    # Ensure API key is available
    if "VIRUSTOTAL_API_KEY" not in os.environ:
        raise HTTPException(status_code=500, detail="VIRUSTOTAL_API_KEY not set")

    buf = io.StringIO()
    try:
        # many functions in virustotal_ingest print their results rather than returning them
        # capture stdout and return the captured text as the API response
        with contextlib.redirect_stdout(buf):
            virustotal_ingest.ioc_reputation_check(ioc)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    output = buf.getvalue()
    return {"ioc": ioc, "output": output}
