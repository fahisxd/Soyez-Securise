#!/bin/bash
cd 'Ayano V2'
source .venv/bin/activate
uvicorn main:app --reload
