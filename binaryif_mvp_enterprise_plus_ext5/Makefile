
install:
	pip install -r requirements.txt

keys:
	python tools/gen_keys.py

run:
	uvicorn app.main:app --reload

test:
	pytest -q

conformance:
	python tools/conformance_report.py
