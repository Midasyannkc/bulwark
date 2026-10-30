.PHONY: install test report incidents verify
install:
	pip install -r requirements.txt --break-system-packages
test:
	python3 -m pytest -q
report:
	python3 -m bulwark
incidents:
	python3 scripts/incidents.py
verify:
	python3 scripts/verify_incidents.py
