# Testing Instructions

This project uses `pytest` for unit testing.

## Prerequisites

Install the test dependencies:


```bash
pip install -r requirements.txt
pip install pytest
```


## Running Tests

Run all tests from the project root directory:

```bash
python -m pytest tests/
```

## Test Structure

- `tests/test_nmap_scanner.py`: Tests for Nmap scanning logic and risk scoring
- `tests/test_suricata_parser.py`: Tests for Suricata EVE JSON parsing
