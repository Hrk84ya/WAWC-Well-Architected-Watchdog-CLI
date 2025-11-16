# Contributing to WAWC

Thank you for your interest in contributing to WAWC!

## Development Setup

### Prerequisites

- Python 3.10 or higher
- pip or pipx
- Git

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Hrk84ya/WAWC-Well-Architected-Watchdog-CLI.git
cd WAWC-Well-Architected-Watchdog-CLI
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install in development mode:
```bash
pip install -e ".[dev]"
```

4. Install pre-commit hooks (optional):
```bash
pip install pre-commit
pre-commit install
```

## Development Workflow

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=wawc --cov-report=html

# Run specific test file
pytest tests/test_s3.py

# Run with verbose output
pytest -v
```

### Linting

```bash
# Check code style
ruff check src/ tests/

# Auto-fix issues
ruff check --fix src/ tests/
```

### Type Checking

```bash
# Run mypy
mypy src/wawc
```

### Running Locally

```bash
# Install in editable mode
pip install -e .

# Run CLI
wawc scan --checks s3 --region us-east-1 --format table

# With verbose logging
wawc -v scan --checks s3,sg,rds --region us-east-1
```

## Adding New Checks

To add a new AWS service check:

1. Create a new file in `src/wawc/checks/` (e.g., `lambda.py`)
2. Implement the check function following this pattern:

```python
def check_lambda_functions(
    session: boto3.Session, region: str
) -> tuple[list[Finding], list[dict[str, str]]]:
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []
    
    # Your check logic here
    
    return findings, errors
```

3. Register the check in `src/wawc/engine/runner.py`:

```python
CHECK_REGISTRY = {
    "s3": check_s3_public_buckets,
    "sg": check_security_groups,
    "rds": check_rds_backups,
    "lambda": check_lambda_functions,  # Add your check
}
```

4. Add tests in `tests/test_lambda.py`
5. Update documentation

## Code Style

- Follow PEP 8
- Use type hints for all functions
- Write docstrings for public functions
- Keep functions focused and small
- Use meaningful variable names

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Run linting and type checking
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to your fork (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### PR Guidelines

- Provide a clear description of the changes
- Reference any related issues
- Include test coverage for new code
- Update documentation as needed
- Keep PRs focused on a single feature/fix

## Testing Guidelines

- Write unit tests for all new functions
- Use botocore.stub for mocking AWS API calls
- Aim for >80% code coverage
- Test both success and error cases
- Use descriptive test names

## Documentation

- Update README.md for user-facing changes
- Add docstrings to new functions
- Update SECURITY.md for security-related changes
- Keep examples up to date

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions or ideas
- Contact via [GitHub Issues](https://github.com/Hrk84ya/WAWC-Well-Architected-Watchdog-CLI/issues)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
