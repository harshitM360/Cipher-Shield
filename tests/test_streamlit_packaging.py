from pathlib import Path
import py_compile


def test_streamlit_packaging_files_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    required = [
        root / "streamlit_app.py",
        root / "Dockerfile",
        root / "docker-compose.yml",
        root / ".dockerignore",
        root / "docs" / "streamlit_docker_guide.md",
    ]
    for path in required:
        assert path.exists(), f"Missing expected file: {path}"


def test_streamlit_app_compiles() -> None:
    root = Path(__file__).resolve().parents[1]
    py_compile.compile(str(root / "streamlit_app.py"), doraise=True)
