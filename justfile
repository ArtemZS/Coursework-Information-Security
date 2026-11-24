set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

default:
    @just --list

setup:
    uv sync --locked

run *args:
    uv run --locked python -m image_messenger {{args}}

test:
    uv run --locked python -m unittest discover -s tests -v
