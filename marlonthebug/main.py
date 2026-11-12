"""MarlonTheBug CLI entry point."""

from marlonthebug.cli.app import cli

app = cli


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
