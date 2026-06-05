import typer

app = typer.Typer()


@app.command()
def version() -> None:
    typer.echo("mylilpwny 0.1.0")


if __name__ == "__main__":
    app()
