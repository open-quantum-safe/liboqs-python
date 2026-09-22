import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import oqs.oqs

LIBOQS_URL = "https://github.com/open-quantum-safe/liboqs"


def install_with_recorded_commands(
    commands: list[tuple[object, dict[str, object]]],
    target_directory: Path,
    oqs_version_to_install: str | None,
    returncode: int = 0,
) -> None:
    """Run _install_liboqs, recording each command instead of executing it."""

    def fake_run(args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append((args, kwargs))
        return subprocess.CompletedProcess(args, returncode)  # type: ignore[arg-type]

    def fake_call(args: object, **kwargs: object) -> int:
        commands.append((args, kwargs))
        return returncode

    # subprocess.call is also recorded so that a regression to it cannot start a
    # real clone and build during the tests.
    with (
        mock.patch.object(oqs.oqs.subprocess, "run", fake_run),
        mock.patch.object(oqs.oqs.subprocess, "call", fake_call),
        mock.patch.object(oqs.oqs, "_countdown"),
    ):
        oqs.oqs._install_liboqs(target_directory, oqs_version_to_install)  # noqa: SLF001


def test_install_commands_are_not_run_through_a_shell() -> None:
    target_directory = Path(tempfile.gettempdir()) / "oqs dir; echo INJECTED"
    commands: list[tuple[object, dict[str, object]]] = []
    install_with_recorded_commands(commands, target_directory, "0.16.0")

    assert len(commands) == 4  # noqa: S101
    for args, kwargs in commands:
        assert isinstance(args, list), f"expected an argument list, got {args!r}"  # noqa: S101
        assert not kwargs.get("shell"), f"command run through a shell: {args!r}"  # noqa: S101

    clone, configure, build, install = (args for args, _ in commands)
    assert clone[:5] == ["git", "clone", "--depth", "1", "--branch=0.16.0"]  # noqa: S101
    assert clone[5] == LIBOQS_URL  # noqa: S101
    assert configure[0] == "cmake"  # noqa: S101
    assert f"-DCMAKE_INSTALL_PREFIX={target_directory}" in configure  # noqa: S101
    assert build[:2] == ["cmake", "--build"]  # noqa: S101
    assert install[:2] == ["cmake", "--build"]  # noqa: S101
    assert install[-2:] == ["--target", "install"]  # noqa: S101


def test_liboqs_version_selects_git_branch() -> tuple[None, str]:
    cases = [
        ("0.16.0", "--branch=0.16.0"),
        ("0.16.0.1", "--branch=0.16.0"),
        ("0.14.0rc1", "--branch=0.14.0-rc1"),
        ("0.14.0-rc1", "--branch=0.14.0-rc1"),
        ("0.16.1.dev0", None),
        ("0.16.1-dev", None),
        (None, None),
    ]
    for oqs_version_to_install, expected_branch_arg in cases:
        yield check_liboqs_version_selects_git_branch, oqs_version_to_install, expected_branch_arg


def check_liboqs_version_selects_git_branch(
    oqs_version_to_install: str | None,
    expected_branch_arg: str | None,
) -> None:
    commands: list[tuple[object, dict[str, object]]] = []
    install_with_recorded_commands(commands, Path("liboqs-install"), oqs_version_to_install)
    clone = commands[0][0]
    assert isinstance(clone, list), f"expected an argument list, got {clone!r}"  # noqa: S101
    branch_args = [arg for arg in clone if arg.startswith("--branch")]
    expected = [expected_branch_arg] if expected_branch_arg else []
    assert branch_args == expected, f"{oqs_version_to_install!r}: {branch_args!r}"  # noqa: S101


def test_invalid_liboqs_version_is_rejected() -> tuple[None, str]:
    for oqs_version_to_install in [
        "0.15.0; id; echo INJECTED; #",
        "0.15.0rc1; id; echo INJECTED; #",
        "$(id)",
        "0.16.0 --upload-pack=touch",
        "--upload-pack=touch",
        "main",
    ]:
        yield check_invalid_liboqs_version_is_rejected, oqs_version_to_install


def check_invalid_liboqs_version_is_rejected(oqs_version_to_install: str) -> None:
    commands: list[tuple[object, dict[str, object]]] = []
    try:
        install_with_recorded_commands(commands, Path("liboqs-install"), oqs_version_to_install)
    except ValueError:
        pass
    else:
        msg = f"{oqs_version_to_install!r} was accepted"
        raise AssertionError(msg)
    assert commands == [], f"commands ran for {oqs_version_to_install!r}"  # noqa: S101


def test_install_stops_at_first_failing_command() -> None:
    commands: list[tuple[object, dict[str, object]]] = []
    try:
        install_with_recorded_commands(commands, Path("liboqs-install"), "0.16.0", returncode=1)
    except SystemExit:
        pass
    else:
        msg = "a failing install command did not abort the install"
        raise AssertionError(msg)
    assert len(commands) == 1  # noqa: S101


if __name__ == "__main__":
    try:
        import nose2

        nose2.main()
    except ImportError:
        msg_ = "nose2 module not found. Please install it with 'pip install nose2'."
        raise RuntimeError(msg_) from None
