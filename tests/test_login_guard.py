"""A failed KNOSSOS login is remembered so it is not submitted again."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from selenium.common.exceptions import StaleElementReferenceException

from uribo_mcp import auth, live
from uribo_mcp.auth import (
    LOGIN_STATE_KEY,
    MAX_UNCONFIRMED_FAILURES,
    PASSWORD_KEY,
    UNCONFIRMED_RETRY_HOURS,
    USERNAME_KEY,
    KobeCredentials,
    clear_login_state,
    interactive_setup,
    login_block_reason,
    record_login_failure,
)
from uribo_mcp.errors import AuthenticationRequired, CredentialsRejected

KNOSSOS = "https://knossos.center.kobe-u.ac.jp/auth/realms/x/login-actions/authenticate"
BEEF_HOST = "beefplus.center.kobe-u.ac.jp"
SAVED = KobeCredentials("1234567x", "wrong-password")
NOW = datetime(2026, 11, 23, 9, 0, tzinfo=UTC)


class _Field:
    def __init__(self, driver, generation: int) -> None:
        self.driver = driver
        self.generation = generation

    def send_keys(self, text: str) -> None:
        self.driver.typed.append(text)

    def click(self) -> None:
        self.driver.clicks += 1
        self.driver.after_click(self.driver)

    def is_enabled(self) -> bool:
        if self.generation != self.driver.generation:
            raise StaleElementReferenceException()
        return True


class FakeKnossos:
    """A browser on the KNOSSOS form; ``after_click`` decides what the submit does."""

    def __init__(self, after_click) -> None:
        self.current_url = KNOSSOS
        self.after_click = after_click
        self.generation = 0
        self.has_form = True
        self.clicks = 0
        self.typed: list[str] = []
        self.opened: list[str] = []
        self.closed = False

    def get(self, url: str) -> None:
        self.opened.append(url)

    def find_elements(self, by, value):
        return [_Field(self, self.generation)] if self.has_form else []

    def find_element(self, by, value):
        return _Field(self, self.generation)

    def get_cookies(self):
        return [{"name": "JSESSIONID", "value": "cookie-value", "domain": BEEF_HOST}]

    def quit(self) -> None:
        self.closed = True


def form_again(driver) -> None:
    driver.generation += 1  # KNOSSOS reloads and shows the form with an error


def signed_in(driver) -> None:
    driver.generation += 1
    driver.has_form = False
    driver.current_url = f"https://{BEEF_HOST}/lms/timetable"


def extra_step(driver) -> None:
    driver.generation += 1  # a one-time-code page: still KNOSSOS, no password field
    driver.has_form = False


@pytest.fixture
def saved_login(monkeypatch):
    monkeypatch.setattr(live, "load_credentials", lambda: SAVED)
    # The form never changes in these fakes, so do not wait out the real timeouts.
    from selenium.webdriver.support import ui

    original = ui.WebDriverWait.__init__

    def quick(self, driver, timeout, *args, **kwargs):
        original(self, driver, 0.05, 0.01)

    monkeypatch.setattr(ui.WebDriverWait, "__init__", quick)


# ------------------------------------------------------------ recorded state
def test_rejected_login_blocks_until_the_credentials_change(login_state_store) -> None:
    assert login_block_reason(SAVED) is None
    record_login_failure(SAVED, rejected=True, now=NOW)

    reason = login_block_reason(SAVED, now=NOW + timedelta(days=30))
    assert reason and "rejected" in reason and "uribo-mcp setup" in reason
    assert "wrong-password" not in login_state_store.get(LOGIN_STATE_KEY)
    assert "1234567x" not in login_state_store.get(LOGIN_STATE_KEY)
    # A different password is a different login: it gets its own first attempt.
    assert login_block_reason(KobeCredentials("1234567x", "new-password")) is None

    clear_login_state()
    assert login_block_reason(SAVED) is None


def test_unconfirmed_failures_pause_after_three_and_retry_once_a_day(login_state_store) -> None:
    for attempt in range(1, MAX_UNCONFIRMED_FAILURES):
        record_login_failure(SAVED, rejected=False, now=NOW + timedelta(hours=attempt))
        assert login_block_reason(SAVED, now=NOW + timedelta(hours=attempt)) is None
    last = NOW + timedelta(hours=MAX_UNCONFIRMED_FAILURES)
    record_login_failure(SAVED, rejected=False, now=last)

    assert "3 times in a row" in (login_block_reason(SAVED, now=last + timedelta(hours=1)) or "")
    retry = last + timedelta(hours=UNCONFIRMED_RETRY_HOURS)
    assert login_block_reason(SAVED, now=retry) is None
    record_login_failure(SAVED, rejected=False, now=retry)  # the daily retry failed too
    assert login_block_reason(SAVED, now=retry + timedelta(hours=1)) is not None


def test_unreadable_state_never_blocks_or_raises(login_state_store) -> None:
    login_state_store.set(LOGIN_STATE_KEY, "{not json")
    assert login_block_reason(SAVED) is None

    class Broken:
        def get(self, key: str) -> str | None:
            raise RuntimeError("keyring locked")

        def set(self, key: str, value: str) -> None:
            raise RuntimeError("keyring locked")

        def delete(self, key: str) -> None:
            raise RuntimeError("keyring locked")

    assert login_block_reason(SAVED, secret_store=Broken()) is None
    record_login_failure(SAVED, rejected=True, secret_store=Broken())
    clear_login_state(Broken())


# ------------------------------------------------------------- form handling
def test_form_shown_again_is_a_rejected_login_and_is_never_resubmitted(saved_login) -> None:
    driver = FakeKnossos(form_again)
    with pytest.raises(CredentialsRejected):
        live._submit_knossos_form(driver, BEEF_HOST)
    assert driver.clicks == 1 and driver.typed == ["1234567x", "wrong-password"]

    # Next scheduled run: refused before any page is opened or any key is typed.
    second = FakeKnossos(form_again)
    with pytest.raises(AuthenticationRequired, match="rejected"):
        live._login_once(second, f"https://{BEEF_HOST}/saml/login?disco=true", BEEF_HOST)
    with pytest.raises(AuthenticationRequired, match="rejected"):
        live._submit_knossos_form(second, BEEF_HOST)
    assert second.opened == [] and second.clicks == 0 and second.typed == []


def test_moodle_sign_in_is_refused_before_the_browser_starts(saved_login, tmp_path) -> None:
    from uribo_mcp.config import load_settings

    record_login_failure(SAVED, rejected=True)
    with pytest.raises(AuthenticationRequired, match="rejected"):
        live.open_moodle(
            load_settings(root=tmp_path),
            base_url="https://beef.center.kobe-u.ac.jp/2026",
            driver_factory=lambda: pytest.fail("browser opened"),
        )


def test_successful_login_clears_earlier_failures(saved_login) -> None:
    record_login_failure(SAVED, rejected=False)
    record_login_failure(SAVED, rejected=False)
    live._submit_knossos_form(FakeKnossos(signed_in), BEEF_HOST)
    record_login_failure(SAVED, rejected=False)  # counted from one again
    assert login_block_reason(SAVED) is None


def test_extra_sign_in_step_is_not_reported_as_a_wrong_password(saved_login) -> None:
    driver = FakeKnossos(extra_step)
    with pytest.raises(AuthenticationRequired) as caught:
        live._submit_knossos_form(driver, BEEF_HOST)
    assert not isinstance(caught.value, CredentialsRejected)
    assert login_block_reason(SAVED) is None  # one unconfirmed failure does not pause


# ------------------------------------------------------- check before storing
def test_check_reports_ok_with_cookies_and_records_nothing(saved_login, login_state_store) -> None:
    driver = FakeKnossos(signed_in)
    check = live.check_kobe_login("1234567x", "right", driver_factory=lambda: driver)
    assert check.status == "ok" and check.cookies[0]["name"] == "JSESSIONID"
    assert driver.opened == [f"https://{BEEF_HOST}/saml/login?disco=true"]
    assert driver.typed == ["1234567x", "right"] and driver.closed
    assert login_state_store.values == {}


def test_check_reports_rejected_without_pausing_the_saved_login(saved_login, login_state_store) -> None:
    driver = FakeKnossos(form_again)
    check = live.check_kobe_login("1234567x", "typo", driver_factory=lambda: driver)
    assert check.status == "rejected" and check.cookies == () and driver.closed
    assert login_state_store.values == {}


def test_check_is_unverified_when_the_answer_is_unknown(saved_login) -> None:
    def no_browser():
        raise OSError("chrome not found")

    assert live.check_kobe_login("u", "p", driver_factory=no_browser).status == "unverified"
    stuck = live.check_kobe_login("u", "p", driver_factory=lambda: FakeKnossos(extra_step))
    assert stuck.status == "unverified" and stuck.cookies == ()


def test_check_ignores_a_pause_on_the_saved_login(saved_login) -> None:
    record_login_failure(SAVED, rejected=True)
    check = live.check_kobe_login(
        SAVED.username, "corrected", driver_factory=lambda: FakeKnossos(signed_in)
    )
    assert check.status == "ok"


# ------------------------------------------------------------ terminal setup
class _Memory:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value):
        self.values[key] = value

    def delete(self, key):
        self.values.pop(key, None)


def _answers(*values: str):
    queue = list(values)
    return lambda prompt="": queue.pop(0)


def test_terminal_setup_asks_again_after_a_rejected_login(capsys) -> None:
    store = _Memory()
    record_login_failure(SAVED, rejected=True, secret_store=store)
    seen: list[tuple[str, str]] = []

    def verifier(username, password):
        seen.append((username, password))
        return live.LoginCheck("rejected" if password == "typo" else "ok")

    verified = interactive_setup(
        store,
        verifier=verifier,
        input_fn=_answers("1234567x", "1234567x"),
        getpass_fn=_answers("typo", "right"),
    )

    assert verified is True and seen == [("1234567x", "typo"), ("1234567x", "right")]
    assert store.get(USERNAME_KEY) == "1234567x" and store.get(PASSWORD_KEY) == "right"
    assert store.get(LOGIN_STATE_KEY) is None  # the earlier pause is lifted
    err = capsys.readouterr().err
    assert "rejected" in err and "typo" not in err and "right" not in err


def test_terminal_setup_stops_after_three_rejections_and_stores_nothing() -> None:
    store = _Memory()
    with pytest.raises(CredentialsRejected, match="3 times"):
        interactive_setup(
            store,
            verifier=lambda username, password: live.LoginCheck("rejected"),
            input_fn=_answers("u", "u", "u"),
            getpass_fn=_answers("a", "b", "c"),
        )
    assert store.values == {}


def test_terminal_setup_stores_an_unverifiable_login_and_says_so(capsys) -> None:
    store = _Memory()
    verified = interactive_setup(
        store,
        verifier=lambda username, password: live.LoginCheck("unverified", "the browser did not start"),
        input_fn=_answers("u"),
        getpass_fn=_answers("p"),
    )
    assert verified is None and store.get(PASSWORD_KEY) == "p"
    assert "could not be checked" in capsys.readouterr().err


def test_terminal_setup_without_a_verifier_stores_directly() -> None:
    store = _Memory()
    assert interactive_setup(store, input_fn=_answers("u"), getpass_fn=_answers("p")) is None
    assert store.get(USERNAME_KEY) == "u"


def test_state_store_is_isolated_from_the_real_keyring(login_state_store) -> None:
    assert auth._state_store() is login_state_store
