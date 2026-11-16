# SPDX-License-Identifier: MIT
"""Finite serial DATA protocol; acceptance still needs passive output ELF checks."""
import re

PACKAGE = 'perl'
PROBE = dict(STATUS='PASS', ARCH='aarch64', PAGESIZE='16384', UID='1000', GID='1000',
             PERL_VERSION='5.42.3', FUNCTIONAL='PASS', COMMANDS='PASS', ELF_GEOMETRY='HOST_CHECK_REQUIRED')
INSTALLED = dict(STATUS='PASS', PACKAGE=PACKAGE, VERSION='5.42.3-1.3')
RESTORED = dict(STATUS='PASS', ARCH='aarch64', PAGESIZE='16384', PACKAGE=PACKAGE,
                VERSION='5.42.3-1.3', BASE_PAYLOAD='RESTORED', BASE_METADATA='RESTORED', BASE_XATTR='RESTORED',
                LOCAL_DB='RESTORED', USERS='RESTORED', UNOWNED_LDCACHE='RESTORED', PERL_BASELINE='RESTORED', PRIVATE_TRUST='REMOVED',
                HOOKS_SCRIPTLETS='UNSUPPRESSED', GUEST_SYNC='PASS', ELF_GEOMETRY='HOST_CHECK_REQUIRED', RTC_PRESENT='yes',
                RTC_DRIVER='pl031', RTC_HCTOSYS='1', RTC_CLOCK_ADVANCED='yes', CLOCK_SETTING='none')
EPOCHS = {'HOST_BOOT_UTC', 'GUEST_BEFORE_CRYPTO_UTC', 'RTC_BEFORE_CRYPTO_UTC'}
HASHES = {'BASE_SHA256', 'FINAL_SHA256', 'FUNCTIONAL_SHA256', 'ELF_MANIFEST_SHA256'}
HOLD_MARKER = 'guest-HOLD-retire.json'
HOLD_RETIRED = 'guest-HOLD-retired.json'


def hold_failure(value):
    if (type(value) is not dict or set(value) != {'status', 'waiting', 'frame', 'phase'}
            or value['status'] != 'HOLD' or value['waiting'] not in {'INSTALLED', 'PROBE', 'RESTORED'}
            or value['frame'] not in {'INSTALLED', 'PROBE', 'RESTORED'}
            or not isinstance(value['phase'], str) or not re.fullmatch('[a-z_]{1,64}|UNREPORTED', value['phase'])):
        raise ValueError('exact bounded guest HOLD failure required')
    return value


class GuestHold(ValueError):
    def __init__(self, waiting, kind, phase):
        self.failure = hold_failure(dict(status='HOLD', waiting=waiting, frame=kind, phase=phase))
        super().__init__('guest explicit HOLD while waiting for ' + waiting + ': ' + kind + '/' + phase)


def _nonce(nonce):
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('literal nonce required')


def frame(data, nonce, kind='PROBE'):
    _nonce(nonce)
    if kind not in {'INSTALLED', 'PROBE', 'RESTORED'}:
        raise ValueError('fixed Perl phase required')
    if not isinstance(data, bytes) or len(data) > 8 * 1024 * 1024:
        raise ValueError('bounded serial bytes required')
    text = data.decode('utf-8', errors='strict').replace('\r\n', '\n')
    begin = 'PERL5423_' + kind + '_BEGIN ' + nonce
    end = 'PERL5423_' + kind + '_END ' + nonce
    lines = text.split('\n')
    if lines.count(begin) != 1 or lines.count(end) != 1:
        raise ValueError('one exact complete Perl phase frame required')
    first, last = lines.index(begin), lines.index(end)
    if last <= first or last - first > 65:
        raise ValueError('ordered bounded Perl phase frame required')
    fields = {}
    for line in lines[first + 1:last]:
        if '=' not in line or len(line) > 321:
            raise ValueError('bounded scalar frame field required')
        key, value = line.split('=', 1)
        if (not re.fullmatch('[A-Z][A-Z0-9_]{0,63}', key) or key in fields
                or not re.fullmatch('[ -~]{1,256}', value)):
            raise ValueError('unique ASCII frame fields required')
        fields[key] = value
    return fields


def _exact(fields, expected):
    if fields != expected:
        raise ValueError('exact Perl phase fields differ')
    return fields


def validate_probe(fields):
    return _exact(fields, PROBE)


def validate(fields, expected_base, epoch, now, policy='EXACT'):
    """Validate Root receipt DATA; this does not grant ELF or runtime authority."""
    if not isinstance(expected_base, str) or not re.fullmatch('[0-9a-f]{64}', expected_base):
        raise ValueError('exact expected baseline hash required')
    if set(fields) != set(RESTORED) | HASHES | EPOCHS | {'DB_POLICY'}:
        raise ValueError('complete exact Root restoration fields required')
    if policy not in ('EXACT','NORMAL_INSTALLDATE_AND_TRANSACTION_TIMESTAMPS') or fields['DB_POLICY'] != policy:
        raise ValueError('exact certified database transaction policy required')
    for key, value in RESTORED.items():
        if fields[key] != value:
            raise ValueError('Root restoration result differs: ' + key)
    if any(not re.fullmatch('[0-9a-f]{64}', fields[k]) for k in HASHES):
        raise ValueError('actual receipt/output hashes required')
    if fields['BASE_SHA256'] != expected_base or fields['FINAL_SHA256'] != expected_base:
        raise ValueError('exact baseline restoration hash required')
    if any(not re.fullmatch('[1-9][0-9]{8,11}', fields[k]) for k in EPOCHS):
        raise ValueError('bounded actual RTC epochs required')
    if type(epoch) is not int or type(now) is not int:
        raise ValueError('actual integer host clock observations required')
    host, guest, rtc = (int(fields[k]) for k in
                        ('HOST_BOOT_UTC', 'GUEST_BEFORE_CRYPTO_UTC', 'RTC_BEFORE_CRYPTO_UTC'))
    # Match the unchanged reviewed PL031 RTC helper, without setting clocks.
    if not (host == epoch and host - 5 <= guest <= min(host + 485, now + 5)
            and abs(guest - rtc) <= 2):
        raise ValueError('advancing guest RTC/host clock disagreement')
    return fields


def _session(session):
    expected = dict(ARCH='aarch64', PAGESIZE='16384', UID='1000', USERNAME='builder',
                    PID1='systemd', Name='builder', User='1000', Class='user',
                    Type='tty', Service='login', Remote='no', LOGIND='active', DBUS='active')
    if any(session.get(k) != v for k, v in expected.items()):
        raise ValueError('ordinary baseline ARM16K PAM/systemd/logind session required')
    identity = session.get('Id', '')
    if (not re.fullmatch('[A-Za-z0-9_-]{1,64}', identity)
            or session.get('XDG_SESSION_ID') != identity
            or not re.fullmatch('[1-9][0-9]{0,9}', session.get('Leader', ''))
            or session.get('State') not in {'active', 'online'}):
        raise ValueError('actual finite logind identity required')


def wait_phase(serial, nonce, kind):
    """Consume one complete ordered frame, including explicit early failures."""
    _nonce(nonce)
    if kind not in {'INSTALLED', 'PROBE', 'RESTORED'}:
        raise ValueError('fixed Perl phase required')
    marker = nonce.encode()
    pattern = (rb'(?:^|\r?\n)PERL5423_(INSTALLED|PROBE|RESTORED)_BEGIN ' + marker
               + rb'\r?\n(?:[^\r\n]{0,321}\r?\n){0,65}?PERL5423_\1_END '
               + marker + rb'(?=\r?\n|$)')
    match = serial.until(pattern)
    actual = match.group(1).decode('ascii')
    fields = frame(bytes(serial.data[match.start():match.end()]), nonce, actual)
    if fields.get('STATUS') == 'HOLD':
        phase = fields.get('FAILED_PHASE', 'UNREPORTED')
        if not re.fullmatch('[a-z_]{1,64}|UNREPORTED', phase):
            phase = 'UNREPORTED'
        raise GuestHold(kind, actual, phase)
    if fields.get('STATUS') != 'PASS':
        raise ValueError('unsupported Perl phase status while waiting for ' + kind)
    if actual != kind:
        raise ValueError('out-of-order Perl phase while waiting for ' + kind + ': ' + actual)
    return fields


def journey(serial, password, baseline_nonce, nonce, parse_frame):
    """Use one normal PAM login; all waits inherit the driver's finite deadline."""
    _nonce(baseline_nonce)
    _nonce(nonce)
    if (not isinstance(password, str) or not 1 <= len(password) <= 128
            or any(c in password for c in '\r\n\x00')):
        raise ValueError('bounded single-line baseline password required')
    serial.until(rb'login:\s*')
    serial.send(b'builder\n')
    serial.until(rb'Password:\s*')
    serial.send(password.encode() + b'\n')
    serial.until(('ARM16K_SHELL_READY ' + baseline_nonce).encode())
    # The root snapshot covers the home directories. Interactive Bash history
    # must not add a logout side effect to this deliberately finite case.
    serial.send(b'unset HISTFILE; /usr/local/libexec/arm16k-login-proof\n')
    serial.until(('TCG_LOGIN_END ' + baseline_nonce).encode())
    session = parse_frame(bytes(serial.data), baseline_nonce)
    _session(session)
    command = ('/usr/bin/env -i HOME=/home/builder USER=builder LOGNAME=builder '
               'PATH=/usr/bin:/bin LC_ALL=C TZ=UTC /usr/bin/bash --noprofile --norc '
               '/var/lib/arm16k-perl5423-vm/probe.sh ' + nonce)
    serial.send((command + '\n').encode())
    installed = wait_phase(serial, nonce, 'INSTALLED')
    _exact(installed, INSTALLED)
    probe = wait_phase(serial, nonce, 'PROBE')
    validate_probe(probe)
    serial.send((command + ' restored\n').encode())
    restored = wait_phase(serial, nonce, 'RESTORED')
    serial.send(b'exit\n')
    serial.until(rb'login:\s*')
    # Preserve the existing whole-transcript duplicate-frame refusal.
    for kind, expected in (('INSTALLED', installed), ('PROBE', probe), ('RESTORED', restored)):
        _exact(frame(bytes(serial.data), nonce, kind), expected)
    return dict(session=session, installed=installed, probe=probe, restored=restored,
                normal_PAM_logout_observed=True)
