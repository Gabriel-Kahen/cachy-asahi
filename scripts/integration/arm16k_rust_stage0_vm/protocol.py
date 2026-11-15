# SPDX-License-Identifier: MIT
"""Finite nonce-separated baseline PAM and Rust/RTC serial DATA protocol."""
import hashlib
import re
import time


def frame(data,nonce):
    if not re.fullmatch('[0-9a-f]{32}',nonce):raise ValueError('literal test nonce required')
    text=data.decode('utf-8',errors='strict').replace('\r','');begin='RUST_STAGE0_BEGIN '+nonce+'\n';end='RUST_STAGE0_END '+nonce
    if text.count(begin)!=1 or text.count(end)!=1:raise ValueError('one complete Rust nonce frame required')
    fields={}
    for line in text.split(begin,1)[1].split(end,1)[0].splitlines():
        if '=' not in line:raise ValueError('malformed Rust frame')
        key,value=line.split('=',1)
        if key in fields or not re.fullmatch('[A-Z0-9_]{1,64}',key) or len(value)>256:raise ValueError('duplicate/unbounded Rust frame')
        fields[key]=value
    return fields


def validate(fields,expected111,epoch,now):
    expected={'STATUS':'PASS','ARCH':'aarch64','PAGESIZE':'16384','UID':'1000','PREFIX':'/opt/cachy-asahi/rust-stage0','RUSTC_RELEASE':'1.98.0','RUSTC_HOST':'aarch64-unknown-linux-gnu','CARGO_VERSION':'1.98.0','INVENTORY_BEFORE_SHA256':expected111,'INVENTORY_AFTER_SHA256':expected111,'OWNED_READABLE_BEFORE':'PASS','OWNED_READABLE_AFTER':'PASS','GUEST_SYNC':'PASS','DIRECT_RUSTC':'PASS','CARGO_OFFLINE':'PASS','CORRECTNESS_RUNS':'2','RTC_PRESENT':'yes','RTC_DRIVER':'pl031','RTC_HCTOSYS':'1','RTC_CLOCK_ADVANCED':'yes','CLOCK_SETTING':'none'}
    for key,value in expected.items():
        if fields.get(key)!=value:raise ValueError('Rust/RTC result differs: '+key)
    if set(fields)!=set(expected)|{'HOST_BOOT_UTC','GUEST_BEFORE_CRYPTO_UTC','RTC_BEFORE_CRYPTO_UTC'}:raise ValueError('complete exact Rust/RTC result fields required')
    for key in ('HOST_BOOT_UTC','GUEST_BEFORE_CRYPTO_UTC','RTC_BEFORE_CRYPTO_UTC'):
        if not re.fullmatch('[1-9][0-9]{8,11}',fields[key]):raise ValueError('bounded observed RTC epochs required')
    host,guest,rtc=(int(fields[k]) for k in ('HOST_BOOT_UTC','GUEST_BEFORE_CRYPTO_UTC','RTC_BEFORE_CRYPTO_UTC'))
    if not(host==epoch and host-5<=guest<=min(host+485,now+5) and abs(guest-rtc)<=2):raise ValueError('observed advancing RTC/host clock disagreement')
    return fields


def journey(serial,password,baseline_nonce,nonce,baseline_parser):
    serial.until(rb'login:\s*');serial.send(b'builder\n');serial.until(rb'Password:\s*');serial.send(password.encode()+b'\n')
    serial.until(('ARM16K_SHELL_READY '+baseline_nonce).encode())
    serial.send(b'/usr/local/libexec/arm16k-login-proof\n');serial.until(('TCG_LOGIN_END '+baseline_nonce).encode())
    session=baseline_parser(bytes(serial.data),baseline_nonce)
    if session.get('ARCH')!='aarch64' or session.get('PAGESIZE')!='16384':raise ValueError('baseline actual ARM16K PAM session required')
    command='/usr/bin/env -i HOME=/home/builder USER=builder LOGNAME=builder PATH=/usr/bin:/bin LC_ALL=C TZ=UTC /usr/bin/bash --noprofile --norc /opt/cachy-asahi/rust-stage0/fixture/check.sh '+nonce+'\n'
    serial.send(command.encode());serial.until(('RUST_STAGE0_END '+nonce).encode());rust=frame(bytes(serial.data),nonce)
    # Logout happens even when the complete guest test frame reports FAIL.
    serial.send(b'exit\n');serial.until(rb'login:\s*')
    return dict(session=session,rust=rust,normal_PAM_logout_observed=True)
