# SPDX-License-Identifier: MIT
# Informational live-host UTC is never used to set the guest clock.
rtc_clock_guard() {
 local token host= count=0 now rtc after rtc_after hctosys name
 for token in $(cat /proc/cmdline);do
  case "$token" in arm16k_rtc_host_epoch=*) host=${token#*=};count=$((count+1));;esac
 done
 [[ $count == 1 && $host =~ ^[1-9][0-9]{8,11}$ ]] || return 2
 [[ -d /sys/class/rtc/rtc0 ]] || return 2
 hctosys=$(cat /sys/class/rtc/rtc0/hctosys);name=$(cat /sys/class/rtc/rtc0/name)
 [[ $hctosys == 1 && $name == "rtc-pl031 9010000.pl031" ]] || return 2
 now=$(date -u +%s);rtc=$(cat /sys/class/rtc/rtc0/since_epoch)
 [[ $now =~ ^[1-9][0-9]{8,11}$ && $rtc =~ ^[1-9][0-9]{8,11}$ ]] || return 2
 (( now >= host-5 && now <= host+485 && now >= rtc-2 && now <= rtc+2 )) || return 2
 sleep 1
 after=$(date -u +%s);rtc_after=$(cat /sys/class/rtc/rtc0/since_epoch)
 [[ $after =~ ^[1-9][0-9]{8,11}$ && $rtc_after =~ ^[1-9][0-9]{8,11}$ ]] || return 2
 (( after >= now+1 && after <= now+5 && rtc_after >= rtc+1 && rtc_after <= rtc+5 && after >= rtc_after-2 && after <= rtc_after+2 )) || return 2
 printf 'RTC_PRESENT=yes\nRTC_DRIVER=pl031\nRTC_HCTOSYS=1\nHOST_BOOT_UTC=%s\nGUEST_BEFORE_CRYPTO_UTC=%s\nRTC_BEFORE_CRYPTO_UTC=%s\nRTC_CLOCK_ADVANCED=yes\nCLOCK_SETTING=none\n' "$host" "$after" "$rtc_after" > "$D/rtc-clock.env"
 sync -f "$D"
}
