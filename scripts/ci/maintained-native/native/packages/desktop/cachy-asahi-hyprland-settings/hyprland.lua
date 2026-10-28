-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 cachy-asahi contributors. See LICENSE and NOTICE.
-- API reference: Hyprland v0.56.2, efb50993780079460b0cbed1363e2166a2de1d9f.
-- Use a separate configuration file. This file does not import existing settings.
hl.monitor({ output = "", mode = "preferred", position = "auto", scale = "auto" })

hl.config({
    general = { layout = "dwindle", gaps_in = 3, gaps_out = 5, border_size = 2 },
    input = { touchpad = { natural_scroll = true, tap_to_click = true } },
})

-- Command maps to SUPER on Apple keyboards; verify the mapping on the target.
hl.bind("SUPER + RETURN", hl.dsp.exec_cmd("alacritty"))
hl.bind("SUPER + SPACE", hl.dsp.exec_cmd("wofi --show drun"))
hl.bind("SUPER + Q", hl.dsp.window.close())
hl.bind("SUPER + F", hl.dsp.window.float({ action = "toggle" }))
hl.bind("SUPER + L", hl.dsp.exec_cmd("swaylock --color 000000"))

for _, direction in ipairs({ "left", "right", "up", "down" }) do
    hl.bind("SUPER + " .. direction, hl.dsp.focus({ direction = direction }))
end
for workspace = 1, 10 do
    local key = workspace % 10
    hl.bind("SUPER + " .. key, hl.dsp.focus({ workspace = workspace }))
    hl.bind("SUPER + SHIFT + " .. key, hl.dsp.window.move({ workspace = workspace }))
end
hl.bind("SUPER + mouse:272", hl.dsp.window.drag(), { mouse = true })
hl.bind("SUPER + mouse:273", hl.dsp.window.resize(), { mouse = true })

-- Use WirePlumber's existing routing and speaker-protection path, never ALSA Master.
hl.bind("XF86AudioRaiseVolume", hl.dsp.exec_cmd("wpctl set-volume -l 1 @DEFAULT_AUDIO_SINK@ 5%+"), { repeating = true })
hl.bind("XF86AudioLowerVolume", hl.dsp.exec_cmd("wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%-"), { repeating = true })
hl.bind("XF86AudioMute", hl.dsp.exec_cmd("wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle"))
-- Select backlight-class devices rather than a PC-specific device or keyboard LED.
hl.bind("XF86MonBrightnessUp", hl.dsp.exec_cmd("brightnessctl --class=backlight set +5%"), { repeating = true })
hl.bind("XF86MonBrightnessDown", hl.dsp.exec_cmd("brightnessctl --class=backlight --min-value=1 set 5%-"), { repeating = true })

-- Optional apps: install and check their optdepends first. Enable these only if
-- the base session does not already manage these processes (e.g. through UWSM).
-- hl.on("hyprland.start", function()
--     hl.exec_cmd("waybar --config /usr/share/cachy-asahi/hyprland/waybar.json --style /usr/share/cachy-asahi/hyprland/waybar.css")
--     hl.exec_cmd("mako --config /usr/share/cachy-asahi/hyprland/mako.conf")
-- end)
