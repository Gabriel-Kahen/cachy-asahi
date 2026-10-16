# Held Hyprland Lua layout API source excerpts

Read-only source audit; no native execution or layout acceptance.

Source file: /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/reviews/virtual-empty-configerrors-diagnosis-20261012/independent-replay/source-contract/upstream-hyprland/src/config/lua/bindings/LuaBindingsDispatchers.cpp

SHA256: a109eeb982856e0fe2ac9d88c29115a09984511787e19a20e7b4804e14a9d4de

Lines 721-728:

```cpp
static int hlWindowFloat(lua_State* L) {
    const auto action = Internal::tableToggleAction(L, 1);

    lua_pushnumber(L, (int)action);
    Internal::pushWindowUpval(L, 1);
    lua_pushcclosure(L, dsp_floatWindow, 2);
    return 1;
}
```

Lines 845-861:

```cpp
        return 1;
    }

    auto x = Internal::tableOptNum(L, 1, "x");
    auto y = Internal::tableOptNum(L, 1, "y");
    if (x && y) {
        bool relative = Internal::tableOptBool(L, 1, "relative").value_or(false);
        lua_pushnumber(L, *x);
        lua_pushnumber(L, *y);
        lua_pushboolean(L, relative);
        Internal::pushWindowUpval(L, 1);
        lua_pushcclosure(L, dsp_move, 4);
        return 1;
    }

    auto ws = Internal::tableOptWorkspaceSelector(L, 1, "workspace", "hl.window.move");
    if (ws) {
```

Lines 1072-1093:

```cpp
static int hlWindowResize(lua_State* L) {
    if (lua_gettop(L) == 0 || lua_isnil(L, 1)) {
        lua_pushnumber(L, 0);
        lua_pushcclosure(L, dsp_mouseResize, 1);
        return 1;
    }

    if (!lua_istable(L, 1))
        return Internal::configError(L, "hl.window.resize: expected no args, a table { x, y, relative?, window? }, or a table { keep_aspect_ratio }");

    auto x = Internal::tableOptNum(L, 1, "x");
    auto y = Internal::tableOptNum(L, 1, "y");
    if (x && y) {
        bool relative = Internal::tableOptBool(L, 1, "relative").value_or(false);
        lua_pushnumber(L, *x);
        lua_pushnumber(L, *y);
        lua_pushboolean(L, relative);
        Internal::pushWindowUpval(L, 1);
        lua_pushcclosure(L, dsp_resize, 4);
        return 1;
    }

```
