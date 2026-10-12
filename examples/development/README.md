# Development onboarding example

Use this small original program to exercise the installed terminal, an existing
editor and native compiler after the accepted overlay setup. It is an onboarding
smoke check, not a representative benchmark or performance claim.

From the frozen project source, open `hello.c` with the base's installed editor,
then build and run with an already installed C compiler:

```sh
mkdir -p build/onboarding
cc -Wall -Wextra -Werror -O2 examples/development/hello.c -o build/onboarding/hello
./build/onboarding/hello
```

Expected output is `Hello from cachy-asahi`. No command installs dependencies or
changes system settings. Record source/compiler/base/overlay versions, exact
machine and execution context, command results, editing/terminal behavior and
whether the example survives lock and resume. Do not commit the generated binary.
If an editor/compiler is missing, resolve it through the accepted complete base
transaction before the independent onboarding exercise.

Development-host x86 execution verifies only this example. Exact M2 onboarding
and native application behavior remain NOT RUN until performed on each target.
