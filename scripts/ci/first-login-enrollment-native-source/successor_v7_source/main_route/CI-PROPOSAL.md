# Canonical route controls

Existing shared CI selectors and workflows stay unchanged. The source-only
commands to add under the existing Python3.12/3.14 DATA envelope are:

```sh
python -I -B -Werror::ResourceWarning scripts/ci/first-login-enrollment-native-source/successor_v7_source/main_route/test_contract.py
python -I -B -Werror::ResourceWarning scripts/ci/first-login-enrollment-native-source/successor_v7_source/main_route/test_route.py \
  --source-root "$GENUINE_SOURCE205_DATA" --profile "$GENUINE_SOURCE205_PROFILE"
```

The genuine inputs are the fixed9e reconstruction already produced by the
Source205 DATA workflow. The controls intercept operational actors and use
explicit MODEL authority only. No actual Source205 CID or Root proof is supplied
by this proposal. Historical tests keep their original cases/pins and load the
attested v6 Main test operand instead of assuming latest Main is v6.
