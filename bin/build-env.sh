
cargo_ndf_flag='--no-default-features'

cargo_feats_args='--features'
cargo_feats_args="$cargo_feats_args eg-allow-unsafe-code"
cargo_feats_args="$cargo_feats_args,eg-allow-insecure-deterministic-csprng"
cargo_feats_args="$cargo_feats_args,eg-allow-test-data-generation"
cargo_feats_args="$cargo_feats_args,eg-allow-toy-parameters"
cargo_feats_args="$cargo_feats_args,eg-allow-nonstandard-egds-version"

cargo_ndf_feat_args="$cargo_ndf_flag $cargo_feats_args"

cargo_build_flags='--all-targets'
cargo_insta_flags='--all'
cargo_test_flags='--no-fail-fast'

printf '# cargo aliases:\n\n'

export CARGO_ALIAS_FA="fmt --all"
printf 'cargo %s:   cargo fmt --all\n' 'fa'

cargo_profile_flags='--profile=test'
printf '\n# with flags:\n'
printf '#   %s\n' "$cargo_ndf_flag"
printf '#   %s\n' "$cargo_feats_args"
printf '#   %s\n' "$cargo_profile_flags"

export CARGO_ALIAS_B="build $cargo_profile_flags $cargo_ndf_feat_args $cargo_build_flags"
printf 'cargo b:    cargo build\n'
export CARGO_ALIAS_T="test $cargo_profile_flags $cargo_ndf_feat_args $cargo_test_flags -- --test-threads=1"
printf 'cargo t:    cargo test\n'
export CARGO_ALIAS_TI="test $cargo_profile_flags $cargo_ndf_feat_args $cargo_test_flags -- --ignored --test-threads=1"
printf 'cargo ti:   cargo test ... -- --ignored ...)\n'

export CARGO_ALIAS_IR="insta review $cargo_insta_flags"
printf 'cargo ir:   cargo insta review\n'

export CARGO_ALIAS_WB="watch --why -- cargo ${CARGO_ALIAS_B}"
printf 'cargo wb:   cargo watch build\n'
export CARGO_ALIAS_WT="watch --why -- cargo ${CARGO_ALIAS_T}"
printf 'cargo wt:   cargo watch test\n'

cargo_profile_flags='--release'
printf '\n# with flags:\n'
printf '#   %s\n' "$cargo_ndf_flag"
printf '#   %s\n' "$cargo_feats_args"
printf '#   %s\n' "$cargo_profile_flags"

export CARGO_ALIAS_RB="build $cargo_profile_flags $cargo_ndf_feat_args $cargo_build_flags"
printf 'cargo rb:    cargo build                       (release profile)\n'
export CARGO_ALIAS_RT="test $cargo_profile_flags $cargo_ndf_feat_args $cargo_test_flags -- --test-threads=1"
printf 'cargo rt:    cargo test                        (release profile)\n'
export CARGO_ALIAS_RTEL="test $cargo_profile_flags $cargo_ndf_feat_args $cargo_test_flags -p eg --lib -- --test-threads=1"
printf 'cargo rtel:  cargo test -p eg --lib                       (release profile)\n'
export CARGO_ALIAS_RTELI="$CARGO_ALIAS_RTEL --ignored"
printf 'cargo rteli: cargo test -p eg --lib ... -- --ignored ...  (release profile)\n'

export CARGO_ALIAS_RTI="test $cargo_profile_flags $cargo_ndf_feat_args $cargo_test_flags -- --ignored --test-threads=1"
printf 'cargo rti:   cargo test ... -- --ignored ...   (release profile)\n'
export CARGO_ALIAS_RITR="insta test $cargo_insta_flags --review $cargo_profile_flags $cargo_ndf_feat_args"
printf 'cargo ritr:  cargo insta test --review         (release profile)\n'

export CARGO_ALIAS_RWB="watch --why -- cargo $CARGO_ALIAS_RB"
printf 'cargo rwb:   cargo watch build                 (release profile)\n'
export CARGO_ALIAS_RWT="watch --why -- cargo $CARGO_ALIAS_RT"
printf 'cargo rwt:   cargo watch test                  (release profile)\n'
export CARGO_ALIAS_RWTEL="watch --why -- cargo $CARGO_ALIAS_RTEL"
printf 'cargo rwtel:  cargo watch test -p eg --lib                       (release profile)\n'
export CARGO_ALIAS_RWTELI="watch --why -- cargo $CARGO_ALIAS_RTELI"
printf 'cargo rwteli: cargo watch test -p eg --lib ... -- --ignored ...  (release profile)\n'

unset -v cargo_build_flags cargo_insta_flags cargo_feats_args cargo_ndf_feat_args cargo_profile_flags cargo_test_flags
echo
