https://github.com/pgcentralfoundation/pgrx for pgrx installation instructions
on Mac, be sure to export or add these to your zshrc/bashrc:

```
export MACOSX_DEPLOYMENT_TARGET=15.4
export PKG_CONFIG_PATH=/opt/homebrew/opt/icu4c/lib/pkgconfig
```

run tests:
`cargo pgrx test --package hessra_authz`

run extension
`cargo pgrx run --package hessra_authz`
