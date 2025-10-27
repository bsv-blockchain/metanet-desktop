The latest versions of this software will be released elsewhere: [https://github.com/bsv-blockchain/bsv-desktop](https://github.com/bsv-blockchain/bsv-desktop)

This repo will remain an archive of earlier versions for posterity.

# BSV Desktop

BRC100 Wallet Desktop Application Example

- Runs JSON-API over TCP/3321
- Will soon run Wallet Wire over TCP/3301
- Lets apps talk to a wallet
- Authenticates with WAB
- Permissions management
- Trust and identity management
- ...

## To Run

You need Rust and Node installed so you can run Tauri.

Clone the repo, then:

```
npm i
npm run tauri dev
```

Some platforms require this, so install if needed:
```
npm i -g @rollup/rollup-darwin-x64 
```

- Choose your network (mainnet/testnet), WAB and pick your Auth Method (Twiloo Phone for now)
- Pick a Storage URL
- Proceed to the wallet greeter, enter your phone, code, password, save recovery key
- You are in! Now BSV apps will work.

## Compiled version

Coming soon.

## Recommended IDE Setup

- [VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)

## Release

To release a new version you ought to have a clean working directory, then run `npm run release-version x.x.x` where x.x.x is the release version in marjor.minor.patch format: 0.4.0 for example.
Your working tree will then be updated by rust which automatically creates a file you also need to merge. So add that and push. The action to create a release draft with all the binaries will then be created as a draft. You should manually review that and then set it to released as the latest version. This will update all the links at https://bsv.bsvb.tech automatically, because the script just looks for the most recent release.

## License

The license for the code in this repository is the Open BSV License.
