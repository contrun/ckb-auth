# Import private keys into wallet file
See also [Creating a wallet in non-interactive mode using monero-wallet-cli? - Monero Stack Exchange](https://monero.stackexchange.com/questions/10385/creating-a-wallet-in-non-interactive-mode-using-monero-wallet-cli).

To import an account with address `41eBLjYsK28CJD5z2b7FojMCDg6vERASShVZqAvnsC9LhS7saG8CmMo5Rm92wgnT8wa6nJVu57MHHjmnoyvTpCG7NQ7dErc` into a wallet named `wallet` non-interactively, we can first create a file which is to be used as the stdin of a following `monero-wallet-cli`.
```
cat <<EOF >commands 
41eBLjYsK28CJD5z2b7FojMCDg6vERASShVZqAvnsC9LhS7saG8CmMo5Rm92wgnT8wa6nJVu57MHHjmnoyvTpCG7NQ7dErc
8ef26aced8b5f8e1e8ce63b6c75ac6ee41424242424242424242424242424202
972874ae95f5c167285858141e940847398f9c246c7913c0d396b6d73b484105
pw
pw
0
N

EOF
```

Here `8ef26aced8b5f8e1e8ce63b6c75ac6ee41424242424242424242424242424202` and `972874ae95f5c167285858141e940847398f9c246c7913c0d396b6d73b484105` are respectively the spend private key and view private key of this account.

We can then run the following command to import this account.
```
monero-wallet-cli --offline --generate-from-keys wallet < commands
```

# Get address information

Running `monero-wallet-cli --wallet-file wallet --password pw --offline` to enter the interactive mode of
monero command line wallet.

```
[wallet 41eBLj (no daemon)]: viewkey
Wallet password:
secret: 972874ae95f5c167285858141e940847398f9c246c7913c0d396b6d73b484105
public: bbcb8c902571ae1a777f7f07a023ecc5e3d83ba624d4b0ffb7eff79e8b5d10bd
[wallet 41eBLj (no daemon)]: spendkey
Wallet password:
secret: 8ef26aced8b5f8e1e8ce63b6c75ac6ee41424242424242424242424242424202
public: 007caf7a553a894389dd562115b17e78ba84a5c7692677f216c54385dc5c6ff1
[wallet 41eBLj (no daemon)]: address
0  41eBLjYsK28CJD5z2b7FojMCDg6vERASShVZqAvnsC9LhS7saG8CmMo5Rm92wgnT8wa6nJVu57MHHjmnoyvTpCG7NQ7dErc  Primary address
```

# Sign message helloworld
```
printf helloworld > message
echo pw | monero-wallet-cli --wallet-file wallet --password pw sign message
```

Below is a sample output of the above command.

```
This is the command line monero wallet. It needs to connect to a monero
daemon to work correctly.
WARNING: Do not reuse your Monero keys on another fork, UNLESS this fork has key reuse mitigations built in. Doing so will harm your privacy.

Monero 'Fluorine Fermi' (v0.18.1.2-unknown)
Logging to monero-wallet-cli.log
Opened wallet: 41eBLjYsK28CJD5z2b7FojMCDg6vERASShVZqAvnsC9LhS7saG8CmMo5Rm92wgnT8wa6nJVu57MHHjmnoyvTpCG7NQ7dErc
**********************************************************************
Use the "help" command to see a simplified list of available commands.
Use "help all" to see the list of all available commands.
Use "help <command>" to see a command's documentation.
**********************************************************************
SigV2DXdetxj9qiRe6PHsch9EwZVutb1FFR38ubNuM9ef8YPYcnjAisLWo4sLZMoT3g4Z48VRD3xAUsk1EcfthWcxnayW
```

Stripping the prefix `SigV2` of `SigV2DXdetxj9qiRe6PHsch9EwZVutb1FFR38ubNuM9ef8YPYcnjAisLWo4sLZMoT3g4Z48VRD3xAUsk1EcfthWcxnayW`,
we get the base58 representation of the signature. Note that monero's implementation of base58 is different from bitcoin's.
See [monero-rs/base58-monero](https://github.com/monero-rs/base58-monero) for how to manipulate monero base58 data programatically.

